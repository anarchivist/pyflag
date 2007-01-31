# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.82 Date: Sat Jun 24 23:38:33 EST 2006$
# ******************************************************
#
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# *
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
# ******************************************************
""" Implements a Pyflag filesystem driver for processing of pcap files.

When a pcap file is loaded into a case, the reassembler creates
virtual inodes for each stream. These streams are then scanned by
protocol handlers to create more virtual inodes for each
protocol. (e.g. HTTP objects, Emails etc).
"""
import pyflag.Reports as Reports
import pyflag.FlagFramework as FlagFramework
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.FileSystem as FileSystem
from pyflag.FileSystem import DBFS,File
import pyflag.pyflaglog as pyflaglog
import pyflag.IO as IO
import pyflag.DB as DB
import pyflag.Scanner as Scanner
import pyflag.ScannerUtils as ScannerUtils
import pyflag.Registry as Registry
import os,sys,time
import dissect,reassembler, _dissect
from NetworkScanner import *
import FileFormats.PCAP as PCAP
from format import Buffer
from pyflag.TableObj import StringType, IntegerType, TimestampType, InodeType

description = "Network Forensics"

def draw_only_PCAPFS(query,result):
    """ Draws a selector with only PCAPFS filesystems """
    dbh = DB.DBO(query['case'])
    dbh2 = DB.DBO(query['case'])
    images = []
    ## Get a list of filesystems which are of type PCAPFS:
    dbh.execute("select value from meta where property='fsimage'")
    for row in dbh:
        t=dbh2.get_meta("fstype")
        if t.startswith("PCAP"):
            images.append(row['value'])

    result.const_selector("Select filesystem",'fsimage',images,images)


class PCAPFS(DBFS):
    """ This implements a simple filesystem for PCAP files.
    """
    name = 'PCAP Filesystem'

    def load(self, mount_point, iosource_name,scanners = None):
        DBFS.load(self, mount_point, iosource_name)
        
        ## We create the tables we need:
        ## The pcap table stores indexes into the pcap file,
        ## The connection_details table stores information about each
        ## connection, while the connection table store all the
        ## packets belonging to each connection.
        dbh = DB.DBO(self.case)
        dbh.execute("""CREATE TABLE if not exists `pcap` (
        `id` INT NOT NULL,
        `iosource` varchar(50),
        `offset` BIGINT NOT NULL ,
        `length` INT NOT NULL ,
        `ts_sec` TIMESTAMP,
        `ts_usec` INT NOT NULL,
        `link_type`  TINYINT not null,
        KEY `id` (`id`)
        )""")
        
        dbh.execute("select max(id) as id from pcap")
        row=dbh.fetch()

        if row['id']:
            max_id = row['id']
        else:
            max_id = 0
            
        dbh.execute(
            """CREATE TABLE if not exists `connection_details` (
            `inode` varchar(250),
            `con_id` int(11) signed NOT NULL default 0,
            `reverse` int(11) unsigned NOT NULL default '0',
            `src_ip` int(11) unsigned NOT NULL default '0',
            `src_port` int(11) unsigned NOT NULL default '0',
            `dest_ip` int(11) unsigned NOT NULL default '0',
            `dest_port` int(11) unsigned NOT NULL default '0',
            `isn` int(100) unsigned NOT NULL default 0,
            `ts_sec` TIMESTAMP default 0,
            KEY `con_id` (`con_id`)
            )""")
        
        ### data offset is the offset within the iosource where we can
        ### find the data section of this packet.
        ## This must be autoincrement to assign unique ids to new
        ## streams which get created by the scanners.
        dbh.execute(
            """CREATE TABLE if not exists `connection` (
            `con_id` int(11) signed NOT NULL default '0',
            `original_id` int(11) unsigned NOT NULL default '0',
            `packet_id` int(11) unsigned NOT NULL default '0',
            `seq` int(11) unsigned NOT NULL default '0',
            `length` mediumint(9) unsigned NOT NULL default '0',
            `cache_offset`  bigint(9) unsigned NOT NULL default '0'
            ) """)

        ## Open the file descriptor
        self.fd = IO.open(self.case, iosource_name)
        buffer = Buffer(fd=self.fd)

        ## Try to open the file as a pcap file:
        pcap_file = PCAP.FileHeader(buffer)

        ## Build our streams:
        pyflaglog.log(pyflaglog.DEBUG, "Reassembling streams, this might take a while")

        ## Prepare the dbh for the callback
        case = dbh.case
        dbh2 = DB.DBO(case)
        dbh2.mass_insert_start("connection")

        ## We need to find a good spot to have con_ids:
        dbh2.execute("select max(con_id) as max from connection_details")
        row = dbh2.fetch()
        try:
            ## This number is designed to provide enough room for
            ## connection ids to grow without collision. In the even
            ## that another simulataneous load process is launched.
            initial_con_id = row['max']+2e6
        except:
            initial_con_id = 0

        ## Where to store the reassembled stream files
        hashtbl = reassembler.init(FlagFramework.get_temp_path(dbh.case,'I%s|' % iosource_name),initial_con_id)

        if scanners:
            scanner_string = ",".join(scanners)
            pdbh = DB.DBO()
            pdbh.mass_insert_start('jobs')

        def Callback(s):
            ## Flush the mass insert pcap:
            dbh.mass_insert_commit()
            
            ## Find the mtime of the first packet in the stream:
            try:
                dbh2.execute("select ts_sec from pcap where id=%r limit 1",
                                 s['packets'][0])
                row = dbh2.fetch()
                mtime = row['ts_sec']
            except IndexError,e:
                mtime = "0000-00-00"

            ## Add the stream to the connection details table: (Note
            ## here that dbh.insert and dbh.mass_insert do not
            ## interfer with each other and can be used alternatively
            dbh2.insert("connection_details",
                       con_id=s['con_id'],
                       src_ip=s['src_ip'],
                       src_port=s['src_port'],
                       dest_ip=s['dest_ip'],
                       dest_port=s['dest_port'],
                       isn=s['isn'],
                       inode='I%s|S%s' % (iosource_name, s['con_id']),
                       reverse=s['reverse'],
                       ts_sec=mtime
                       )

            ## If the stream is empty we dont really want to record it.
            if len(s['seq'])==0: return

            ## Figure out the size of the stream:
            try:
                size = s['seq'][-1] + s['length'][-1] - s['seq'][0]
            except:
                size = 0
	    
            ## Create a new VFS node:
            new_inode = "I%s|S%s" % (iosource_name, s['con_id'])
            
            ## Seperate the streams into days to make handling huge
            ## files in the gui a little eaiser.
            date_str = mtime.split(" ")[0]
            
            if s['direction'] == "forward":
                self.VFSCreate(
                    None,
                    new_inode,
                    "%s/streams/%s/%s-%s/%s:%s/%s" % (
                    self.mount_point,
                    date_str,
                    IP2str(s['dest_ip']),
                    IP2str(s['src_ip']),
                    s['dest_port'],
                    s['src_port'],
                    s['direction']),
                    mtime = mtime,
                    size=size
                    )
            else:
                self.VFSCreate(
                    None,
                    new_inode,
                    "%s/streams/%s/%s-%s/%s:%s/%s" % (
                    self.mount_point,
                    date_str,
                    IP2str(s['src_ip']),
                    IP2str(s['dest_ip']),
                    s['src_port'],
                    s['dest_port'],
                    s['direction']),
                    mtime = mtime,
                    size=size
                    )
                
            for i in range(len(s['seq'])):
                dbh2.mass_insert(
                    con_id = s['con_id'], packet_id = s['packets'][i],
                    seq = s['seq'][i], length = s['length'][i],
                    cache_offset = s['offset'][i],
                    )

            ## If we need to scan it, schedule the job now:
            if scanners:
                pdbh.mass_insert(
                    command = 'Scan',
                    arg1 = self.case,
                    arg2 = new_inode,
                    arg3= scanner_string,
                    cookie=self.cookie,
                    )

        ## Register the callback
        reassembler.set_tcp_callback(hashtbl, Callback)

        ## Scan the filesystem:
        ## Load the packets into the indes:
        dbh.mass_insert_start("pcap")
        link_type = int(pcap_file['linktype'])

        for p in pcap_file:
            ## Store information about this packet in the db:
            dbh.mass_insert(
                iosource = iosource_name,
                offset = p.buffer.offset,
                length = p.size(),
                ts_sec =  p['ts_sec'],
                ts_usec = int(p['ts_usec']),
                link_type = link_type,
                id = max_id
                )

##            max_id = dbh.autoincrement()
            max_id+=1
            ## Some progress reporting
            if max_id % 10000 == 0:
                pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "processed %s packets (%s bytes)" % (max_id, p.buffer.offset))

            data = p.payload()
#            print "%r" % data[:100]
            d = _dissect.dissect(data,link_type, max_id)

        ## Now reassemble it:
            try:
                reassembler.process_packet(hashtbl, d, self.fd.name)
            except RuntimeError,e:
                pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "%s" % e)

        pyflaglog.log(pyflaglog.DEBUG, "Finalising streams, nearly done")
        
        # Finish it up
        reassembler.clear_stream_buffers(hashtbl);
        reassembler.set_tcp_callback(hashtbl,None);
        
        dbh.check_index("connection_details",'src_ip')
        dbh.check_index("connection_details",'src_port')
        dbh.check_index("connection_details",'dest_ip')
        dbh.check_index("connection_details",'dest_port')
        dbh.check_index("connection", 'con_id')
        dbh.check_index('connection_details','inode')

    def delete(self):
        DBFS.delete(self)
        dbh = DB.DBO(self.case)    
        dbh.MySQLHarness("%s/pcaptool -d -t pcap" % (
            config.FLAG_BIN))

class PCAPFile(File):
    """ A file like object to read packets from a pcap file.

    Read the module header for usage warnings. Many normal assumptions
    do not work with this driver.
    """
    specifier = 'p'
    ignore = True

    def __init__(self, case, fd, inode):
        """ This is a top level File driver for opening pcap files.

        Note that pcap files are stored in their own filesystem. We expect the following initialisation:
        @arg fd: is an io source for the pcap file
        @arg inode: The inode of the pcap file in the pcap filesystem, currently ignored.
        """
        File.__init__(self, case, fd, inode)
        ## Calculates the size of this file:
        dbh = DB.DBO(self.case)    
        self.private_dbh = dbh.clone()
        dbh.execute("select max(id) as max from pcap")
        row=dbh.fetch()
        if row['max']:
            self.size = row['max']
        else:
            self.size = 0
        
        self.private_dbh.execute("select id,offset,link_type,ts_sec,length from pcap where id>%r" % int(self.size))
        self.iosource = fd

    def read(self,length=None):
        ## If we dont specify the length we get the full packet. Must
        ## be smaller than MAXINT
        if length==None: length=sys.maxint
        if self.readptr>=self.size: return ''

        ## Find out the offset in the file of the packet:
        row=self.private_dbh.fetch()

        if not row:
            self.readptr+=1
            return '\x00'
        
        ## Is this the row we were expecting?
        if row['id'] != self.readptr:
            self.private_dbh.execute("select id,offset,link_type,ts_sec,length from pcap where id=%r", self.readptr)
            row=self.private_dbh.fetch()

        self.packet_offset = row['offset']
        self.fd.seek(row['offset'])

        self.link_type = row['link_type']
        self.ts_sec = row['ts_sec']
        self.readptr+=1
        
        if length<row['length']:
            return self.fd.read(length)
        else:
            return self.fd.read(row['length'])

class ViewDissectedPacket(Reports.report):
    """ View Dissected packet in a tree. """
    parameters = {'id':'numeric'}
    name = "View Packet"
    family = "Network Forensics"
    description = "Views the packet in a tree"

    def form(self,query,result):
        try:
            result.case_selector()
            result.textfield('Packet ID','id')
        except KeyError:
            pass

    def display(self,query,result):
        dbh = DB.DBO(query['case'])
        dbh.execute("select * from pcap where id=%r limit 1", query['id'])
        row=dbh.fetch()
        
        io = IO.open(query['case'], row['iosource'])
        io.seek(row['offset'])
        packet = PCAP.Packet(io.read(row['length'])).payload()
        id = int(query['id'])
        
        link_type = row['link_type']

        ## Now dissect it.
        proto_tree = dissect.dissector(packet,link_type, id)

        def get_node(branch):
            node = proto_tree
            previous_node = node
            for field in branch:
                field=field.replace('/','')
                try:
                    tmp = node
                    node = node[field]
                    previous_node = tmp
                except:
                    break

            return previous_node,node
        
        def tree_cb(path):
            branch = FlagFramework.splitpath(path)
            
            previous_node, node = get_node(branch)
            try:
                for field in node.list_fields():
                    if field.startswith("_"): continue
                    
                    if node.is_node(field):
                        yield  ( field, node[field].name, 'branch')
                    else:
                        yield  ( field, field, 'leaf')
            except AttributeError:
                pass
            
            return
        
        def pane_cb(path,result):
            branch = FlagFramework.splitpath(path)
            
            previous_node, node = get_node(branch)

            result.heading("Packet %s" % id)

            h=FlagFramework.HexDump(packet,result)
            
            try:
                result.text("%s" % node.name, font='bold')
                result.text('',color='black', font='normal')
                start,length = node.get_range()
                h.dump(highlight=[[start,length,'highlight'],])
                
            except AttributeError:
                result.text("%s.%s\n" % (previous_node.name,
                                          branch[-1]), color='black',
                            font='bold'
                               )
                try:
                    node = node[:10000]
                except:
                    pass
                
                result.text("%s\n" % node, color='red', wrap='full', font='typewriter', sanitise='full')
                result.text('',color='black', font='normal')

                try:
                    start,length = previous_node.get_range(branch[-1])
                    h.dump(highlight=[[start,length,'highlight'],])
                except KeyError:
                    pass

            return

        result.tree(tree_cb=tree_cb, pane_cb=pane_cb, branch=[''])

        ## We add forward and back toolbar buttons to let people move
        ## to next or previous packet:
        dbh.execute("select min(id) as id from pcap")
        row = dbh.fetch()

        new_query=query.clone()
        if id>row['id']:
            del new_query['id']
            new_query['id']=id-1
            result.toolbar(text="Previous Packet",icon="stock_left.png",link=new_query)
        else:
            result.toolbar(text="Previous Packet",icon="stock_left_gray.png")
            
        dbh.execute("select max(id) as id from pcap")
        row = dbh.fetch()
        
        if id<row['id']:
            del new_query['id']
            new_query['id']=id+1
            result.toolbar(text="Next Packet",icon="stock_right.png",link=new_query)
        else:
            result.toolbar(text="Next Packet",icon="stock_right_gray.png")


class NetworkingSummary(Reports.report):
    """ This report provides users with a summary of the information extracted from all the network captures for this case.

    This is a start but I actually want more powerful/useful stats like below.  I am thinking about how to do this.

    <ul>
    <li><b>HTTP</b> - Number of unique GET requests,unique content types, all urls ordered by frequency (index-scanner like)</li>
    <li><b>IRC</b> - List of (unique) participants (senders,receivers), list of (unique) IRC commands used</li>
    <li><b>MSN</b> - List of participants (senders,receivers)</li>
    <li><b>Email</b> - No of unique subjects, list of unique senders, list of unique recipients</li>
    </ul>
    """
    name = "Networking Summary"
    family = "Network Forensics"
    
    def display(self,query,result):
    
        result.heading("Summary of Networking Information for %s" % query['case'])

        def http(query,output):
            #select distinct url from http group by url
            #select distinct count(inode) from http group by url
            output.table(
                elements = [ IntegerType('Number of HTTP Get Requests', 'count(inode)') ],
                table='http',
                case=query['case']
                )
            return output

        def irc(query,output):
            output.table(
                elements = [ IntegerType('Number of IRC Messages', 'count(inode)') ],
                table='irc_messages',
                case=query['case']
                )
            return output

        def msn(query,output):
            output.table(
                elements = [ IntegerType('Number of MSN Messages', sql='count(inode)') ],
                table='msn_session',
                case=query['case']
                )
            return output

        def email(query,output):
            output.table(
                elements = [ IntegerType('Number of Emails Messages', 'count(inode)') ],
                table='email',
                case=query['case']
                )
            return output
        
        try:
            result.notebook(
                names=["HTTP","IRC","MSN","Email"],
                callbacks=[http,irc,msn,email],
                )
        except DB.DBError,args:
            result.para("No networking tables found, you probably haven't run the correct scanners: %s" % args)


## UnitTests:
import unittest
import pyflag.pyflagsh as pyflagsh
from pyflag.FileSystem import DBFS

class NetworkForensicTests(unittest.TestCase):
    """ Tests network forensics """
    test_case = "PyFlagNetworkTestCase"
    order = 20
    def test01LoadFilesystem(self):
        """ Test that pcap files can be loaded """
        pyflagsh.shell_execv(command="execute",
                             argv=["Case Management.Remove case",'remove_case=%s' % self.test_case])
        
        pyflagsh.shell_execv(command="execute",
                             argv=["Case Management.Create new case",'create_case=%s' % self.test_case])

        pyflagsh.shell_execv(command="execute",
                             argv=["Load Data.Load IO Data Source",'case=%s' % self.test_case,
                                   "iosource=pcap",
                                   "subsys=advanced",
                                   "io_filename=%s/stdcapture_0.3.pcap" % config.UPLOADDIR,
                                   ])
        
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env,
                             command="load_and_scan",
                             argv=["pcap",                   ## IOSource
                                   "/stdcapture/",           ## Mount point
                                   "PCAPFS",                 ## FS type
                                   ""])                     ## List of Scanners (None)

        
