# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.87-pre1 Date: Thu Jun 12 00:48:38 EST 2008$
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
import reassembler
from NetworkScanner import *
import pypcap
import cStringIO
from pyflag.ColumnTypes import StringType, IntegerType, TimestampType, InodeIDType, CounterType, BigIntegerType, ShortIntegerType, IPType, StateType
import pyflag.CacheManager as CacheManager

description = "Network Forensics"

class NetworkingInit(FlagFramework.EventHandler):
    """ Create all the tables related to basic network forensics """
    def create(self, case_dbh, case):
        ## We create the tables we need:
        ## The pcap table stores indexes into the pcap file for each packet
        ### data offset is the offset within the iosource where we can
        ### find the data section of this packet.
        case_dbh.execute("""CREATE TABLE if not exists `pcap` (
        `id` INT NOT NULL auto_increment,
        `ipid` SMALLINT UNSIGNED default 0,
        `iosource` varchar(50),
        `offset` BIGINT NOT NULL ,
        `length` INT NOT NULL ,
        `ts_sec` TIMESTAMP NULL DEFAULT '0000-00-00 00:00:00',
        `ts_usec` INT NOT NULL,
        KEY `id` (`id`)
        )""")

        ## The connection_details table stores information about each
##        ## connection
##        case_dbh.execute(
##            """CREATE TABLE if not exists `connection_details` (
##            `inode_id` int not null,
##            `inode` varchar(250),
##            `con_id` int(11) signed NOT NULL auto_increment,
##            `reverse` int(11) unsigned NOT NULL default '0',
##            `src_ip` int(11) unsigned NOT NULL default '0',
##            `src_port` int(11) unsigned NOT NULL default '0',
##            `dest_ip` int(11) unsigned NOT NULL default '0',
##            `dest_port` int(11) unsigned NOT NULL default '0',
##            `isn` int(100) unsigned NOT NULL default 0,
##            `ts_sec` TIMESTAMP default 0,
##            KEY `con_id` (`con_id`)
##            )""")

##        ## the connection table store all the packets belonging to
##        ## each connection.
##        case_dbh.execute(
##            """CREATE TABLE if not exists `connection` (
##            `con_id` int(11) signed NOT NULL default '0',
##            `original_id` int(11) unsigned NOT NULL default '0',
##            `packet_id` int(11) unsigned NOT NULL default '0',
##            `seq` int(11) unsigned NOT NULL default '0',
##            `length` mediumint(9) unsigned NOT NULL default '0',
##            `cache_offset`  bigint(9) unsigned NOT NULL default '0'
##            ) """)

class ConnectionTable(FlagFramework.CaseTable):
    """ Connection table - contains infomation about all packets involved in a connection """
    name = 'connection'
    columns = [
        [ InodeIDType, {} ],
        [ IntegerType, dict(name='Original ID', column ='original_id')],
        [ IntegerType, dict(name='Packet ID', column='packet_id'),
          "unsigned "],
        [ IntegerType, dict(name='Sequence', column='seq'),
          'unsigned '],
        [ IntegerType, dict(name='Length', column='length'),
          'unsigned '],
        [ BigIntegerType, dict(name='Cache Offset', column='cache_offset')],
        ]

class ConnectionDetailsTable(FlagFramework.CaseTable):
    """ Connection Details - Contains details about each connection """
    name ='connection_details'
    columns = [
        [ InodeIDType, {} ],
        [ IntegerType, dict(name='Reverse', column='reverse')],
        [ IPType, dict(name='Source IP', column='src_ip')],
        [ ShortIntegerType, dict(name='Source Port', column='src_port')],
        [ IPType, dict(name='Destination IP', column='dest_ip')],
        [ ShortIntegerType, dict(name='Destination Port', column='dest_port')],
        [ IntegerType, dict(name='ISN', column='isn'), 'unsigned default 0'],
        [ TimestampType, dict(name='Timestamp', column='ts_sec')],
        [ StateType, dict(name='Type', column='type', states={'tcp':'tcp', 'udp':'udp'})]
        ]
        
class PCAPFS(DBFS):
    """ This implements a simple filesystem for PCAP files.
    """
    name = 'PCAP Filesystem'
    order = 10

    def guess(self, fd, result, metadata):
        """ We need to see if its a PCAP file """
        DBFS.guess(self, fd, result, metadata)
        if 'tcpdump' in metadata['magic']:
            result.row("Selecting PCAP Virtual Filesystem automatically" ,**{'colspan':50,'class':'hilight'})
            return 120
        else:
            return -1

    def make_processor(self, iosource_name, scanners):
        ## We manage a number of tables here with mass insert:
        packet_handlers = [ x(self.case) for x in Registry.PACKET_HANDLERS.classes ]
        dbh = DB.DBO(self.case)
        ## We do not want to use mass insert here to ensure that
        ## scanning can begin immediately - this is useful when the
        ## incremental_loader is used because small files may be
        ## processed.
        pdbh = DB.DBO()
        cookie = int(time.time())

        if scanners:
            scanner_string = ','.join(scanners)

        def Callback(mode, packet, connection):
            """ This callback is called for each packet with the following modes:

            est - called when the connection is just established.
            data - called for each data packet.
            end - called when the connection is destroyed.
            """
            if mode=='est':
                ip = packet.find_type("IP")
                tcp = ip.payload
                ##tcp = packet.find_type("TCP")

                ## Connection id have not been set yet:
                if not connection.has_key('inode_id'):
                    ## We insert a null value so we can get a valid
                    ## autoincrement id.
                    dbh.insert('inode', _inode_id='NULL', _fast=True)
                    forward_inode_id = dbh.autoincrement()
                    dbh.delete('inode', where='inode_id = %s' % forward_inode_id)

                    dbh.insert('inode', _inode_id='NULL', _fast=True)
                    reverse_inode_id = dbh.autoincrement()
                    dbh.delete('inode', where='inode_id = %s' % reverse_inode_id)

                    connection['inode_id'] = forward_inode_id;
                    connection['reverse']['inode_id'] = reverse_inode_id;

                    date_str=time.strftime("%Y-%m-%d", time.gmtime(packet.ts_sec))
                    
                    ## This is used for making the VFS inode below
                    connection['path'] = "%s/streams/%s/%s-%s/%s:%s/%%s" % (
                        self.mount_point,
                        date_str,
                        ip.source_addr,
                        ip.dest_addr,
                        tcp.source,
                        tcp.dest)

                ## Record the stream in our database:
                connection['mtime'] = packet.ts_sec
                args = dict(
                    inode_id = connection['inode_id'],
                    reverse = connection['reverse']['inode_id'],
                    
                    ## This is the src address as an int
                    src_ip=ip.src,
                    type = tcp.get_name(),
                    src_port=tcp.source,
                    dest_ip=ip.dest,
                    dest_port=tcp.dest,
                    _ts_sec="from_unixtime('%s')" % connection['mtime'],
                    _fast = True)

                try:
                    args['isn']=tcp.seq
                except KeyError:
                    pass

                dbh.insert('connection_details',
                           **args)

                ## This is where we write the data out
                connection['data'] = CacheManager.MANAGER.create_cache_fd(
                    dbh.case,
                    "I%s|S%s" % (iosource_name, connection['inode_id']),
                    inode_id = connection['inode_id'])

                #if tcp.data_len > 0:
                #    Callback('data', packet, connection)

            elif mode=='data':
                ip = packet.find_type("IP")
                tcp = ip.payload
                data = tcp.data
                fd = connection['data']

                try:
                    datalen = len(data)
                except TypeError:
                    datalen = 0

                args = dict(
                    inode_id = connection['inode_id'],
                    packet_id = packet.id,
                    cache_offset = fd.offset,
                    length = datalen,
                    _fast=True
                    )

                try:
                    args['seq'] = tcp.seq
                except KeyError:
                    args['seq'] = 0
                
                dbh.insert("connection", **args)
                
                if data: fd.write(data)

            elif mode=='destroy':
                ## Find the mtime of the first packet in the stream:
                try:
                    fd = connection['data']
                    fd.write_to_file()

                    if fd.offset > 0:
                        ## Create a new VFS node:
                        new_inode = "I%s|S%s" % (iosource_name, connection['inode_id'])

                        inode_id = self.VFSCreate(
                            None,
                            new_inode,
                            connection['path'] % "forward",
                            size = fd.offset,
                            inode_id = connection['inode_id'],
                            _mtime = connection['mtime'],
                            _fast = True
                            )
                        
                        if scanners:
                            pdbh.insert("jobs",
                                command = 'Scan',
                                arg1 = self.case,
                                arg2 = new_inode,
                                arg3= scanner_string,
                                cookie=cookie,
                                )

                except KeyError: pass

                try:
                    fd = connection['reverse']['data']
                    fd.write_to_file()

                    if fd.offset > 0:
                        ## Create a new VFS node:
                        new_inode = "I%s|S%s" % (iosource_name, connection['reverse']['inode_id'])

                        inode_id = self.VFSCreate(
                            None,
                            new_inode,
                            connection['path'] % "reverse",
                            inode_id = connection['reverse']['inode_id'],
                            size = fd.offset,
                            _mtime = connection['reverse']['mtime'],
                            _fast = True
                            )

                        if scanners:
                            pdbh.insert("jobs",
                                command = 'Scan',
                                arg1 = self.case,
                                arg2 = new_inode,
                                arg3= scanner_string,
                                cookie=cookie,
                                )

                except KeyError: pass

            ## Miscelaneous packets do not belong in a TCP connection
            ## and can be processed by packet handlers. Should we make
            ## all packets parsable by packet handlers or just misc?
            ## Its a performance consideration. For now there are no
            ## packet handlers for TCP related packets, so this seems
            ## best.
            elif mode=='misc':
                for handler in packet_handlers:
                    handler.handle(packet)
                
        ## Create a new reassembler with this callback
        processor = reassembler.Reassembler(packet_callback = Callback)
        return cookie, processor

    def load(self, mount_point, iosource_name,scanners = None):
        DBFS.load(self, mount_point, iosource_name)
        
        ## Open the file descriptor
        self.fd = IO.open(self.case, iosource_name)

        ## Use the C implementation to read the pcap files:
        pcap_file = pypcap.PyPCAP(self.fd)

        ## Build our streams:
        pyflaglog.log(pyflaglog.DEBUG, "Reassembling streams, this might take a while")
        pcap_dbh = DB.DBO(self.case)
        pcap_dbh.mass_insert_start("pcap")

        pcap_dbh.execute("select max(id) as m from pcap")
        max_id = pcap_dbh.fetch()['m'] or 0
        cookie, processor = self.make_processor(iosource_name, scanners)

        ## Process the file with it:
        while 1:
            try:
                packet = pcap_file.dissect()
                max_id += 1

                ## FIXME - this is a bottleneck. For now we use mass
                ## insert but this will break when we have multiple
                ## concurrent loaders.  Record the packet in the pcap
                ## table:
                args = dict(
                    iosource = iosource_name,
                    offset = packet.offset,
                    length = packet.caplen,
                    _ts_sec =  "from_unixtime('%s')" % packet.ts_sec,
                    ts_usec = packet.ts_usec,
                    )

                ## Try to insert the ipid field
                try:
                    args['ipid']= packet.root.eth.payload.id
                except: pass

                pcap_dbh.mass_insert(**args)
                #pcap_id = pcap_dbh.autoincrement()
                pcap_id = max_id
                pcap_file.set_id(pcap_id)

                
                ## Some progress reporting
                if pcap_id % 10000 == 0:
                    pyflaglog.log(pyflaglog.DEBUG, "processed %s packets (%s bytes)" % (pcap_id, packet.offset))

                processor.process(packet)
            except StopIteration:
                break

        processor.flush()

        pcap_dbh.check_index("connection_details",'src_ip')
        pcap_dbh.check_index("connection_details",'src_port')
        pcap_dbh.check_index("connection_details",'dest_ip')
        pcap_dbh.check_index("connection_details",'dest_port')
        pcap_dbh.check_index('connection_details','inode_id')

        ## Make sure that no NULL inodes remain (This might be slow?)
        ##pcap_dbh.delete("connection_details",
        ##                where = "inode is null")

import pyflag.Magic as Magic

class PCAPMagic(Magic.Magic):
    """ Identify PCAP files """
    type = "PCAP tcpdump file"
    mime = "binary/x-pcap"
    default_score = 100

    regex_rules = [
        ( r"\xd4\xc3\xb2\xa1", (0,1)),
        ( r"\xa1\xb2\xc3\xd4", (0,1))
        ]

    samples = [
        ( 100, "\xd4\xc3\xb2\xa1sddsadsasd")
        ]
        
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
        packet = pypcap.PyPCAP(io)
        packet.seek(row['offset'])
        dissected_packet = packet.dissect()
        
        id = int(query['id'])
        
        def get_node(branch):
            """ Locate the node specified by the branch.

            branch is a list of attribute names.
            """
            result = dissected_packet
            for b in branch:
                try:
                    result = getattr(result, b)
                except: pass

            return result
        
        def tree_cb(path):
            branch = FlagFramework.splitpath(path)
            
            node = get_node(branch)
            try:
                for field in node.list():
                    if field.startswith("_"): continue

                    child = getattr(node, field)
                    try:
                        yield  ( field, child.get_name(), 'branch')
                    except AttributeError:
                        yield  ( field, field, 'leaf')

            except AttributeError:
                pass
            
            return
        
        def pane_cb(path,result):
            branch = FlagFramework.splitpath(path)
            
            node = get_node(branch)

            result.heading("Packet %s" % id)
            data = dissected_packet.serialise()
            
            h=FlagFramework.HexDump(data, result)
            try:
                result.text("%s" % node.get_name(), font='bold')
                result.text('',style='black', font='normal')
                start,length = node.get_range()
                
            except AttributeError:
                result.text("%s\n" % node, style='red', wrap='full', font='typewriter', sanitise='full')
                result.text('',style='black', font='normal')
                node = get_node(branch[:-1])
                start,length = node.get_range(branch[-1])

            h.dump(highlight=[[start,length,'highlight'],])

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
    ## Disabled for now, broken since 0.85
    hidden = True
    
    def display(self,query,result):
    
        result.heading("Summary of Networking Information for %s" % query['case'])

        def http(query,output):
            #select distinct url from http group by url
            #select distinct count(inode) from http group by url
            output.table(
                elements = [ CounterType('Number of HTTP Get Requests') ],
                table='http',
                case=query['case'],
                filter="filter",
                )
            return output

        def irc(query,output):
            output.table(
                elements = [ CounterType('Number of IRC Messages') ],
                table='irc_messages',
                case=query['case'],
                filter="filter1",
                )
            return output

        def msn(query,output):
            output.table(
                elements = [ CounterType('Number of MSN Messages') ],
                table='msn_session',
                case=query['case'],
                filter="filter2",
                )
            return output

        def email(query,output):
            output.table(
                elements = [ CounterType('Number of Emails Messages') ],
                table='email',
                case=query['case'],
                filter="filter3",
                )
            return output
        
        try:
            result.notebook(
                names=["HTTP","IRC","MSN","Email"],
                callbacks=[http,irc,msn,email],
                )
        except DB.DBError,args:
            result.para("No networking tables found, you probably haven't run the correct scanners: %s" % args)
