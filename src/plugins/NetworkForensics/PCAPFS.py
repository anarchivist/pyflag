""" Implements a Pyflag filesystem driver for processing of pcap files.

When a pcap file is loaded into a case, we create a virtual file in
the VFS called '/rawdata' at the root directory. This file will be
scanned by the scanners. The scanners will use the PCAPFile object to
read this file. We use an inode driver specifier of 'p' for this
special file.

The PCAPFile driver is a little unusual:

- seek(offset). Offset is interpreted as a packet id, seeking to that packet will cause read to return it. Note that packet ids are incremental integers.

- read(length): Causes the current packet to be read. Note that we only return a single packet, even if we return a short read.

The effect of this interface is that you can not assume:

fd.seek(x)
y=fd.read(1000)
fd.tell != x+y != x+1000

Further (fd.read(length)<length) does not indicate the end of
file. The end of file is always indicated by fd.read(length)==0. This
is a common misconception that is fueled by the fact that regular file
reads never return less data than is available and requested. However
this is common on sockets, so code should always be testing for a zero
return.
"""
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.80.1 Date: Tue Jan 24 13:51:25 NZDT 2006$
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
import pyflag.Reports as Reports
import pyflag.FlagFramework as FlagFramework
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.FileSystem as FileSystem
from pyflag.FileSystem import DBFS,File
import pyflag.logging as logging
import pyflag.IO as IO
import pyflag.DB as DB
import pyflag.Scanner as Scanner
import pyflag.ScannerUtils as ScannerUtils
import pyflag.Registry as Registry
import os,sys
import dissect,reassembler, _dissect
from NetworkScanner import *

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

    We start off with a single file '/rawdata'. The scanners will do the rest.
    """
    name = 'PCAP Filesystem'

    def load(self, mount_point, iosource_name):
        DBFS.load(self, mount_point, iosource_name)
        
        ## This sets up the schema for pcap
        self.dbh.MySQLHarness("%s/pcaptool -c -t pcap" %(config.FLAG_BIN))
        self.dbh.execute("select max(id) as id from pcap")
        row=self.dbh.fetch()
        if row:
            max_id = row['id']
        else:
            max_id = 1

        ## This populates it 
        sql =  "%s/iowrapper -p %r -i %r -o %s -f foo -- %s/pcaptool -t pcap -i %r foo" % (
            config.FLAG_BIN,
            max_id,
            self.iosource.subsystem,
            self.iosource.make_parameter_list(),
            config.FLAG_BIN, iosource_name)

        self.dbh.MySQLHarness(sql)

        ## Add our VFS node
        self.VFSCreate(None,"I%s|p0" % iosource_name,'%s/rawdata' % mount_point);

        ## Creates indexes on id:
        self.dbh.check_index("pcap",'id')

        self.fd = IO.open(self.dbh.case, iosource_name)

        ## Build our streams:
        ## We create the tables we need: The connection_details table
        ## stores information about each connection, while the
        ## connection table store all the packets belonging to each
        ## connection.
        self.dbh.execute(
            """CREATE TABLE if not exists `connection_details` (
            `inode` varchar(250),
            `con_id` int(11) unsigned NOT NULL auto_increment,
            `reverse` int(11) unsigned NOT NULL default '0',
            `src_ip` int(11) unsigned NOT NULL default '0',
            `src_port` int(11) unsigned NOT NULL default '0',
            `dest_ip` int(11) unsigned NOT NULL default '0',
            `dest_port` int(11) unsigned NOT NULL default '0',
            `isn` int(100) unsigned NOT NULL default 0,
            `ts_sec` int(100) unsigned NOT NULL default 0,
            KEY `con_id` (`con_id`)
            )""")
        
        ### data offset is the offset within the iosource where we can
        ### find the data section of this packet.
        self.dbh.execute(
            """CREATE TABLE if not exists `connection` (
            `con_id` int(11) unsigned NOT NULL default '0',
            `original_id` int(11) unsigned NOT NULL default '0',
            `packet_id` int(11) unsigned NOT NULL default '0',
            `seq` int(11) unsigned NOT NULL default '0',
            `length` mediumint(9) unsigned NOT NULL default '0',
            `cache_offset`  mediumint(9) unsigned NOT NULL default '0'
            ) """)

        self.dbh.check_index("connection", 'con_id')
        
        ## Ensure that the connection_details table has indexes. We
        ## need the indexes because we are about to do lots of selects
        ## on this table.
        self.dbh.check_index("connection_details",'src_ip')
        self.dbh.check_index("connection_details",'src_port')
        self.dbh.check_index("connection_details",'dest_ip')
        self.dbh.check_index("connection_details",'dest_port')

        ## Where to store the reassembled stream files
        hashtbl = reassembler.init(FlagFramework.get_temp_path(self.dbh.case,'I%s|' % iosource_name))

        def Callback(s):
            ## Find the mtime of the first packet in the stream:
            try:
                self.dbh.execute("select ts_sec from pcap where id=%r",
                                 s['packets'][0])
                row = self.dbh.fetch()
                mtime = row['ts_sec']
            except IndexError,e:
                mtime = 0

            ## Add the stream to the connection details table:
            self.dbh.execute("insert into `connection_details` set con_id=%r, src_ip=%r, src_port=%r, dest_ip=%r, dest_port=%r, isn=%r, inode='I%s|S%s', reverse=%r, ts_sec=%r ",(
                s['con_id'], s['src_ip'], s['src_port'],
                s['dest_ip'],s['dest_port'], s['isn'],
                iosource_name, s['con_id'], s['reverse'],
                mtime
                ))

            ## Create a new VFS node:
            if s['direction'] == "forward":
                self.VFSCreate(
                    None,
                    "I%s|S%s" % (iosource_name, s['con_id']) ,
                    "%s/%s-%s/%s:%s/%s" % ( self.mount_point,
                                            IP2str(s['dest_ip']),
                                            IP2str(s['src_ip']),
                                            s['dest_port'],
                                            s['src_port'],
                                            s['direction']),
                    mtime = mtime
                    )
            else:
                self.VFSCreate(
                    None,
                    "I%s|S%s" % (iosource_name, s['con_id']) ,
                    "%s/%s-%s/%s:%s/%s" % ( self.mount_point,
                                            IP2str(s['src_ip']),
                                            IP2str(s['dest_ip']),
                                            s['src_port'],
                                            s['dest_port'],
                                            s['direction']),
                    mtime = mtime
                    )
                
            self.dbh.mass_insert_start("connection")
            
            for i in range(len(s['seq'])):
                self.dbh.mass_insert(
                    con_id = s['con_id'], packet_id = s['packets'][i],
                    seq = s['seq'][i], length = s['length'][i],
                    cache_offset = s['offset'][i],
                    )

            self.dbh.mass_insert_commit()

        ## Register the callback
        reassembler.set_tcp_callback(hashtbl, Callback)

        ## Scan the filesystem:
        self.dbh.execute("select id,offset,link_type,ts_sec,length from pcap")
        for row in self.dbh:
            self.fd.seek(row['offset'])
            data = self.fd.read(row['length'])
            d = _dissect.dissect(data,row['link_type'],
                                  row['id'])

            ## Now reassemble it:
            try:
                reassembler.process_packet(hashtbl, d, self.fd.name)
            except RuntimeError,e:
                print "Error %s" % e

        # Finish it up
        reassembler.clear_stream_buffers(hashtbl);

    def delete(self):
        DBFS.delete(self)
        self.dbh.MySQLHarness("%s/pcaptool -d -t pcap" % (
            config.FLAG_BIN))

class PCAPFile(File):
    """ A file like object to read packets from a pcap file.

    Read the module header for usage warnings. Many normal assumptions
    do not work with this driver.
    """
    specifier = 'p'

    def __init__(self, case, fd, inode, dbh=None):
        """ This is a top level File driver for opening pcap files.

        Note that pcap files are stored in their own filesystem. We expect the following initialisation:
        @arg fd: is an io source for the pcap file
        @arg inode: The inode of the pcap file in the pcap filesystem, currently ignored.
        """
        File.__init__(self, case, fd, inode, dbh)
        ## Calculates the size of this file:
        self.dbh = dbh.clone()
        self.dbh.execute("select max(id) as max from pcap")
        row=self.dbh.fetch()
        self.size = row['max']
        self.dbh.execute("select id,offset,link_type,ts_sec,length from pcap")
        self.iosource = fd

    def read(self,length=None):
        ## If we dont specify the length we get the full packet. Must
        ## be smaller than MAXINT
        if length==None: length=sys.maxint
        if self.readptr>=self.size: return ''

        ## Find out the offset in the file of the packet:
        row=self.dbh.fetch()

        ## Is this the row we were expecting?
        if row['id'] != self.readptr:
            self.dbh.execute("select id,offset,link_type,ts_sec,length from pcap where id>=%r", self.readptr)
            row=self.dbh.fetch()

        if not row:
            self.readptr+=1
            return '\x00'

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
        dbh.execute("select * from pcap where id=%r", query['id'])
        row=dbh.fetch()
        
        io = IO.open(query['case'], row['iosource'])
        io.seek(row['offset'])
        packet = io.read(row['length'])
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
        
        def tree_cb(branch):
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
        
        def pane_cb(branch,result):
            previous_node, node = get_node(branch)

            result.heading("Packet %s" % id)

            h=FlagFramework.HexDump(packet,result)
            
            try:
                result.text("%s" % node.name, font='bold')
                result.text('',color='black', font='normal')
                start,length = node.get_range()
                h.dump(highlight=start,length=length)
                
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
                    h.dump(highlight=start,length=length)
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
                columns=['count(inode)'],
                names=['Number of HTTP Get Requests'],
                table='http',
                case=query['case']
                )
            return output

        def irc(query,output):
            output.table(
                columns=['count(inode)'],
                names=['Number of IRC Messages'],
                table='irc_messages',
                case=query['case']
                )
            return output

        def msn(query,output):
            output.table(
                columns=['count(inode)'],
                names=['Number of MSN Messages'],
                table='msn_messages',
                case=query['case']
                )
            return output

        def email(query,output):
            output.table(
                columns=['count(inode)'],
                names=['Number of Emails'],
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
