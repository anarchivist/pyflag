""" This module implements a simple stream reassembler.
"""
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.78 Date: Fri Aug 19 00:47:14 EST 2005$
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
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.Registry as Registry
from pyflag.Scanner import *
import struct,sys,cStringIO
import pyflag.DB as DB
from pyflag.FileSystem import File,CachedFile
import pyflag.IO as IO
import pyflag.FlagFramework as FlagFramework
from NetworkScanner import *
import struct,re

class StreamReassembler(NetworkScanFactory):
    """ This scanner reassembles the packets into the streams.

    We internally use two tables. The first is connection_details,
    which contains ip and port tuples identifying the connection. The
    connection table contains a list of packets comprising each
    connection and some shortcuts to access their data.
    """
    default = True
    order=5

    class Drawer(Scanner.FSSpecialisedDrawer):
        description = "Network Scanners"
        name = "NetworkScanners"
        contains = [ "IRCScanner", "MSNScanner", "HTTPScanner", "POPScanner","SMTPScanner","RFC2822" ]
        default = True
        special_fs_name = 'PCAPFS'

            
    def prepare(self):
        ## We create the tables we need: The connection_details table
        ## stores information about each connection, while the
        ## connection table store all the packets belonging to each
        ## connection.
        self.dbh.execute(
            """CREATE TABLE if not exists `connection_details_%s` (
            `inode` varchar(250),
            `con_id` int(11) unsigned NOT NULL auto_increment,
            `src_ip` int(11) unsigned NOT NULL default '0',
            `src_port` int(11) unsigned NOT NULL default '0',
            `dest_ip` int(11) unsigned NOT NULL default '0',
            `dest_port` int(11) unsigned NOT NULL default '0',
            `isn` int(100) unsigned NOT NULL default 0,
            KEY `con_id` (`con_id`)
            )""",(self.table,))
        self.dbh.execute(
            """CREATE TABLE if not exists `connection_%s` (
            `con_id` int(11) unsigned NOT NULL default '0',
            `packet_id` int(11) unsigned NOT NULL default '0',
            `seq` int(11) unsigned NOT NULL default '0',
            `length` mediumint(9) unsigned NOT NULL default '0',
            `packet_offset`  mediumint(9) unsigned NOT NULL default '0'
            ) """,(self.table,))
        self.connection_cache={}

    def reset(self):
        self.dbh.execute("drop table connection_%s",(self.table,))
        self.dbh.execute("drop table connection_details_%s",(self.table,))

    class Scan(NetworkScanner):
        """ Each packet will cause a new instantiation of this class. """
        def process(self,data, metadata=None):
            """ We get a complete packet in data.

            We dissect it and add it to the connection table.
            """
            NetworkScanner.process(self,data,metadata)

            ## See if we can find what we need in this packet
            try:
                tcpsrcport=self.proto_tree['tcp.src_port']
                tcpdestport=self.proto_tree['tcp.dest_port']
                ipsrc=self.proto_tree['ip.src']
                ipdest=self.proto_tree['ip.dest']
                packet_offset = self.proto_tree['tcp.data_offset']
            except KeyError,e:
                return

            ## Here we try and cache connection information in memory
            ## so we dont hit the db so much
            forward_key = struct.pack("IIII",ipsrc,ipdest,tcpsrcport,tcpdestport)

            ## The following tests the cache for both forward or
            ## reverse connections, creating them if needed.
            try:
                con_id,isn = self.outer.connection_cache[forward_key]
            except KeyError:
                #We dont have the forward connection, maybe we have
                #the reverse?
                try:
                    reverse_key = struct.pack("IIII",ipdest,ipsrc,tcpdestport,tcpsrcport)
                    con_id,isn = self.outer.connection_cache[reverse_key]

                    ## Create the current connection for this one:
                    isn = self.proto_tree['tcp.seq']+1

                    self.dbh.execute("insert into connection_details_%s set src_ip=%r, src_port=%r, dest_ip=%r, dest_port=%r, isn=%r ",(
                        self.table, ipsrc,tcpsrcport,
                        ipdest,tcpdestport,
                        isn))
                    
                    ## Create a New VFS directory structure for this connection:
                    con_id=self.dbh.autoincrement()
                    self.ddfs.VFSCreate(None,"S%s" % (con_id) , "%s-%s/%s:%s/reverse" % (IP2str(ipdest),IP2str(ipsrc),tcpdestport, tcpsrcport))
                    ## Cache it:
                    self.outer.connection_cache[forward_key]=(con_id,isn)
                    
                except KeyError:
                    ## Nope - we dont have that either, we need to
                    ## create a new node for the forward stream:
                    
                    isn = self.proto_tree['tcp.seq']+1
                    self.dbh.execute("insert into connection_details_%s set src_ip=%r, src_port=%r, dest_ip=%r, dest_port=%r, isn=%r",(
                        self.table,
                        ipsrc,tcpsrcport, ipdest, tcpdestport,
                        isn))

                    ## Create a New VFS directory structure for this connection:
                    con_id=self.dbh.autoincrement()
                    self.ddfs.VFSCreate(None,"S%s" % (con_id) , "%s-%s/%s:%s/forward" % (IP2str(ipsrc),IP2str(ipdest),tcpsrcport, tcpdestport))
                    
                    ## Cache it:
                    self.outer.connection_cache[forward_key]=(con_id,isn)

                    ## END CREATE FORWARD STREAM
                    
            ## Now insert into connection table:
            packet_id = self.fd.tell()-1
            seq = self.proto_tree['tcp.seq']
            length = self.proto_tree['tcp.data_len']
            
            self.dbh.execute("insert into connection_%s set con_id=%r,packet_id=%r,seq=%r,length=%r, packet_offset=%r",(self.table,con_id,packet_id,seq,length, packet_offset))

            ## Signal this inode to our clients
            metadata['inode']= "S%s" % con_id

            ## Note this connection's ISN to our clients
            metadata['isn']=isn

            ## Note the offset of this packet in the stream:
            metadata['stream_offset'] = seq-isn

        def finish(self):
            if not NetworkScanner.finish(self): return
            
            self.dbh.check_index("connection_%s" % self.table, 'con_id')
            ## Ensure that the connection_details table has indexes. We
            ## need the indexes because we are about to do lots of selects
            ## on this table.
            self.dbh.check_index("connection_details_%s" % self.table,'src_ip')
            self.dbh.check_index("connection_details_%s" % self.table,'src_port')
            self.dbh.check_index("connection_details_%s" % self.table,'dest_ip')
            self.dbh.check_index("connection_details_%s" % self.table,'dest_port')

def combine_streams(query,result):
    """ Show both ends of the stream combined.

    In each screenfull we show a maximum of MAXSIZE characters per connection. We stop as soon as either direction reaches this many characters.
    """
    ## FIXME: Implement sensible paging here.
    
    ## First we find the reverse connection:
    table = query['fsimage']
    fd = IO.open(query['case'],table)

    #extract stream id from inode
    m=re.match("S(\d+)",query['inode'])
    
    forward_inode = m.group(1)
    forward_cid = int(forward_inode)

    dbh = DB.DBO(query['case'])
    dbh.execute("select * from connection_details_%s where con_id=%r",(table,forward_cid))
    row=dbh.fetch()
    
    dbh.execute("select con_id from connection_details_%s where src_ip=%r and src_port=%r and dest_ip=%r and dest_port=%r",(table,row['dest_ip'],row['dest_port'],row['src_ip'],row['src_port']))
    row = dbh.fetch()
    if row:
        reverse_cid = row['con_id']
    else:
        reverse_cid = 0

    dbh.execute("select con_id,offset,packet_offset,connection_%s.length as length from connection_%s join pcap_%s on packet_id=id where con_id=%r or con_id=%r order by packet_id",(table,table,table,forward_cid,reverse_cid))
    for row in dbh:
        ## Get the data:
        fd.seek(row['offset']+row['packet_offset'])
        data=fd.read(row['length'])
        if row['con_id']==forward_cid:
            result.text(data,color="blue",font='typewriter',sanitise='full',wrap='full')
        else:
            result.text(data,color="red",font='typewriter',sanitise='full',wrap='full')    
    
def show_packets(query,result):
    """ Shows the packets which belong in this stream """
    inode = query['inode']
    table = query['fsimage']
    fd = IO.open(query['case'],table)
    dbh = DB.DBO(query['case'])

    try:
        con_id = int(inode[1:])
    except ValueError:
        dbh.execute("select con_id from connection_details_%s where inode=%r",(table,inode))
        row=dbh.fetch()
        con_id=row['con_id']
            
    def show_data(value):
        length,packet_offset,packet_id = value.split(",")
        length=int(length)
        dbh.execute("select offset from pcap_%s where id=%s",(table,packet_id))
        row = dbh.fetch()
        fd.seek(row['offset'] + int(packet_offset))
        ## We read at most this many chars from the packet:
        elipses=''
        
        if length>50:
            length=50
            elipses=' ... '
            
        data=fd.read(length)

        ## Sanitise data
        return data+elipses
    
    result.table(
        columns = ('packet_id','from_unixtime(ts_sec)','ts_usec','seq','con.length','concat(con.length,",",packet_offset,",",packet_id)'),
        names = ('Packet ID','Timestamp','uSec','Sequence Number','Length',"Data"),
        links = [ FlagFramework.query_type((),family="Network Forensics",report='View Packet',case=query['case'],fsimage=query['fsimage'],__target__='id')],
        table= 'connection_%s as con , pcap_%s' % (query['fsimage'],query['fsimage']),
        where = 'con_id="%s" and packet_id=id ' % con_id,
        callbacks = { 'Data': show_data },
        case=query['case']
        )
            
class StreamFile(File):
    """ A File like object to reassemble the stream from individual packets.

    Note that this is currently a very Naive reassembler. Stream Reassembling is generally considered a very difficult task. The approach we take is to make a very simple reassembly, and have a different scanner check the stream for potetial inconsistancies.

    The inode format is:
    Scon_id/con_id/con_id

    con_ids are the connection IDs. If more than one con_id is
    specified we merge all connections into the same stream based on
    arrival time.
    """
    stat_cbs = [ show_packets, combine_streams ]
    stat_names = [ "Show Packets", "Combined streams"]
    
    def __init__(self, case, table, fd, inode):
        File.__init__(self, case, table, fd, inode)

        ## We allow the user to ask for a number of streams which will
        ## be combined at the same time. This allows us to create a
        ## VFS node for both forward and reverse streams, or even
        ## totally unrelated streams which happen at the same time.

        ## This is handled by creating a "virtual stream" - a new
        ## stream with a new stream id which collects all the packets
        ## in the component streams in chronological order.

        ## We use the inode column in the connection_details table to
        ## cache this so we only have to combine the streams once.
        try:
            self.con_id = int(inode[1:])
        except ValueError: ## We have / in the inode name
            self.dbh.execute("select con_id from connection_details_%s where inode=%r",(self.table,inode))
            row=self.dbh.fetch()
            if row:
                self.con_id=row['con_id']
            else:
                self.con_id=self.create_new_stream(inode[1:].split("/"))
            
        ## Strategy: We determine the ISN of this stream at
        ## startup. When requested to read a range we select all those
        ## packets whose seq number fall within the range, we then
        ## initialise the output buffer and copy the data from each of
        ## the hits onto the buffer at the correct spot. This allows
        ## us to have missing packets, as we will simply return 0 for
        ## the byte sequences we are missing.
        
        self.fd = IO.open(case,table)
        
        self.dbh = DB.DBO(self.case)
        self.dbh.execute("select isn from connection_details_%s where con_id=%r",(self.table,self.con_id))
        row=self.dbh.fetch()
        if not row:
            raise IOError("No stream with connection ID %s" % self.con_id)

        self.isn = row['isn']
        self.dbh.execute("select max(seq+length) as size from connection_%s where con_id=%r",(self.table,self.con_id))
        row=self.dbh.fetch()
        self.size=row['size']-self.isn

    def create_new_stream(self,stream_ids):
        """ Creates a new stream by combining the streams given by the list stream_ids.
        
        @return the new stream id.
        """
        ## Store the new stream in the cache:
        self.dbh.execute("insert into connection_details_%s set inode=%r",(self.table,self.inode))
        con_id = self.dbh.autoincrement()
        self.dbh2 = self.dbh.clone()
        sum=0
        self.dbh.execute("select * from connection_%s where %s order by packet_id",(
            self.table," or ".join(["con_id=%r" % a for a in stream_ids])
            ))
        for row in self.dbh:
            self.dbh2.execute("insert into connection_%s set con_id=%r,packet_id=%r,seq=%r,length=%r,packet_offset=%r",(
                self.table,con_id,row['packet_id'],sum,
                row['length'],row['packet_offset']
                ))
            sum+=row['length']

        return con_id

    def readpkt(self,pkt_id,packet_offset,start,end,result,result_offset):
        """ This function gets the data from pkt_id and pastes it into
        the file like object in result at offset result_offset.

        We basically do this: pkt_id.data[start:end] -> result[result_offset]
        @arg pkt_id: The packet ID
        @arg packet_offset: The offset within the packet where the data starts
        @arg start: The start within the data segment where we want to copy from
        @arg end: The end point to copy till
        @arg result: A cStringIO object to copy the data to
        @arg result_offset: The position in the cStringIO to paste to
        """
        dbh = DB.DBO(self.case)
        dbh.execute("select * from pcap_%s where id=%r",(self.table,pkt_id))
        row = dbh.fetch()

        self.fd.seek(row['offset']+packet_offset+start)
        
        data = self.fd.read(end-start)
        result.seek(result_offset)
        result.write(data)

    def read(self,length = None):
        if length==None:
            length=sys.maxint

        if length>self.size-self.readptr:
            length=self.size-self.readptr
        ##Initialise the output buffer:
        result = cStringIO.StringIO()

        ## Find out which packets fall within the range of interest
        self.dbh.execute("select * from connection_%s where con_id=%r and seq+length>=%r and seq<=%r order by seq",(
            self.table,
            self.con_id,
            self.isn+self.readptr, ## Start of range
            self.isn+self.readptr+length, ## End of range
            ))

        for row in self.dbh:
            self.seq = row['seq']
            ## This is the case where we start reading half way
            ## through a packet

            ##    row['seq']|--------->| row['length']
            ##      self.isn----->| readptr
            ##We are after  |<--->|
            if self.seq <= self.isn+self.readptr :
                start = self.isn + self.readptr - self.seq
            else:
                start = 0

            ## This is the case where the packet extends past where we
            ## want to read:
            ## LHS = Where the packet ends in the seq number space
            ## RHS = Where we want to stop reading

            ##        row['seq']|------->| row['length']
            ## self.isn--->readptr--->| length
            ##     We are after |<--->|
            if self.seq+row['length']>=self.isn+self.readptr+length:
                end=self.isn + self.readptr + length - self.seq

            ##    row['seq']|------->| row['length']
            ## self.isn--->readptr------>| length
            ## We are after |<------>|
            else:
                end=row['length']

            ## We create the output buffer here:
            ## current packet         |<--->|  (begings at start+row[seq])
            ## self.isn--->readptr|---------->| length
            ## Output buffer      |<--------->|
            ## We want the offset |<->|  for result_offset
         
            self.readpkt(
                row['packet_id'],
                row['packet_offset'],
                start,
                end,
                result,
                start+self.seq-self.isn-(self.readptr))

        result.seek(0)
        data=result.read()
        result.close()
        self.readptr+=len(data)
        return data

    def seek(self,offset,rel=None):
        result= File.seek(self,offset,rel)
        return result

    def get_packet_id(self, position=None):
        """ Gets the current packet id (where the readptr is currently at) """
        if not position:
            position = self.tell()
            
        self.dbh.execute("select con_id,isn from connection_details_%s where inode=%r",(self.table,self.inode))
        row=self.dbh.fetch()
        if not row:
            self.dbh.execute("select con_id,isn from connection_details_%s where con_id=%r",(self.table,self.inode[1:]))
            row=self.dbh.fetch()
            
        con_id,isn = row['con_id'],row['isn']
        self.dbh.execute("""select packet_id from connection_%s where
                         con_id = %r and seq <= (%r+%r) order by seq desc, length desc limit 1""",
                         (self.table, con_id, isn, position))
        row=self.dbh.fetch()
        return row['packet_id']

class CachedStreamFile(CachedFile,StreamFile):
    """ A StreamFile VFS node with file based cache.

    Due to complex operations required to reassemble the streams on the fly we find that its quicker to cache these streams on disk.
    """
    specifier = 'S'
    target_class = StreamFile

class OffsetFile(File):
    """ A simple offset:length file driver.

    The inode name specifies an offset and a length into our parent Inode.
    The format is offset:length
    """
    specifier = 'o'
    def __init__(self, case, table, fd, inode):
        File.__init__(self, case, table, fd, inode)

        ## We parse out the offset and length from the inode string
        tmp = inode.split('|')[-1]
        tmp = tmp[1:].split(":")
        self.offset = int(tmp[0])
        self.readptr=0
        
        ## Seek our parent file to its initial position
        self.fd.seek(self.offset)

        try:
            self.size=int(tmp[1])
        except IndexError:
            self.size=sys.maxint

    def seek(self,offset,whence=0):
        if whence==2:
            self.readptr=self.size+offset
        elif whence==1:
            self.readptr+=offset
        else:
            self.readptr=offset

        self.fd.seek(self.offset + self.readptr)

    def tell(self):
        return self.readptr
    
    def read(self,length=None):
        available = self.size - self.readptr
        if length==None:
            length=available
        else:
            if length > available:
                length = available

        if(length<0): return ''

        result=self.fd.read(length)
        
        self.readptr+=len(result)
        return result

## There is no point in caching the offset file since its basically
## not doing much underlying stuff
##class CachedOffsetFile(CachedFile, OffsetFile):
##    target_class = OffsetFile    
