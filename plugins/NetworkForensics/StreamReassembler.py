""" This module implements a simple stream reassembler.
"""
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.76 Date: Sun Apr 17 21:48:37 EST 2005$
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
import pyethereal
import struct,sys,cStringIO
import pyflag.DB as DB
from pyflag.FileSystem import File
import pyflag.IO as IO
import pyflag.FlagFramework as FlagFramework
from NetworkScanner import *

class StreamReassembler(GenScanFactory):
    """ This scanner reassembles the packets into the streams.

    We internally use two tables. The first is connection_details,
    which contains ip and port tuples identifying the connection. The
    connection table contains a list of packets comprising each
    connection and some shortcuts to access their data.
    """
    default = True

    def prepare(self):
        ## We create the tables we need
        self.dbh.execute(
            """CREATE TABLE if not exists `connection_details_%s` (
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

        ## Ensure that the connection_details table has indexes. We
        ## need the indexes because we are about to do lots of selects
        ## on this table.
        self.dbh.check_index("connection_details_%s" % self.table,'src_ip')
        self.dbh.check_index("connection_details_%s" % self.table,'src_port')
        self.dbh.check_index("connection_details_%s" % self.table,'dest_ip')
        self.dbh.check_index("connection_details_%s" % self.table,'dest_port')

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
                tcpsrcport=self.proto_tree['tcp.srcport'].value()
                tcpdestport=self.proto_tree['tcp.dstport'].value()
                ipsrc=self.proto_tree['ip.src'].value()
                ipdest=self.proto_tree['ip.dst'].value()
            except KeyError,e:
                return
            
            ## check the connection_details table to see if we have
            ## done this connection previously:
            self.dbh.execute("select * from connection_details_%s where (src_ip=%r and src_port=%r and dest_ip=%r and dest_port=%r) or (src_ip=%r and src_port=%r and dest_ip=%r and dest_port=%r)",(
                self.table,
                ipsrc,tcpsrcport, ipdest, tcpdestport,
                ipdest, tcpdestport,ipsrc,tcpsrcport,
                ))

            con_id=-1
            row=None
            
            for row in self.dbh:
                ## This row represents our connection
                if row['src_ip']==ipsrc:
                    con_id=row['con_id']
                    isn = row['isn']
                    break

            if con_id<0:
                ## The opposite stream is found but not this stream
                if row:
                    ## We insert into the connection_details table...
                    ## FIXME: This is a potential race in multithreaded mode.
                    isn = self.proto_tree['tcp.seq'].value()

                    self.dbh.execute("insert into connection_details_%s set src_ip=%r, src_port=%r, dest_ip=%r, dest_port=%r, isn=%r ",(
                        self.table, row['dest_ip'],row['dest_port'],
                        row['src_ip'],row['src_port'],
                        isn))

                    ## Create a New VFS directory structure for this connection:
                    con_id=self.dbh.autoincrement()
                    self.ddfs.VFSCreate(None,"S%s" % (con_id) , "%s-%s/%s:%s/reverse" % (IP2str(row['src_ip']),IP2str(row['dest_ip']),row['src_port'], row['dest_port']))
                else:
                    isn = self.proto_tree['tcp.seq'].value()
                    self.dbh.execute("insert into connection_details_%s set src_ip=%r, src_port=%r, dest_ip=%r, dest_port=%r, isn=%r",(
                        self.table,
                        ipsrc,tcpsrcport, ipdest, tcpdestport,
                        isn))

                    ## Create a New VFS directory structure for this connection:
                    con_id=self.dbh.autoincrement()
                    self.ddfs.VFSCreate(None,"S%s" % (con_id) , "%s-%s/%s:%s/forward" % (IP2str(ipsrc),IP2str(ipdest),tcpsrcport, tcpdestport))

            ## Now insert into connection table:
            packet_id = self.fd.tell()-1
            seq = self.proto_tree['tcp.seq'].value()
            length = self.proto_tree['tcp.len'].value()
            tcp_node = self.proto_tree['tcp']
            
            ## We consider anything that follows the tcp header as
            ## data belonging to the stream:
            packet_offset = tcp_node.start()+tcp_node.length()

            self.dbh.execute("insert into connection_%s set con_id=%r,packet_id=%r,seq=%r,length=%r,packet_offset=%r",(self.table,con_id,packet_id,seq,length,packet_offset))

            ## Signal this inode to our clients
            metadata['inode']= "S%s" % con_id

            ## Note this connection's ISN to our clients
            metadata['isn']=isn

            ## Note the offset of this packet in the stream:
            metadata['stream_offset'] = seq-isn

        def finish(self):
            self.dbh.check_index("connection_%s" % self.table, 'con_id')

def combine_streams(query,result):
    """ Show both ends of the stream combined.

    In each screenfull we show a maximum of MAXSIZE characters per connection. We stop as soon as either direction reaches this many characters.
    """
    ## FIXME: Implement sensible paging here.
    
    ## First we find the reverse connection:
    table = query['fsimage']
    fd = IO.open(query['case'],table)
    
    forward_inode = query['inode']
    forward_cid = int(forward_inode[1:])

    dbh = DB.DBO(query['case'])
    dbh.execute("select * from connection_details_%s where con_id=%r",(table,forward_cid))
    row=dbh.fetch()
    
    dbh.execute("select con_id from connection_details_%s where src_ip=%r and src_port=%r and dest_ip=%r and dest_port=%r",(table,row['dest_ip'],row['dest_port'],row['src_ip'],row['src_port']))
    row = dbh.fetch()
    reverse_cid = row['con_id']

    dbh.execute("select con_id,offset,packet_offset,connection_%s.length as length from connection_%s join pcap_%s on packet_id=id where con_id=%r or con_id=%r order by packet_id",(table,table,table,forward_cid,reverse_cid))
    for row in dbh:
        ## Get the data:
        fd.seek(row['offset']+row['packet_offset'])
        data=fd.read(row['length'])
        if row['con_id']==forward_cid:
            result.text(data,color="blue",font='typewriter',sanitise='full')
        else:
            result.text(data,color="red",font='typewriter',sanitise='full')
    
    
def show_packets(query,result):
    """ Shows the packets which belong in this stream """
    tmp = query['inode'][1:]
    table = query['fsimage']
    fd = IO.open(query['case'],table)
    dbh = DB.DBO(query['case'])
    
    con_id = int(tmp)

    def show_data(value,result):
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
        where = 'con_id=%r and packet_id=id ' % con_id,
        callbacks = { 'Data': show_data },
        case=query['case']
        )
            
class StreamFile(File):
    """ A File like object to reassemble the stream from individual packets.

    Note that this is currently a very Naive reassembler. Stream Reassembling is generally considered a very difficult task. The approach we take is to make a very simple reassembly, and have a different scanner check the stream for potetial inconsistancies.

    The inode format is:
    Scod_id[:offset]

    con_id is the connection ID
    offset is an optional offset
    """
    specifier = 'S'
    stat_cbs = [ show_packets, combine_streams ]
    stat_names = [ "Show Packets", "Combined streams"]
    
    def __init__(self, case, table, fd, inode):
        File.__init__(self, case, table, fd, inode)

        self.con_id = int(inode[1:])
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

    def read(self,len = None):
        if len==None:
            len=sys.maxint
            
        ##Initialise the output buffer:
        result = cStringIO.StringIO()

        ## Find out which packets fall within the range of interest
        self.dbh.execute("select * from connection_%s where con_id=%r and seq+length>=%r and seq<=%r",(
            self.table,
            self.con_id,
            self.isn+self.readptr, ## Start of range
            self.isn+self.readptr+len, ## End of range
            ))

        for row in self.dbh:
            ## This is the case where we start reading half way
            ## through a packet

            ##    row['seq']|--------->| row['len']
            ##      self.isn----->| readptr
            ##We are after  |<--->|
            if row['seq'] <= self.isn+self.readptr :
                start = self.isn + self.readptr - row['seq']
            else:
                start = 0

            ## This is the case where the packet extends past where we
            ## want to read:
            ## LHS = Where the packet ends in the seq number space
            ## RHS = Where we want to stop reading

            ##        row['seq']|------->| row['len']
            ## self.isn--->readptr--->| len
            ##     We are after |<--->|
            if row['seq']+row['length']>=self.isn+self.readptr+len:
                end=self.isn + self.readptr + len - row['seq']

            ##    row['seq']|------->| row['len']
            ## self.isn--->readptr------>| len
            ## We are after |<------>|
            else:
                end=row['length']

            ## We create the output buffer here:
            ## current packet         |<--->|  (begings at start+row[seq])
            ## self.isn--->readptr|---------->| len
            ## Output buffer      |<--------->|
            ## We want the offset |<->|  for result_offset
         
            self.readpkt(
                row['packet_id'],
                row['packet_offset'],
                start,
                end,
                result,
                start+row['seq']-self.isn-(self.readptr))

        result.seek(0)
        data=result.read()
        result.close()
        self.readptr+=len
        return data

    def seek(self,offset,rel=None):
        result= File.seek(self,offset,rel)
        return result

class OffsetFile(File):
    """ A simple offset:length file driver.

    The inode name specifies an offset and a length into our parent Inode.
    The format is offset:length
    """
    specifier = 'o'
    def __init__(self, case, table, fd, inode):
        File.__init__(self, case, table, fd, inode)
        tmp = inode.split('|')[-1]
        tmp = tmp[1:].split(":")
        self.offset = int(tmp[0])
        try:
            self.size=int(tmp[1])
        except IndexError:
            self.size=0

    def seek(self,offset,rel=None):
        result = File.seek(self,offset,rel)

        self.fd.seek(self.readptr + self.offset)
        return result
    
    def read(self,length=None):
        if length==None:
            result=self.fd.read()
        else:
            result=self.fd.read(length)
            
        self.readptr+=len(result)
        return result
