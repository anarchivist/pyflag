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
from pyflag.Scanner import *
import pyethereal
import struct,sys,cStringIO
import pyflag.DB as DB
from pyflag.FileSystem import File
import pyflag.IO as IO
import pyflag.FlagFramework as FlagFramework

def IP2str(ip):
    """ Returns a string representation of the 32 bit network order ip """
    tmp = list(struct.unpack('BBBB',struct.pack('L',ip)))
    tmp.reverse()
    return ".".join(["%s" % i for i in tmp])

class NetworkScanner(BaseScanner):
    """ This is the base class for all network scanners.
    """
    def process(self,data,metadata=None):
        """ Pre-process the data for all other network scanners """
        ## We try to get previously set proto_tree. We store it in
        ## a metadata structure so that scanners that follow us
        ## can reuse it. This ensure we do not un-necessarily
        ## dissect each packet.
        try:
            self.packet_id = self.fd.tell()-1
            self.proto_tree = metadata['proto_tree'][packet_id]
        except:
            ## Ensure ethereal doesnt fiddle with the sequence numbers
            ## for us:
            pyethereal.set_pref("tcp.analyze_sequence_numbers:false")

            ## Now dissect it.
            self.proto_tree = pyethereal.Packet(data,self.packet_id)

            ## Store it for the future
            metadata['proto_tree']={ packet_id: self.proto_tree }

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

    class Scan(BaseScanner):
        """ Each packet will cause a new instantiation of this class. """
        def process(self,data, metadata=None):
            """ We get a complete packet in data.

            We dissect it and add it to the connection table.
            """
            ## See if we can find what we need in this packet
            try:
                ipsrc=proto_tree['ip.src'].value()
                ipdest=proto_tree['ip.dst'].value()
                tcpsrcport=proto_tree['tcp.srcport'].value()
                tcpdestport=proto_tree['tcp.dstport'].value()
            except:
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
                    break

            if con_id<0:
                ## The opposite stream is found but not this stream
                if row:
                    ## We insert into the connection_details table...
                    ## FIXME: This is a potential race in multithreaded mode.
                    self.dbh.execute("insert into connection_details_%s set src_ip=%r, src_port=%r, dest_ip=%r, dest_port=%r",(
                        self.table, row['dest_ip'],row['dest_port'],row['src_ip'],row['src_port']))

                    ## Create a New VFS directory structure for this connection:
                    con_id=self.dbh.autoincrement()
                    self.ddfs.VFSCreate(None,"S%s" % (con_id) , "%s-%s/%s:%s/reverse" % (IP2str(row['src_ip']),IP2str(row['dest_ip']),row['src_port'], row['dest_port']))
                else:
                    self.dbh.execute("insert into connection_details_%s set src_ip=%r, src_port=%r, dest_ip=%r, dest_port=%r",(
                        self.table,
                        ipsrc,tcpsrcport, ipdest, tcpdestport))

                    ## Create a New VFS directory structure for this connection:
                    con_id=self.dbh.autoincrement()
                    self.ddfs.VFSCreate(None,"S%s" % (con_id) , "%s-%s/%s:%s/forward" % (IP2str(ipsrc),IP2str(ipdest),tcpsrcport, tcpdestport))

            ## Now insert into connection table:
            packet_id = self.fd.tell()-1
            seq = proto_tree['tcp.seq'].value()
            length = proto_tree['tcp.len'].value()
            tcp_node = proto_tree['tcp']
            
            ## We consider anything that follows the tcp header as
            ## data belonging to the stream:
            packet_offset = tcp_node.start()+tcp_node.length()

            self.dbh.execute("insert into connection_%s set con_id=%r,packet_id=%r,seq=%r,length=%r,packet_offset=%r",(self.table,con_id,packet_id,seq,length,packet_offset))

        def finish(self):
            self.dbh.check_index("connection_%s" % self.table, 'con_id')

def show_packets(query,result):
    """ Shows the packets which belong in this stream """
    con_id = int(query['inode'][1:])
        
    result.table(
        columns = ('packet_id','seq','length'),
        names = ('Packet ID','Sequence Number','Length'),
        links = [ FlagFramework.query_type((),family="Network Forensics",report='View Packet',case=query['case'],fsimage=query['fsimage'],__target__='id')],
        table= 'connection_%s' % query['fsimage'],
        where = 'con_id=%r' % con_id,
        case=query['case']
        )
            
class StreamFile(File):
    """ A File like object to reassemble the stream from individual packets.

    Note that this is currently a very Naive reassembler. Stream Reassembling is generally considered a very difficult task. The approach we take is to make a very simple reassembly, and have a different scanner check the stream for potetial inconsistancies.
    """
    specifier = 'S'
    stat_cbs = [ show_packets ]
    stat_names = [ "Show Packets"]
    
    def __init__(self, case, table, fd, inode):
        File.__init__(self, case, table, fd, inode)

        ## Strategy: We determine the ISN of this stream at
        ## startup. When requested to read a range we select all those
        ## packets whose seq number fall within the range, we then
        ## initialise the output buffer and copy the data from each of
        ## the hits onto the buffer at the correct spot. This allows
        ## us to have missing packets, as we will simply return 0 for
        ## the byte sequences we are missing.
        
        self.fd = IO.open(case,table)
        
        self.con_id = int(inode[1:])
        self.dbh = DB.DBO(self.case)
        self.dbh.execute("select min(seq) as isn from connection_%s where con_id=%s",(self.table,self.con_id))
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
                start+row['seq']-self.isn-self.readptr)

        result.seek(0)
        data=result.read()
        result.close()
        self.readptr+=len
        return data
