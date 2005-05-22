""" These are some basic scanners which users should usually want to run.
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
import struct

def IP2str(ip):
    """ Returns a string representation of the 32 bit network order ip """
    tmp = list(struct.unpack('BBBB',struct.pack('L',ip)))
    tmp.reverse()
    return ".".join(["%s" % i for i in tmp])

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

        ## We start counting packets
        self.count=0

    def reset(self):
        self.dbh.execute("drop table connection_%s",(self.table,))
        self.dbh.execute("drop table connection_details_%s",(self.table,))

    class Scan(BaseScanner):
        """ Each packet will cause a new instantiation of this class. """
        def process(self,data, metadata=None):
            """ We get a complete packet in data.

            We dissect it and add it to the connection table.
            """
            ## Ensure ethereal doesnt fiddle with the sequence numbers
            ## for us:
            pyethereal.set_pref("tcp.analyze_sequence_numbers:false")
            
            ## Now dissect it.
            proto_tree = pyethereal.Packet(data,self.outer.count)
            self.outer.count+=1

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
            self.dbh.execute("select * from connection_details_%s where src_ip=%r and src_port=%r and dest_ip=%r and dest_port=%r",(
                self.table, ipsrc,tcpsrcport, ipdest, tcpdestport))
            
            row=self.dbh.fetch()
            if not row:
                ## We insert into the connection_details table...
                ## FIXME: This is a potential race in multithreaded mode.
                self.dbh.execute("insert into connection_details_%s set src_ip=%r, src_port=%r, dest_ip=%r, dest_port=%r",(
                    self.table, ipsrc,tcpsrcport, ipdest, tcpdestport))

                ## Create a New VFS directory structure for this connection:
                con_id=self.dbh.autoincrement()
                self.ddfs.VFSCreate(None,"Sf%s" % (con_id) , "%s-%s/%s:%s/forward" % (IP2str(ipsrc),IP2str(ipdest),tcpsrcport, tcpdestport))
            else:
                con_id=row['con_id']

            ## Now insert into connection table:
            packet_id = self.fd.tell()
            seq = proto_tree['tcp.seq'].value()
            length = proto_tree['tcp.len'].value()
            tcp_node = proto_tree['tcp']
            
            ## We consider anything that follows the tcp header as
            ## data belonging to the stream:
            packet_offset = tcp_node.start()+tcp_node.length()

            self.dbh.execute("insert into connection_%s set con_id=%r,packet_id=%r,seq=%r,length=%r,packet_offset=%r",(self.table,con_id,packet_id,seq,length,packet_offset))
            
