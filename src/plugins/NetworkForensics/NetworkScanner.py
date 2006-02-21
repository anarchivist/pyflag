""" This module contains functions which are shared among many plugins """
# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG  $Version: 0.80.1 Date: Tue Jan 24 13:51:25 NZDT 2006$
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
import pyflag.Scanner as Scanner
import dissect
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

## FIXME: This is currently not implemented...
class Storage:
    """ This class enables Network scanners to store persistant information between packets.

    We need to ensure that this persistant information does not consume too much memory. Every time a new piece of information is stored, we store the current packet number where it came from. Periodically we go through and expire those items which are too old.
    """
    data = {}
    ages = {}
    time_to_check = 100
    _time_to_check = 100
    max_age = 0
    too_old = 100
    
    def store(self,age,key,value):
        self.data[key]=value
        self.ages[key]=age
        if age>self.max_age:
            self.max_age=age

        self.check_me()

    def __getitem__(self,item):
        self.check_me()
        return self.data[item]

    def check_me(self):
        if self._time_to_check<=0:
            self._time_to_check=self.time_to_check
            for k in data.keys():
                if self.ages[k]+self.too_old<self.max_age:
                    del self.data[k]
                    del self.ages[k]
                    
        self._time_to_check-=1

class NetworkScanFactory(GenScanFactory):
    """ All network scanner factories come from here.

    This is used for scanners which need to invoke factories on VFS
    nodes. The VFS nodes are not network packets, so we only invoke
    those scanners which do not derive from this class. This class is
    therefore used to tag those scanners which only make sense to
    run on network traffic.
    """
    def stream_to_server(self, stream, protocol):
        if stream.dest_port in dissect.fix_ports(protocol):
            forward_stream = stream.con_id
            reverse_stream = find_reverse_stream(
                forward_stream,  self.dbh)
            
        elif stream.src_port in dissect.fix_ports(protocol):
            reverse_stream = stream.con_id
            forward_stream = find_reverse_stream(
                reverse_stream,  self.dbh)
        else:
            return None, None

        return forward_stream, reverse_stream

    def process_stream(self, stream, factories):
        pass
    
    def scan_as_file(self, inode, factories):
        """ Scans inode as a file (i.e. without any network scanners). """
        fd = self.fsfd.open(inode=inode)
        factories = [ x for x in factories if not isinstance(x,NetworkScanFactory) ]

        Scanner.scanfile(self.fsfd,fd,factories)
        fd.close()

                
class NetworkScanner(BaseScanner):
    """ This is the base class for all network scanners.
    """
    ## Note that Storage is the same object across all NetworkScanners:
    store = Storage()
    proto_tree = dissect.empty_dissector()

    def finish(self):
        """ Only allow scanners to operate on pcapfs inodes """
        try:
            if self.fd.link_type:
                return True
        except:
            return False
    
    def process(self,data,metadata=None):
        """ Pre-process the data for all other network scanners """
        try:
            ## We may only scan network related filesystems like
            ## pcapfs.
            link_type = self.fd.link_type
        except:
#            print "Not processing non network fs"
            return
        
        ## We try to get previously set proto_tree. We store it in
        ## a metadata structure so that scanners that follow us
        ## can reuse it. This ensure we do not un-necessarily
        ## dissect each packet.
        self.packet_id = self.fd.tell()-1
          
        try:
            self.proto_tree = metadata['proto_tree'][self.packet_id]
        except KeyError,e:
            ## Now dissect it.
            self.proto_tree = dissect.dissector(data,link_type)

            ## Store it for the future
            metadata['proto_tree']={ self.packet_id: self.proto_tree }

def find_reverse_stream(forward_stream,dbh):
    """ Given a connection ID and a table name, finds the reverse connection.

    return None if there is not reverse stream
    """
    dbh.execute("select * from connection_details where con_id=%r",
                (forward_stream))
    
    row=dbh.fetch()
    
    dbh.execute("select con_id from connection_details where src_ip=%r and src_port=%r and dest_ip=%r and dest_port=%r",(
        row['dest_ip'],row['dest_port'],row['src_ip'],row['src_port']))
    row=dbh.fetch()

    try:
        return row['con_id']
    except:
        return None
