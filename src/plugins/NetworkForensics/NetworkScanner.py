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
    tmp = list(struct.unpack('=BBBB',struct.pack('=L',ip)))
    tmp.reverse()
    return ".".join(["%s" % i for i in tmp])
                
class NetworkScanner(BaseScanner):
    """ This is the base class for network scanners.

    Note that network scanners operate on discrete packets, where stream scanners operate on whole streams (and derive from StreamScannerFactory).
    """
    def __init__(self,inode,ddfs,outer,factories=None,fd=None):
        BaseScanner.__init__(self,inode,ddfs,outer,factories=factories,fd=fd)
        try:
            self.fd.link_type
            self.ignore = False
        except:
            self.ignore = True
            
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
            return
        
        ## We try to get previously set proto_tree. We store it in
        ## a metadata structure so that scanners that follow us
        ## can reuse it. This ensure we do not un-necessarily
        ## dissect each packet.
        self.packet_id = self.fd.tell()-1
        self.packet_offset = self.fd.packet_offset
        metadata['mime'] = "text/packet"
          
        try:
            self.proto_tree = metadata['proto_tree'][self.packet_id]
        except KeyError,e:
            ## Now dissect it.
            self.proto_tree = dissect.dissector(data, link_type,
                                  self.packet_id, self.packet_offset)

            ## Store it for the future
            metadata['proto_tree']={ self.packet_id: self.proto_tree }

class StreamScannerFactory(GenScanFactory):
    """ This is a scanner factory which allows scanners to only
    operate on streams.
    """
    order = 2

    def stream_to_server(self, stream, protocol):
        if stream.dest_port in dissect.fix_ports(protocol):
            forward_stream = stream.con_id
            reverse_stream = stream.reverse
            
##        elif stream.src_port in dissect.fix_ports(protocol):
##            reverse_stream = stream.con_id
##            forward_stream = stream.reverse
        else:
            return None, None

        return forward_stream, reverse_stream

    def process_stream(self, stream, factories):
        """ Stream scanners need to over ride this to process each stream """
        pass
    
    def scan_as_file(self, inode, factories):
        """ Scans inode as a file (i.e. without any Stream scanners). """
        print "Scanning as file inode %s" % inode
        fd = self.fsfd.open(inode=inode)
        factories = [ x for x in factories if not isinstance(x, StreamScannerFactory) ]

        Scanner.scanfile(self.fsfd,fd,factories)
        fd.close()

    class Scan(BaseScanner):
        def __init__(self,inode,ddfs,outer,factories=None,fd=None):
            BaseScanner.__init__(self,inode,ddfs,outer,factories=factories,fd=fd)
            try:
                ## This identifies our fd as a stream. We only operate
                ## on streams otherwise we do not wish to be bothered.
                self.fd.con_id
                self.ignore = False
            except AttributeError:
                self.ignore = True
                return
            
        def process(self, data, metadata=None):
            metadata['mime'] = "text/packet"
            
            ## Call the base classes process_stream method with the
            ## given stream.
            self.outer.process_stream(self.fd, self.factories)
