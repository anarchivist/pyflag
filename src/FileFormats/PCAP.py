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
""" A library for reading PCAP files.

PCAP format is really simple so this is a nobrainer. Good example of
using the file format library though. This shows how we can handle the
endianess issue simply.
"""
from format import *
from plugins.FileFormats.BasicFormats import *
import sys

class FileHeader(SimpleStruct):
    """ The PCAP file header """
    def init(self):
        self.fields = [
            ['magic',         ULONG, self.parameters],
            ['version_major', WORD,  self.parameters],
            ['version_minor', WORD,  self.parameters],
            ['thiszone',      ULONG, self.parameters], #    /* gmt to local correction */
            ['sigfigs',       ULONG, self.parameters], #    /* accuracy of timestamps */
            ['snaplen',       ULONG, self.parameters], #    /* max length saved portion of each pkt */
            ['linktype',      ULONG, self.parameters], #    /* data link type (LINKTYPE_*) */
            ]
        
    def read(self):
        ## Try to read the file with little endianess
        self.parameters['endianess']='l'
        result=SimpleStruct.read(self)
        if result['magic']==0xa1b2c3d4:
            self.start_of_file = self.offset
            return result
        
        ## Its the wrong endianess, reread:
        elif result['magic']==0xd4c3b2a1:
            self.parameters['endianess']='b'
            result=SimpleStruct.read(self)
            self.start_of_file = self.offset
            return result

        ## Dont know the magic
        raise IOError('This is not a pcap magic (%s) at offset 0x%08X' % (result['magic'], self.buffer.offset))
    
    def __iter__(self):
        self.offset = self.start_of_file
        return self

    def next(self):
        ## Try to read the next packet and return it:
        try:
            b = self.buffer.__getslice__(self.offset)
            p = Packet(b, endianess=self.parameters['endianess'])
            self.offset+=p.size()
            return p
        except IOError:
            raise StopIteration
        
class Packet(SimpleStruct):
    """ Each packet is preceeded by this. """
    def init(self):
        self.fields = [
            ['ts_sec',  TIMESTAMP, self.parameters],    #      /* time stamp */
            ['ts_usec', ULONG,     self.parameters],    #      /* Time in usecs */
            ['caplen',  ULONG,     self.parameters],    #      /* length of portion present */
            ['length',  ULONG,     self.parameters],    #      /* length this packet (off wire) */
            ]

    def read(self):
        result=SimpleStruct.read(self)
        caplen = int(result['caplen'])
        if caplen>64000:
            raise IOError("packet too large at %s, maybe PCAP file is corrupted" % caplen)
        
        s=RAW(self.buffer[self.offset:],count=caplen)
        if s.size()!=caplen:
            raise IOError("Unable to read the last packet from the file (wanted %s, got %s). Is the file truncated?" % (result['caplen'], s.size()))
        
        self.offset+=caplen
        self.add_element(result, 'data', s)

        return result

    def payload(self):
        return self.data['data'].get_value().__str__()

if __name__ == "__main__":
    fd=open(sys.argv[1],'r')
    b=Buffer(fd=fd)

    pcap = FileHeader(b)
    print pcap
    for packet in pcap:
        print packet
#        print "%r" % packet['data']
