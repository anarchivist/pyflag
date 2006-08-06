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
using the file format library though.
"""
from format import *
from plugins.FileFormats.BasicFormats import *
import sys

class FileHeader(SimpleStruct):
    """ The PCAP file header """
    def init(self):
        self.fields = [
            ['magic', ULONG],
            ['version_major', WORD],
            ['version_minor', WORD],
            ['thiszone', ULONG], #    /* gmt to local correction */
            ['sigfigs', ULONG],  #    /* accuracy of timestamps */
            ['snaplen', ULONG],  #    /* max length saved portion of each pkt */
            ['linktype', ULONG], #    /* data link type (LINKTYPE_*) */
            ]
        
    def read(self):
        result=SimpleStruct.read(self)
        if result['magic']!=0xa1b2c3d4:
            raise IOError('This is not a pcap magic at offset 0x%08X' % self.buffer.offset)

        self.start_of_file = self.offset
        return result
    
    def __iter__(self):
        self.offset = self.start_of_file
        return self

    def next(self):
        ## Try to read the next packet and return it:
        p = Packet(self.buffer[self.offset:])
        self.offset+=p.size()
        return p
        
class Packet(SimpleStruct):
    """ Each packet is preceeded by this. """
    def init(self):
        self.fields = [
            ['ts_sec', TIMESTAMP],    #      /* time stamp */
            ['ts_usec', ULONG],       #      /* Time in usecs */
            ['caplen', ULONG],        #      /* length of portion present */
            ['length', ULONG],        #      /* length this packet (off wire) */
            ]

    def read(self):
        result=SimpleStruct.read(self)
        s=BLOB(self.buffer[self.offset:],count=result['caplen'])
        if s.size()!=result['caplen']:
            raise IOError("Unable to read the last packet from the file (wanted %s, got %s). Is the file truncated?" % (result['caplen'], s.size()))
        
        self.offset+=s.size()
        self.add_element(result, 'data', s)

        return result

if __name__ == "__main__":
    fd=open(sys.argv[1],'r')
    b=Buffer(fd=fd)

    pcap = FileHeader(b)
    print pcap
    for packet in pcap:
        print packet
