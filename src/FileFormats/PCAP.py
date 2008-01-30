# ******************************************************
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.86RC1 Date: Thu Jan 31 01:21:19 EST 2008$
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
    fields = [
        ['magic',         ULONG],
        ['version_major', WORD],
        ['version_minor', WORD],
        ['thiszone',      ULONG, None, "gmt to local correction"],
        ['sigfigs',       ULONG, None, "accuracy of timestamps"],
        ['snaplen',       ULONG, None, "max length saved portion of each pkt"],
        ['linktype',      ULONG, None, "data link type (LINKTYPE_*)"],
        ]
    
    def read(self):
        ## Try to read the file with little endianess
        self.parameters['endianess']='l'

        ## Try to find the little endianness magic within the first
        ## 1000 bytes - There could be some crap at the start of the
        ## file.
        tmp = self.buffer[0:1000]
        off =tmp.search(struct.pack("<L",0xa1b2c3d4)) 
        if off>=0:
            self.offset = off
            self.buffer = self.buffer[off:]
            result=SimpleStruct.read(self)
            self.start_of_file = off
            self.start_of_data = self.offset
            return result

        off=tmp.search(struct.pack(">L",0xa1b2c3d4))
        if off>=0:
            self.parameters['endianess']='b'
            self.offset = off
            self.buffer = self.buffer[off:]
            result=SimpleStruct.read(self)
            self.start_of_file = off
            self.start_of_data = self.offset
            return result

        result=SimpleStruct.read(self)
        ## Dont know the magic
        raise IOError('This is not a pcap magic (%s) at offset 0x%08X' % (result['magic'], self.buffer.offset))
    
    def __iter__(self):
        self.offset = self.start_of_data
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
    fields = [
        ['ts_sec',  TIMESTAMP, None, "time stamp"],
        ['ts_usec', ULONG,     None, "Time in usecs"],
        ['caplen',  ULONG,     None, "length of portion present"],
        ['length',  ULONG,     None, "length this packet (off wire)"]
        ]

    def read(self):
        result=SimpleStruct.read(self)
        caplen = int(result['caplen'])
        if caplen>64000:
            raise IOError("packet too large at %s, maybe PCAP file is corrupted" % caplen)

        s=RAW(self.buffer[self.offset:self.offset+caplen])
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
        #print packet['ts_sec'], packet['length'], packet.buffer.offset
        print packet
