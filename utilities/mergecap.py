# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
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

""" This is a reimplementation of the ethereal mergecap program. The
ethereal mergecap program is fine for few small merging capture files
but have a file size limit of 2GB. Also ethereal's mergecap will try
to open all the files at once running out of filehandles if there are
too many files.
"""
from optparse import OptionParser
import glob,bisect
import Store
import FileFormats.PCAP as PCAP
from format import Buffer
import pyflag.logging as logging

## Hush up a bit
logging.config.LOG_LEVEL=5

parser = OptionParser()

parser.add_option("-g", "--glob", default=None,
                  help = "Load All files in the glob. This is useful when there are too many files to expand in the commandline.")

parser.add_option("-w", "--write", default="merged.pcap",
                  help = "The output file to write.")

(options, args) = parser.parse_args()

if options.glob:
    g = options.glob.replace('\\*','*')
    args.extend(glob.glob(g))

## This will hold our filehandles - if this number is too large, we
## will run out of file handles.
store = Store.Store(max_size=50)

class PcapFile:
    """ A class to encapsulate a pcap file """
    def __init__(self, filename):
        self.filename = filename
        self.offset = 0
        b = self.make_handle()

        ## Try to save it in the store
        self.handle = store.put(b)

    def make_handle(self):
        """ This opens and positions the file where we want it"""
        fd=open(self.filename,'r')
        buffer = Buffer(fd=fd)

        if self.offset==0: 
            ## This is done to ensure its a pcap file:
            header = PCAP.FileHeader(buffer)

            ## Position the offset at the end of the header
            self.offset = header.size()

            ## Remember the header data
            self.header = buffer[:self.offset].__str__()

        buffer = buffer[self.offset:]

        ## Now we should be ready to read the next one
        return buffer

    def __iter__(self):
        return self

    def next(self):
        ## Grab the next packet from our file:
        try:
            ## Is the file still in the store?
            buffer = store.get(self.handle)
        except KeyError:
            ## We got cleaned from the store - recreate ourselves:
            buffer = self.make_handle()
            self.handle = store.put(buffer)

        buffer.offset = self.offset
        ## This ensures that packet does not contain references to fd
        ## - which allows it to be closed when the store is full:
        try:
            data = buffer[:1600].__str__()
        except IOError:
            data = buffer.__str__()
            
        packet = PCAP.Packet(data)
        self.timestamp = int(packet['ts_sec'])+int(packet['ts_usec'])/1.0e6
        self.last_packet = packet
        size = packet.size()
        self.offset += size

        ## Keep a copy of the data - This will be later written to the
        ## output file
        self.raw_data = data[:size]

        return packet

class FileList:
    """ A sorted list of PcapFiles """
    def __init__(self, args):
        ## This keeps all instances of pcap files:
        self.files = []

        ## This is a list of the time of the next packet in each file (floats):
        self.times = []

        ## Initialise the timestamps of all args
        for f in args:
            try:
                f=PcapFile(f)
            except IOError:
                print "Unable to read %s, skipping" % f
                continue
            
            self.put(f)

    def put(self, f):
        """ Stores PcapFile f in sequence """
        try:
            p=f.next()
        except IOError:
            return
        
        offset = bisect.bisect(self.times, f.timestamp)
        self.files.insert(offset, f)
        self.times.insert(offset, f.timestamp)

    def __iter__(self):
        return self

    def next(self):
        ## Grab the next packet with the smallest timestamp:
        try:
            f = self.files.pop(0)
            t = self.times.pop(0)
        except IndexError:
            raise StopIteration

        raw_data = f.raw_data

        ## Stores the next timestamp:
        self.put(f)

        return raw_data


outfile = open(options.write,'w')
f=FileList(args)

## Write the file header on:
outfile.write(f.files[0].header)

for data in f:
    outfile.write(data)
