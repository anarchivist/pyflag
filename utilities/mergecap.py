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

""" This is a reimplementation of the ethereal mergecap program. The
ethereal mergecap program is fine for few small merging capture files
but have a file size limit of 2GB. Also ethereal's mergecap will try
to open all the files at once running out of filehandles if there are
too many files.
"""
import glob,bisect,sys
import Store
import FileFormats.PCAP as PCAP
from format import Buffer
import pyflag.conf
config=pyflag.conf.ConfObject()

config.set_usage(usage="""%prog -w Output [options] pcap_file ... pcap_file

Will merge all pcap files into the Output file which must be
specified. The pcap files are sorted on their PCAP timestamps. It is
assumed that each file contains packets in time order.

This version of mergecap has no file size limits or file number
limits.

This implementation of mergecap is done in pure python so its a little
slow.
""", version="Version: %prog PyFlag "+config.VERSION)

config.add_option("glob",  short_option='g',
                  help = """Load All files in the glob. This is useful when there are too many
                  files to expand in the command line. To use this option you will need
                  to escape the * or ? to stop the shell from trying to expand them.""")

config.add_option("write", default="merged.pcap", short_option='w',
                  help = "The output file to write. (Mandatory)")

config.add_option("split", default=2000000000, type='int',short_option='s',
                  help = "The Maximum size of the output file")

config.parse_options()

if config.glob:
    print "Globbing %s "% config.glob
    g = config.glob.replace('\\*','*')
    args.extend(glob.glob(g))
    print "Will merge %s files" % len(args)

if len(args)==0:
    print "Must specify some files to merge, try -h for help"
    sys.exit(-1)

## This will hold our filehandles - if this number is too large, we
## will run out of file handles.
store = Store.Store(max_size=5)

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
            self.endianess = header.parameters['endianess']
            
            ## Position the offset at the end of the header
            self.offset = header.start_of_file+header.size()

            ## Remember the header data
            self.header = buffer[header.start_of_file:self.offset].__str__()

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
        if buffer.size > 1600:
            data = buffer[:1600].__str__()
        else:
            data = buffer.__str__()

        ## Preserve the endianess of the file:
        packet = PCAP.Packet(data, endianess = self.endianess)
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
                fd=PcapFile(f)
            except IOError:
                print "Unable to read %s, skipping" % f
                continue

            #print "Adding file %s" % f
            self.put(fd)

    def put(self, f):
        """ Stores PcapFile f in sequence """
        try:
            p=f.next()
        except IOError,e:
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

length = len(f.files[0].header)
file_number = 0
for data in f:
    length+=len(data)
    if length>options.split:
        file_number+=1
        print "Creating a new file %s%s" % (options.write, file_number)
        outfile = open("%s%s" % (options.write,file_number),'w')
        
        ## Write the file header on:
        outfile.write(f.files[0].header)
        length = len(f.files[0].header) + len(data)
        
    ## Write the packet onto the file:
    outfile.write(data)
