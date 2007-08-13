# ******************************************************
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.84RC4 Date: Wed May 30 20:48:31 EST 2007$
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
from format import Buffer
import pyflag.pyflaglog as logging
import pyflag.conf
config = pyflag.conf.ConfObject()

import pypcap

config.set_usage(usage = """%prog -w Output [options] pcap_file ... pcap_file

Will merge all pcap files into the Output file which must be
specified. The pcap files are sorted on their PCAP timestamps. It is
assumed that each file contains packets in time order.

This implementation of mergecap has no file size limits or file number
limits.

This is the fast implementation of mergecap done using the python pcap
extension module.
""", version = "Version: %prog PyFlag " + config.VERSION)

config.add_option("glob", short_option='g',
                  help = "Load All files in the glob. This is useful when there are too many"
                  " files to expand on the command line. To use this option you will need"
                  " to escape the * or ? to stop the shell from trying to expand them.")

config.add_option("write", default="merged.pcap", short_option='w',
                     help = "The output file to write. (Mandatory)")

config.add_option("split", default=2000000000, type='int', short_option='s',
                     help = "The Maximum size of the output file")

config.parse_options(True)

args = config.args[:]

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

class PCAPParser:
    offset = None
    
    def __init__(self, filename):
        """ opens and initialise the parser for the correct offset """
        self.filename = filename

    def __iter__(self):
        return self

    def reset(self):
        """ Close the file so that a next call will return the first packet again """
        store.expire(self.filename)
        self.offset = None

    def next(self):
        try:
            parser = store.get(self.filename)
        except KeyError:
            fd = open(self.filename)
            parser = pypcap.PyPCAP(fd)
            try:
                parser.seek(self.offset)
            except TypeError: pass
            
            store.put(parser, key=self.filename)

        packet = parser.next()
        self.offset = parser.offset()
        self.timestamp = packet.ts_sec + packet.ts_usec/1.0e6
        
        return packet
    
class FileList:
    """ A sorted list of PcapFiles """
    def __init__(self, args):
        ## This keeps all instances of pcap files:
        self.files = []

        ## This is a list of the time of the next packet in each file (floats):
        self.times = []
        self.firstValid = None

        ## Initialise the timestamps of all args
        for f in args:
            try:
                fd = PCAPParser(f)
                fd.next()

            except IOError:
                print "Unable to read %s, skipping" % f
                continue

            if not self.firstValid:
                self.firstValid = f


            self.put(fd)
            fd.reset()

    def put(self, f):
        """ Stores PcapFile f in sequence """

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

        try:
            p=f.next()

        ## Stores the next timestamp:
            self.put(f)
            
            return p
        except StopIteration:
            return self.next()

outfile = open(config.write,'w')
f=FileList(args)

fd = pypcap.PyPCAP(open(f.firstValid))

## Write the file header on:
header = fd.file_header().serialise()
outfile.write(header)

#for packet in fd:
#    outfile.write(packet.serialise())

#sys.exit(0)

count = 0

length = len(header)
file_number = 0
for packet in f:
    data = packet.serialise()
    length += len(data)
    count += len(data)

    if count > 1000000:
        sys.stdout.write(".")
        sys.stdout.flush()
#        print "Wrote %s Mbytes" % int(length/1e6)
        count = 0
    
    if length>config.split:
        file_number+=1
        print "Creating a new file %s%s" % (config.write, file_number)
        outfile = open("%s%s" % (config.write,file_number),'w')
        
        ## Write the file header on:
        outfile.write(header)
        length = len(header) + len(data)
        
    ## Write the packet onto the file:
    outfile.write(data)
