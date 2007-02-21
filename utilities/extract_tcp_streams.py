""" This utility extracts packets relevant to streams into a new PCAP
file. This could be useful for example in getting other tools to
process specfic protocols that PyFlag doesnt at present support.
"""

from optparse import OptionParser
import FileFormats.PCAP as PCAP
from format import Buffer
import pyflag.pyflaglog as logging
import pyflag.conf
config=pyflag.conf.ConfObject()
import  FlagFramework
import sys
import pyflag.DB as DB
import pyflag.IO as IO

parser = OptionParser(usage="""%prog -w Output [options] [stream ids ...]

Will extract the specified streams into a new PCAP file specified by Output.

Notes:
  - We assume that all streams can from the same endianness PCAP files.
  - The output file will contains all packets from each stream in turn - we do not sort the output. If you need a sorted output, run this program on each stream individually and use mergecap on all of them.""", version="Version %prog PyFlag "+config.VERSION)

parser.add_option("-w", "--write", default="merged.pcap",
                  help = "The output file to write. (Mandatory)")

parser.add_option("-c", "--case", default=None,
                  help = "The case to read from. (Mandatory)")

parser.add_option("-f", "--file", default=None,
                  help = "A single file of connection ids, one per line")

(options, args) = parser.parse_args()

if not options.case or not options.write:
    print "Mandatory args missing - run me with --help for help"
    sys.exit(1)

## Create the PCAP header for the new file:
dbh=DB.DBO(options.case)
dbh.execute("select * from pcap limit 1")
row = dbh.fetch()

io = IO.open(options.case, row['iosource'])
fd = Buffer(fd=io)

## Read the header:
header = PCAP.FileHeader(fd)

io.seek(0)
data = io.read(header.start_of_data)

## Open file for writing:
outfd = open(options.write, 'w')
outfd.write(data)

## Now grab the data packets for all the relevant streams:
def write_stream(con_id):
    dbh2= dbh.clone()
    dbh.execute("select pcap.id as id,iosource,offset,pcap.length from `connection`,pcap where pcap.id=`connection`.packet_id and con_id = %r order by packet_id" % con_id)
    for row in dbh:
        ## This should not be too slow as its cached in the IO module
        ## Store
        io = IO.open(options.case, row['iosource'])
        io.seek(row['offset'])
        data = io.read(row['length'])
        outfd.write(data)

## Do the streams on the command line
for stream in args:
    write_stream(stream)

## Now from file:
if options.file:
    fd = open(options.file,'r')
    for line in fd:
        line = line.strip()
        write_stream(stream)
