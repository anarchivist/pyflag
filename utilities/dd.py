from optparse import OptionParser
import sys

parser = OptionParser()
parser.add_option("-s", "--skip", default=0,
                  help = "Number of bytes to skip in the input file")

parser.add_option("-l", "--length", default=10000,
                  help = "Length of data to read in bytes")

parser.add_option("-i", "--if", default=sys.stdin,
                  help = "Input file to use")

parser.add_option("-o", "--of", default=sys.stdout,
                  help = "Output file")

parser.add_option("-b", "--blocksize", default=64*1024,
                  help = "Blocksize to read")

(options, args) = parser.parse_args()
if args:
    print "Incorrect usage, %s -h for help." % sys.argv[0]
    sys.exit(-1)

if type(options.__dict__["if"])==str:
    fd_i = open(options.__dict__["if"],"r")
else:
    fd_i = options.__dict__["if"]

if type(options.of)==str:
    fd_o = open(options.of,"w")
else:
    fd_o = options.of

fd_i.seek(int(options.skip))
length = int(options.length)

while length>0:
    read_length = length
    if length>options.blocksize:
        read_length =options.blocksize
    
    fd_o.write(fd_i.read(read_length))
    length-=read_length
