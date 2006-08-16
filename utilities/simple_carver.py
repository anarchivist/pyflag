## This is a simple start re, end re carver:
import pyflag.Exgrep as Exgrep
from optparse import OptionParser
import sys

parser = OptionParser()
parser.add_option("-o", "--output", dest='output', default='/tmp/',
                  help="Location of output directory")

parser.add_option("-l", "--length", dest='length', default=None,
                  help="Length of data to extract. This will set the maximum length for all files.")

parser.add_option("-t", "--types", dest='types', default=None,
                  help="File types to extract. ? lists all types supported")

(options, args) = parser.parse_args()

if options.types=="?":
    print "File types supported:"
    for t in Exgrep.definitions:
        print "%s: Start RE: '%s', Length: %s" % (t['Extension'], t['StartRE'], t['MaxLength'])

    sys.exit(0)

if options.types:
    extensions = options.types.split(',')
    Exgrep.definitions = [ x for x in Exgrep.definitions if x['Extension'] in extensions ]

    print "Setting types to:"
    for t in Exgrep.definitions:
        print "%s"% t['Extension'],
        
    print ''
    

if options.length:
    maxlength = int(options.length)
    for t in Exgrep.definitions:
        if t['MaxLength'] > maxlength: t['MaxLength']=maxlength

if not args:
    print "You need to specify some files to carve"
    
for f in args:
    fd=open(f,'r')
    fd3=open(f,'r')

    print "Carving file %s into directory %s" % (f, options.output)

    for m in Exgrep.process('',fd):
        fd2 = open("%s/%s.%s" % (options.output, m['offset'], m['type']), 'w')
        fd3.seek(m['offset'])
        fd2.write(fd3.read(m['length']))
        fd2.close()

