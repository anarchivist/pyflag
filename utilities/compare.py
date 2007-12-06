#!/usr/bin/python
""" Compare a number of disks side by side """
import sys
from optparse import OptionParser

parser = OptionParser()

parser.add_option("-b", "--blocksize", default='0',
                  help="Blocksize to use - if set only shows 5 lines on each side of block boundary")
parser.add_option('-c','--context',default=5,
                  help="Lines of context to show before/after block boundary")

parser.add_option('-w','--width',default=16,
                  help="Width of each column")
parser.add_option("-s","--skip",
                  default='0',
                  help="skip this many bytes from the start of each file")

parser.add_option("-S", "--subsys",
                  default=None,
                  help="Subsystem to use (e.g. EWF)")

(options, args) = parser.parse_args()

if len(args)<2: 
    print "You must specify more than two disks to compare. Try -h for help"
    sys.exit(0)

blocksize=0
width=int(options.width)

def parse_offsets(arg):
    if arg.startswith('0x'): base=16
    else: base=10
    
    suffixes = {'k':1024,
                'K':1024,
                'm':1024*1024,
                'M':1024*1024,
                'G':1024*1024*1024,
                's':512,
                }
                
    try:
        suffix=arg[-1]
        if suffix=='b': suffixes['b']=parse_offsets(options.blocksize)

        return int(arg[:-1],base)*suffixes[suffix]
    except (KeyError,ValueError,TypeError):
        return int(arg,base)

class ParityDisk:
    """ A file like object to simulate a disk which is missing by
    calculating parity from several other disks.
    """
    def __init__(self, fds):
        self.fds = fds
        
    def seek(self, offset):
        for fd in self.fds:
            fd.seek(offset)

    def read(self, length):
        data = '\x00' * length
        for fd in self.fds:
            new_data = fd.read(length)
            data = ''.join([ chr(ord(data[x]) ^ ord(new_data[x]))
                             for x in range(length) ])

        return data

def open_image(filename):
    if not options.subsys:
        io=open(filename, 'r')

    else:
        import Registry, FlagFramework, IO
        Registry.Init()
        
        driver = Registry.IMAGES.dispatch(options.subsys)()
        q = FlagFramework.query_type(filename = filename)
        io = driver.open(None, None, q)

    return io

fds=[]
for arg in args:
    if arg != "None":
        fds.append(open_image(arg))
    else:
        fds.append(ParityDisk([open_image(arg) for arg in args if arg != 'None']))

count=parse_offsets(options.skip)
blocksize = parse_offsets(options.blocksize)
context=int(options.context)

def print_context_lines(fds):
    global count
    for line_number in range(0,context):
        str = "%012s "% hex(count)
        for fd in fds:
            data=fd.read(width)
            for char in data:
                if not (ord(char)>32 and ord(char)<127): char='.'
                str+=char

            str+=' '
        print "%s" % str
        count+=width
    
current_block=0
while 1:
    print_context_lines(fds)
    if blocksize>width*context:
        print ''
        print ' '*13+" ".join([ "." * width for i in fds ])
        print ''
        count+=blocksize - 2*width * context
        current_block +=1
        for fd in fds: fd.seek(count)

    print_context_lines(fds)
    if blocksize>width*context:
        print ''
        print ' '*13+" ".join([ ("*"*(width/2-2) + " %02s "+"*"*(width/2-2)) % i for i in range(len(fds)) ])
        print 'Block %s: ' % current_block
