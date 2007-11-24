import re,sys
import optparse

def pretty_print(raid_map):
    print raid_map
    print "----------------------"
    for x in range(options.period):
        for y in range(options.number):
            try:
                print raid_map[(x,y)],
            except:
                print "None",

        print "."
    print "----------------------"
    
def calculate_map(raid_map):
    new_map = [ [None] * options.number for x in range(options.period) ]
    from_block = 2
    from_disk = 0
    count = 0
    while None == new_map[from_block][from_disk]:
        new_map[from_block][from_disk] = count

        try:
            to_block, to_disk = raid_map[(from_block, from_disk)]
            #print "%s,%s %s,%s" % (from_block, from_disk, to_block, to_disk)
        except KeyError,e:
            print e
            print "Map not complete - match some more entries"
            return

        count += 1

        from_block = to_block
        from_disk = to_disk

    print new_map
    return new_map

def open_image(filename):
    print "Opening image %s" % filename
    if not options.subsys:
        io=open(filename, 'r')

    else:
        import Registry, FlagFramework, IO
        Registry.Init()
        
        driver = Registry.IMAGES.dispatch(options.subsys)()
        q = FlagFramework.query_type(filename = filename)
        io = driver.open(None, None, q)

    return io

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

class RaidReassembler:
    """ A file like object which takes care of reassembling the raid
    based on a raid map
    """
    def __init__(self, raid_map, disk_fds, block_size, offset=0, skip=0):
        self.disk_fds = disk_fds
        self.offset = offset
        self.skip = skip
        self.block_size = block_size
        ## Build the raid map:
        self.map = []
        self.max_block = 0
        from_block = 0
        from_disk = 1
        while 1:
            self.map.append((from_block, disk_fds[from_disk], from_disk))
            try:
                to_block, to_disk = raid_map[(from_block, from_disk)]
            except KeyError:
                raise RuntimeError("Map not complete - match some more entries")

            if self.max_block<from_block: self.max_block=from_block

            if to_block==0 and to_disk==1:
                break

            from_block = to_block
            from_disk = to_disk

        self.period_length = len(self.map) * self.block_size
        self.seek(self.offset)
        self.max_block += 1
        print self.map
        
    def seek(self, offset, whence=0):
        if whence==0:
            self.offset = offset
        elif whence==1:
            self.offset += offset

        ## Now do the actual seeking
        ## The offset of the specific period
        period = (self.offset+1) / self.period_length

        ## The block within this period
        residual_block = (self.offset % self.period_length) / self.block_size

        ## The offset within that block
        sub_block_residual = (self.offset % self.period_length) % self.block_size

        self.current_block, self.current_fd, number = self.map[residual_block]
#        print "%s %s %s" % (period, self.current_block, self.max_block)

        seek_offset = sub_block_residual + period * self.max_block * \
                      self.block_size + self.current_block * self.block_size
#        print "Seeking %r %s %s %s" % (self.current_fd, self.offset,
#                                       seek_offset,
#                                       sub_block_residual)
        
        self.current_fd.seek(seek_offset + self.skip)
        print "Seeking to image offset %s, block %s(%s), disk %s offset %s" % (self.offset, self.current_block, period, number, seek_offset + self.skip)
        self.sub_block_residual = sub_block_residual

    def read(self, length):
        data = ''
        while length > 0:
            sub_length = self.block_size - self.sub_block_residual
#            print "Reading %s "% sub_length
            data += self.current_fd.read(sub_length)
            self.offset += sub_length
            self.seek(self.offset)
            length -= sub_length

        return data

    def dump(self, outfd):
        count = 0
        for block, fd, number in self.map:
            fd.seek(0)

        while 1:
            for block,fd,number in self.map:
                offset = count * self.block_size * 3 * 2 + block * self.block_size
                print count, block, number, offset
                fd.seek( offset)
                data = fd.read(self.block_size)
                if len(data)==0: break
                
                outfd.write(data)
            count+=1
                
def load_map_file(filename):
    fd=open(filename)
    raid_map = {}
    for line in fd:
        if line.startswith('#'): continue

        m = re.match("(\d+),(\d+) +(\d+),(\d+)", line)
        if m:
            from_block = int(m.group(1)) % options.period
            from_disk = int(m.group(2))
            to_block = int(m.group(3)) % options.period
            to_disk = int(m.group(4))

            try:
                tmp = raid_map[(from_block,from_disk)]
                if tmp != (to_block, to_disk):
                    print "Error - clash in line %s" % line
            except:
                pass

            raid_map[(from_block,from_disk)] = (to_block, to_disk)

    return raid_map

if __name__ == '__main__':
    parser = optparse.OptionParser()

    parser.add_option('-p','--period',default=6, type='int',
                      help = "periodicity of the map")

    parser.add_option('-m','--map',default=None,
                      help = "The Map file itself")

    parser.add_option('-s','--skip',default='0',
                      help = "length of data to skip in each disk")

    parser.add_option('-n','--number',default=6, type='int',
                      help = "Number of disks")

    parser.add_option('-b','--blocksize',default="512", 
                      help = "block size")

    parser.add_option('-P','--print_map',default=False, action='store_true', 
                      help = "print the map")

    parser.add_option('-o','--output', default="output.dd",
                      help = "Name of the output file")

    parser.add_option("-S", "--subsys",
                      default=None,
                      help="Subsystem to use (e.g. EWF)")
    
    (options, args) = parser.parse_args()

    raid_map = load_map_file(options.map)
    if options.print_map:
        pretty_print(raid_map)
        print calculate_map(raid_map)
        sys.exit(0)
        

    blocksize = parse_offsets(options.blocksize)

    fds=[]
    for arg in args:
        if arg != "None":
            fds.append(open_image(arg))
        else:
            fds.append(ParityDisk([open_image(arg) for arg in args if arg != 'None']))

    fd = RaidReassembler(raid_map, fds, blocksize)
    # fd.read(parse_offsets(options.skip))
    print "Creating output file"
    outfd = open(options.output,"w")
    fd.dump(outfd)
#    while 1:
#        outfd.write(fd.read(1024*1024))
