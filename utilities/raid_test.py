# This is a good example of how the sk.c stuff can be integrated into
# the raid stuff to be able to verify the image without unpacking the
# whole thing.

import mapper
import optparse,sys
import sk

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

    raid_map = mapper.load_map_file(options.map, options.period)
    if options.print_map:
        mapper.pretty_print(raid_map, options.period, options.number)
        print mapper.calculate_map(raid_map, options.period, options.number)
        sys.exit(0)
        

    blocksize = mapper.parse_offsets(options.blocksize)

    fds=[]
    for arg in args:
        if arg != "None":
            fds.append(mapper.open_image(arg, options.subsys))
        else:
            fds.append(mapper.ParityDisk([mapper.open_image(arg) for arg in args if arg != 'None']))

    fd = mapper.RaidReassembler(raid_map, fds, blocksize, skip=mapper.parse_offsets(options.skip))
    skfs = sk.skfs(fd, imgoff = 128 * 1024 + 512 * 63)
    print skfs.listdir("/")
