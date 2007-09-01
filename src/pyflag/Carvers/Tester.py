#!/usr/bin/python
""" This module implements a unit test generator for the carvers
implemented within PyFlag.

There is an interface for creating test cases based on mapping
functions.
"""
import Carver,os,sys
import pyflag.conf
config=pyflag.conf.ConfObject()

SECTOR_SIZE = 512

class ReverseMapper(Carver.Reassembler):
    """ This class implements methods for creating an image file based
    on the mapping function.

    This object must be constructed with an open file handle for the
    file to be mixed up.
    """
    def dump(self, fd):
        """ This dumps the mapping function into the fd """
        self.fd.seek(0, 2)
        length = self.fd.tell()
        
        ## First find the maximum size of the image:
        max_point = 0
        max_size = 0
        for p in self.points:
            if self.mapping[p] > max_point:
                max_point = self.mapping[p]
                max_size = max_point + length - p

        ## Initalise the output file with random data:
        random_fd = open("/dev/urandom")
        fd.seek(0)
        while fd.tell() < max_size:
            fd.write(random_fd.read(SECTOR_SIZE))

        ## Now go through all the fragments and write them onto the
        ## output file:
        x = 0
        while x<length:
            self.fd.seek(x)
            y, valid_length = self.interpolate(x)
            print "Reading (%s,%s) from target, writing onto offset %s in image" % (x, valid_length, y)
            data = self.fd.read(valid_length)
            fd.seek(y)
            fd.write(data)
            x += valid_length

if __name__ =="__main__":
    config.set_usage(usage = """%prog -w Output -m map_file.map Input_file

    Create a fragmented output file based on input file and the specified map file.
    This is used to generate test cases for the Carver.
    """)

    config.add_option("write", short_option='w',
                      help = "File to write output on")

    config.add_option("map", short_option='m',
                      help = "map file to use")

    config.add_option("plot", short_option='p', default=False, action="store_true",
                      help = "If specified we just plot the map file using gnuplot")

    config.parse_options(True)

    if config.plot:
        r = ReverseMapper(None)
        r.load_map(config.map)
        r.plot(os.path.basename(config.map))
        import time
        time.sleep(100)
        sys.exit(0)

    if len(config.args)!=1:
        print "Must specify exactly one input file"
        sys.exit(-1)

    r = ReverseMapper(open(config.args[0]))
    r.load_map(config.map)
    r.dump(open(config.write,'w'))
