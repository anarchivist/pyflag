""" This is a fuse driver that makes an IO subsystem mountable through the standard linux loopback driver. This allows users to mount say an encase image directly through the loopback driver.

See pyflag_fuse.py for more details about fuse, and how to install it.

This program should be invoked as root to mount the fuse filesystem. This is because once the filesystem is mounted, a virtual image file appears within it. This virtual image can be mounted using the standard linux loopback device::

~/pyflag# fusemount /mnt/point/ ./launch utilities/fuse_loopback_subsystem.py -i subsystem [options]

Where subsystem is a subsystem name, and options are specific to the subsystem.
Now you can mount the virtual image using the standard loopback device:

~/pyflag# mount -oloop /mnt/point/mountme /mnt/
"""
from fuse import Fuse        
import pyflag.IO as IO
import pyflag.FlagFramework as FlagFramework

import os,sys
from errno import *
from stat import *

import thread

class Xmp(Fuse):
    def __init__(self,io=None ):    
        Fuse.__init__(self)
        self.io=io
        
    def mythread(self):    
        """
        The beauty of the FUSE python implementation is that with the python interp
        running in foreground, you can have threads
        """    
        print "mythread: started"
    flags = 1
    
    def getattr(self, path):
        if path.endswith('/'):
            return (16877, 1L, 0L, 3L, 0, 0, 8192L, 0, 0, 0)
        else:
            return (33188, 1, 0, 1L, 0L, 0L, 100*1024*1024*1024L, 0L, 0L, 0L)

    def readlink(self, path):
        raise IOError("No symbolic links supported on forensic filesystem at %s" % path)

    def getdir(self, path):
        return [('mountme',0)]

    def unlink(self, path):
        raise IOError("Unable to modify Virtual Filesystem")

    def rmdir(self, path):
        raise IOError("Unable to modify Virtual Filesystem")

    def symlink(self, path, path1):
        raise IOError("Unable to modify Virtual Filesystem")

    def rename(self, path, path1):
        raise IOError("Unable to modify Virtual Filesystem")

    def link(self, path, path1):
        raise IOError("Unable to modify Virtual Filesystem")

    def chmod(self, path, mode):
        raise IOError("Unable to modify Virtual Filesystem")

    def chown(self, path, user, group):
        raise IOError("Unable to modify Virtual Filesystem")

    def truncate(self, path, size):
        raise IOError("Unable to modify Virtual Filesystem")
    
    def mknod(self, path, mode, dev):
        raise IOError("Unable to modify Virtual Filesystem")
    
    def mkdir(self, path, mode):
        raise IOError("Unable to modify Virtual Filesystem")

    def utime(self, path, times):
        raise IOError("Unable to modify Virtual Filesystem")

    def open(self, path, flags):
        """ For now we only support a single image in the same filesystem, so any open will simply open this one image """
        ## Image is already open
        return 0
    
    def read(self, path, length, offset):
        self.io.seek(offset)
        return self.io.read(length)
    
    def write(self, path, buf, off):
        ## We do not modify the data, but we need to pretend that we
        ## are so callers dont panic - this is handy when mounting
        ## ext3 filesystems over loopback, where the kernel really
        ## wants to update the journal and would freak if it can't.
        return len(buf)
    
    def release(self, path, flags):
        return 0

    def statfs(self):
        """
        Should return a tuple with the following 6 elements:
            - blocksize - size of file blocks, in bytes
            - totalblocks - total number of blocks in the filesystem
            - freeblocks - number of free blocks
            - totalfiles - total number of file inodes
            - freefiles - nunber of free file inodes
    
        Feel free to set any of the above values to 0, which tells
        the kernel that the info is not available.
        """
        blocks_size = 1024
        blocks = 100000
        blocks_free = 25000
        files = 100000
        files_free = 60000
        namelen = 80
        return (blocks_size, blocks, blocks_free, files, files_free, namelen)

    def fsync(self, path, isfsyncfile):
        return 0
    
if __name__ == '__main__':
    ## This command line parser is fairly complex since it can cater
    ## for multiple args per option. This is needed to suppost
    ## subsystems with multiple files, so we can do -filename Case.E0* and
    ## have the shell glob all the files as different filename options.
    query=FlagFramework.query_type(())
    args=sys.argv[1:]
    iter = args.__iter__()
    arg=iter.next()

    try:
        while 1:
            if arg=='-i' or arg=='--subsystem':
                query['subsys']=iter.next()
            elif arg.startswith('-'):
                try:
                    while 1:
                        opt=iter.next()
                        if opt.startswith('-'):
                            arg=opt
                            continue
                        query["io_%s" % arg[1:]]=opt
                except StopIteration:
                    break
                
            arg=iter.next()
                
    except StopIteration:
        pass

    ## We try to instantiate the IO object:
    io=IO.IOFactory(query)

    #Now we create a fuse object with that IO subsystem:
    server = Xmp(io=io)
    server.flags = 0
    server.multithreaded = 1;
    server.main()

