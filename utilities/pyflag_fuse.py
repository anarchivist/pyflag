""" This script implements a fuse filesystem for access to the pyflag virtual filesystem.

Fuse (http://fuse.sourceforge.net/) is a system for implementing filesystems in userspace. The advantage of Fuse over kernel level filesystem drivers is that due to it being implemented in userspace, the filesystem can be quite complex.

This implementation allows access to the pyflag VFS using fuse. After mounting the filesystem it is possible to use arbitrary software directly on the VFS files, even if the files are completely virtual.

Installation:
---------------
To install fuse you can either download the source from the fuse web site or:

apt-get install fuse-utils fuse-source python-fuse

cd /usr/src/
tar xvzf fuse.tar.gz
cd modules/fuse/
./configure && make && make install

Mounting the fuse filesystem:
----------------------------------
To mount the filesystem (from within the pyflag main directory):

fusermount /mnt/point/ ./launch.sh utilities/pyflag_fuse.py -case demo -filesystem fs

Now you can just use the VFS within /mnt/point.

to unmount:
fusemount -u /mnt/point

Note that you do not need to be root as long as fusemount is suid root.
"""
from fuse import Fuse        
import pyflag.DB as DB
import pyflag.IO as IO
import pyflag.FileSystem as FileSystem
import pyflag.Registry as Registry

Registry.Init()

import os,sys
from errno import *
from stat import *

import thread

class Xmp(Fuse):
    def __init__(self, *args, **kw):    
        Fuse.__init__(self, *args, **kw)
        self.case=kw['case']
        io=IO.open(self.case,kw['filesystem'])
        self.fs=Registry.FILESYSTEMS.fs['DBFS'](self.case,kw['filesystem'],io)
        
    def mythread(self):
    
        """
        The beauty of the FUSE python implementation is that with the python interp
        running in foreground, you can have threads
        """    
        print "mythread: started"
    flags = 1
    
    def getattr(self, path):
        if path=='/': return (0,0,0,0,0,0,0,0,0,0)

        result = self.fs.istat(path=path)

        if not result: raise IOError("Unable to stat file %s" % path)
        ## The mode is actually stored as octal
        if self.fs.isdir(path): result['mode']="40"+("%s" % result['mode'])[-3:]
        mode = int("%s"%result['mode'],8)
        result = ( mode,1,0,result['links'],result['uid'],result['gid'],result['size'],result['atime_epoch'],result['mtime_epoch'],result['ctime_epoch'])
        return result

    def readlink(self, path):
        raise IOError("No symbolic links supported on forensic filesystem at %s" % path)

    def getdir(self, path):
        if not path.endswith('/'): path=path+'/'
        result = [ (x,0) for x in self.fs.ls(path=path) ]
        return result

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
        self.fs.open(path=path)
        return 0
    
    def read(self, path, len, offset):
    	f = self.fs.open(path=path)
    	f.seek(offset)
    	return f.read(len)
    
    def write(self, path, buf, off):
        raise IOError("Unable to write to forensic filesystem on %s" % path)
    
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
    import optparse
    parser = optparse.OptionParser(usage = "Fuse filesystem providing access to the pyflag VFS.\n Usage: fusermount /mnt/point/ ./launch.sh utilities/pyflag_fuse.py --case demo --filesystem fs\n", version="%prog version 0.1")
    parser.add_option("-c","--case",default=None,help="Case to open")
    parser.add_option("-f","--filesystem",default=None,help="Filesystem to open (must be already loaded)")
    (options, args) = parser.parse_args()
    if not options.case or not options.filesystem:
        print "You must specify both case and filesystem. Try -h for help."
        sys.exit(-1)
    else:
        server = Xmp(case=options.case,filesystem=options.filesystem)
        server.flags = 0
        server.multithreaded = 1;
        server.main()
