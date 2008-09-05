""" This module implements a Cache Manager.

A Cache manager is a coordinated way of gaining access to the object
cache on disk. PyFlag keeps many objects cached on disk for fast
access. The cache manager manages the specific organization of cache
objects, and provides a unified API for accessing and creating these
objects.

Design documentation for Cache managers
---------------------------------------

The Cache manager is a singleton object within the process (i.e. all
threads use the same manager). The currently active manager is
instantiated in the module variable MANAGER.

The manager needs to handle synchronous access from multiple threads
within this process, as well as multiple processes, and even processes
on multiple machines. This is because many workers can have access to
the same cache and workers can be distributed in a very flexible
way. This implies that its not enough to use thread locks, or even
filesystem locks (unless the filesystem locks are shared across the
network properly say over SMB). Database locks are probably the best
method of synchronization.

"""
import pyflag.conf
config=pyflag.conf.ConfObject()
import cStringIO, os

class CachedWriter:
    """ A class which caches data in memory and then flushes to disk
    when ready. This does not tie up file descriptors.

    FIXME: Stream reassembly typically uses lots of very small files -
    this is inefficient in terms of storage and access speed. The
    CachedWriter may be used to implement a kind of compound file.
    """
    def __init__(self, filename):
        self.filename = filename
        self.fd = cStringIO.StringIO()
        self.offset = 0

    def write_to_file(self):
        ## Only write if we have data - so 0 length files will never
        ## be written.
        data = self.fd.getvalue()
        if len(data)>0:
            fd = open(self.filename,"ab")
            fd.write(data)
            fd.close()
            self.fd.truncate(0)
        
    def write(self, data):
        self.fd.write(data)
        self.offset += len(data)
        
        if self.fd.tell() > 100000:
            self.write_to_file()
            
    def close(self):
        self.write_to_file()
            
    def __del__(self):
        self.close()

class DirectoryCacheManager:
    """ This is a basic cache manager.
    """
    def get_temp_path(self, case, inode):
        for c in "/|:":
            inode = inode.replace(c,'_')
            
        return os.path.join(config.RESULTDIR,"case_%s" % case,inode)

    def create_cache_fd(self, case, inode):
        """ Return an fd with a write method for a new cache object """
        return CachedWriter(self.get_temp_path(case, inode))

    def create_cache_seakable_fd(self, case, inode):
        """ Return an fd with a write method for a new cache object """
        return open(self.get_temp_path(case, inode),'wb')

    def create_cache_from_data(self, case, inode, data):
        """ Create a new cache entry from data. Data is expected to be
        in binary (not unicode)
        """
        out_fd = open(self.get_temp_path(case, inode), "wb")
        out_fd.write(data)
        out_fd.close()
        
        return len(data)

    def create_cache_from_fd(self, case, inode, fd):
        """ Creates a new cache object for inode by repeadadely
        reading fd."""

        out_fd = open(self.get_temp_path(case, inode), "wb")
        size = 0
        
        ## Copy fd into the file
        while 1:
            data=fd.read(10000000)
            if not data or len(data)==0: break
            out_fd.write(data)
            size+=len(data)

        out_fd.close()
        
        return size

    def open(self, case,inode):
        filename = self.get_temp_path(case, inode)
        return ProxyReader(filename)

class ProxyReader:
    def __init__(self, filename):
        self.fd = open(filename,"rb")
        self.name = filename
        
    def seek(self, x, whence=0):
        return self.fd.seek(x,whence)

    def read(self, len=None):
        if len==None:
            return self.fd.read()
        else:
            return self.fd.read(len)

    def tell(self):
        return self.fd.tell()
    
MANAGER = DirectoryCacheManager()
