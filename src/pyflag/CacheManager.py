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
import cStringIO, os, os.path
import pyflag.DB as DB

config.add_option("CACHE_FILENAME", default="__cache__.bin",
                  help = 'Name of consolidated cache file')

def make_cache_filename(case, name):
    cache_path = os.path.join(config.RESULTDIR,"case_%s" % case,
                              name)
    return cache_path


def check_table(case):
    dbh = DB.DBO(case)
    dbh.execute("""create table if not exists cachefile (
    inode_id int not null default 0,
    filename VARCHAR(2000),
    offset bigint,
    length bigint,
    key (`inode_id`))""")


class CacheFile:
    def __init__(self, case, filename=None, inode_id=None):
        dbh = DB.DBO(case)
        try:
            if inode_id:
                dbh.execute("select * from cachefile where inode_id=%r", inode_id)
            else:
                dbh.check_index('cachefile','filename',100)
                dbh.execute("select * from cachefile where filename=%r", filename)

            row = dbh.fetch()
        except DB.DBError:
            check_table(case)
            row = None
            
        self.offset = 0
        if row:
            self.cache_offset = row['offset']
            self.size = row['length']
            cache_path = make_cache_filename(case, config.CACHE_FILENAME)

            self.fd = open(cache_path,"rb")
            self.fd.seek(self.cache_offset)
        else:
            self.cache_offset = 0
            cache_path = make_cache_filename(case, filename)

            self.fd = open(cache_path,'rb')
            self.fd.seek(0,2)
            self.size = self.fd.tell()
            self.fd.seek(0,0)
            self.name = cache_path

    def tell(self):
        return self.offset

    def read(self, length=None):
        if length==None:
            length = 1e9
            
        to_read = min(self.size - self.offset, length)
        data = self.fd.read(to_read)
        self.offset += len(data)
        return data

    def seek(self, offset, whence=0):
        if whence==0:
            self.offset = offset
        elif whence==1:
            self.offset += offset
        elif whence==2:
            self.offset = self.size + offset

        if self.offset>self.size:
            self.offset = self.size

        if self.offset<0:
            self.offset=0

        self.fd.seek(self.offset + self.cache_offset)

    def close(self):
        self.fd.close()

class TemporaryCacheFile:
    def __init__(self, case, filename, inode_id=None, mode='wb'):
        cache_filename = make_cache_filename(case, filename)
        self.fd = open(cache_filename, mode)
        self.filename = filename
        self.name = cache_filename
        self.inode_id = inode_id
        self.closed = False
        self.case = case
        
    def write(self, data):
        return self.fd.write(data)

    def seek(self, len, whence=None):
        if whence==None:
            return self.fd.seek(len)
        return self.fd.seek(len, whence)

    def tell(self):
        return self.fd.tell()

    def __del__(self):
        if not self.closed:
            self.close()

    def close(self):
        """ When we close the file we copy it into the big cache file """
        ## Do not merge large files into the cache (its not efficient anyway)
        if self.fd.tell() > 10e6:
            self.fd.close()
            self.closed=True
            return
        
        dbh = DB.DBO(self.case)
        try:
            dbh.execute("lock table cachefile write")
        except DB.DBError:
            check_table(self.case)
            dbh.execute("lock table cachefile write")

        name = self.fd.name
        self.fd.close()
        fd = open(name, "rb")

        cache_path = make_cache_filename(self.case, config.CACHE_FILENAME)
        
        outfd = open(cache_path,"ab")
        outfd.seek(0,2)
        
        ## Get the offset at the end
        offset = outfd.tell()
        length = 0
        
        while 1:
            data = fd.read(1024*1024)
            if len(data)==0:
                break

            outfd.write(data)
            length += len(data)

        outfd.close()
        args = dict(offset = offset, length = length,
                    filename = os.path.basename(self.filename),)
        
        if self.inode_id:
            args['inode_id'] = self.inode_id

        dbh.insert('cachefile',**args)
        dbh.execute("unlock tables")
        
        ## Remove the file
        os.unlink(name)
        self.closed = True

class CachedWriter:
    """ A class which caches data in memory and then flushes to disk
    when ready. This does not tie up file descriptors.

    FIXME: Stream reassembly typically uses lots of very small files -
    this is inefficient in terms of storage and access speed. The
    CachedWriter may be used to implement a kind of compound file.
    """
    def __init__(self, case, filename, inode_id=None):
        self.filename = make_cache_filename(case, filename)
        self.fd = cStringIO.StringIO()
        self.offset = 0
        self.case = case
        self.inode_id = inode_id

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

        ## Make sure that we copy the file to the main cache file:
        fd = TemporaryCacheFile(self.case,
                                self.filename, inode_id = self.inode_id,
                                mode="ab")
        fd.close()
            
    def __del__(self):
        self.close()

class DirectoryCacheManager:
    """ This is a basic cache manager.
    """
    def get_temp_path(self, case, inode):
        for c in "/|:":
            inode = inode.replace(c,'_')

        return inode
        return os.path.join(config.RESULTDIR,"case_%s" % case,inode)

    def get_temp_path_old(self, case, inode):
        """ Backwards compatibility with the old notation """
        inode = inode.replace("/",'-')

        return inode
        return os.path.join(config.RESULTDIR,"case_%s" % case,inode)

    def create_cache_fd(self, case, inode, inode_id = None):
        """ Return an fd with a write method for a new cache object """
        return CachedWriter(case, self.get_temp_path(case, inode), inode_id)

    def create_cache_seakable_fd(self, case, inode, inode_id=None):
        """ Return an fd with a write method for a new cache object """
        return TemporaryCacheFile(case, make_cache_filename(case,
                          self.get_temp_path(case, inode)), inode_id)
        #return open(self.get_temp_path(case, inode),'wb')

    def create_cache_from_data(self, case, inode, data, inode_id=None):
        """ Create a new cache entry from data. Data is expected to be
        in binary (not unicode)
        """
        out_fd = TemporaryCacheFile(case, make_cache_filename(
            case,
            self.get_temp_path(case, inode)),
                                    inode_id=inode_id)
        out_fd.write(data)
        out_fd.close()
        
        return len(data)

    def create_cache_from_file(self, case, inode, filename, inode_id=None):
        """ Given a file on disk we add it into the cache by moving it
        in (The original file will be unlinked).

        This is efficient because files will only be merged into the
        cache if they are small otherwise will be named appropriately.
        """
        sane_filename = self.get_temp_path(case,inode)
        
        cached_filename = make_cache_filename(case, sane_filename)
        if filename != cached_filename:
            os.rename(filename, cached_filename)

        fd = TemporaryCacheFile(case, sane_filename, mode='rb')
        ## Move it into the cache if needed
        fd.close()
        
    def create_cache_from_fd(self, case, inode, fd, inode_id=None):
        """ Creates a new cache object for inode by repeadadely
        reading fd."""

        out_fd = TemporaryCacheFile(case,
                                    make_cache_filename(
            case,
            self.get_temp_path(case, inode)),
                                    inode_id=inode_id)
        size = 0
        
        ## Copy fd into the file
        while 1:
            data=fd.read(10000000)
            if not data or len(data)==0: break
            out_fd.write(data)
            size+=len(data)

        out_fd.close()
        
        return size

    def provide_cache_filename(self, case, inode, inode_id = None):
        """ This function creates a separate file in the cache
        directory by copying the file out of the consolidated
        cache. This is used when we want to shell out to other
        programs which require the file to be opened. This should not
        happen too much as most helpers should be using python file
        like objects.
        """
        filename = make_cache_filename(
            case,
            self.get_temp_path(case, inode))

        outfd = open(filename,"wb")
        import pyflag.FileSystem as FileSystem

        fsfd = FileSystem.DBFS(case)

        infd = fsfd.open(inode=inode, inode_id=inode_id)
        while 1:
            data = infd.read(1e6)
            if len(data)==0: break

            outfd.write(data)

        outfd.close()
        
        return filename

    def open(self, case, inode, inode_id = None):
        filename = self.get_temp_path(case, inode)
        try:
            return CacheFile(case, filename, inode_id)
        except IOError:
            new_filename = self.get_temp_path_old(case,inode)
            return CacheFile(case, new_filename, inode_id)


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
