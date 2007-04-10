""" This module defines all the standard Image drivers within PyFlag """

import pyflag.IO as IO
import pyflag.DB as DB
from FlagFramework import query_type
import sk,re

class Standard(IO.Image):
    """ A simple access source for raw dd images. """
    order = 10
    mandatory_parameters = ['filename',]
    
    def form(self, query, result):
        result.fileselector("Select %s image:" % self.__class__.__name__.split(".")[-1], name="filename")

    def create(self, name, case, query):
        """ Given an iosource name, returns a file like object which represents it.

        name can be None, in which case this is an anonymous source (not cached).
        """
        return open(query['filename'])
    
    def open(self, name, case, query=None):
        """ Dont bother to even cache this - its so simple """
        dbh = DB.DBO(case)
        if query:
            ## Check that all our mandatory parameters have been provided:
            for p in self.mandatory_parameters:
                if not query.has_key(p):
                    raise IOError("Mandatory parameter %s not provided" % p)

            ## Check that the name does not already exist:
            dbh.execute("select * from iosources where name = %r" , name)
            if dbh.fetch():
                raise IOError("An iosource of name %s already exists in this case" % name)

            ## Try to make it
            fd = self.create(name, case, query)

            ## If we get here we made it successfully so store in db:
            dbh.insert('iosources',
                       name = query['iosource'],
                       parameters = "%s" % query,
                       _fast = True)
            
            return fd
        else:
            dbh.execute("select parameters from iosources where name = %r" , name)
            row = dbh.fetch()
            fd = self.create(name, case, query_type(string=row['parameters']))
            return fd

class IOSubsysFD:
    def __init__(self, io):
        self.io = io
        self.readptr = 0
        ## FIXME - dont lie here
        try:
            self.size = io.size
        except: self.size = 10000000000000
        
    def seek(self, offset, whence=0):
        """ fake seeking routine """
        if whence==0:
            readptr = offset
        elif whence==1:
            readptr+=offset
        elif whence==2:
            readptr = self.size

        if readptr<0:
            raise IOError("Seek before start of file")

        self.readptr = readptr

    def tell(self):
        """ return current read pointer """
        return self.readptr

    def read(self, length=0):
        """ read length bytes from subsystem starting at readptr """            
        buf = self.io.read_random(length,self.readptr)
        self.readptr += len(buf)
        return buf

    def close(self):
        """ close subsystem """
        pass

class Advanced(Standard):
    """ This is a IO source which provides access to raw DD images
    with offsets.
    """
    order = 20
    subsys = "advanced"
    def calculate_partition_offset(self, query, result, offset = 'offset'):
        """ A GUI function to allow the user to derive the offset by calling mmls """
        def mmls_popup(query,result):
            result.decoration = "naked"

            try:
                del query[offset]
            except: pass
    
            ## Try creating the io source
            io = self.create(None, query['case'], query)
            try:
                parts = sk.mmls(io)
            except IOError, e:
                result.heading("No Partitions found")
                result.text("Sleuthkit returned: %s" % e)
                return

            result.heading("Possible IO Sources")
            result.start_table(border=True)
            result.row("Chunk", "Start", "End", "Size", "Description")
            del query[offset]
            for i in range(len(parts)):
                new_query = query.clone()
                tmp = result.__class__(result)
                new_query[offset] = "%ds" % parts[i][0]
                tmp.link("%010d" % parts[i][0], new_query, pane='parent')
                result.row(i, tmp, "%010d" % (parts[i][0] + parts[i][1]), "%010d" % parts[i][1] , parts[i][2])
                result.end_table()
        
        tmp = result.__class__(result)
        tmp2 = result.__class__(result)
        tmp2.popup(mmls_popup,
                   "Survey the partition table",
                   icon="examine.png")

        tmp.row(tmp2,"Enter partition offset:")
        result.textfield(tmp,offset)

    def calculate_offset_suffix(self, offset):
        m=re.match("(\d+)([sSkKgGmM]?)", offset)
        if not m:
            raise IOError("I cant understand offset should be an int followed by s,k,m,g")

        suffix=m.group(2).lower()
        multiplier = 1

        if not suffix: multiplier=1
        elif suffix=='k':
            multiplier = 1024
        elif suffix=='m':
            multiplier=1024*1024
        elif suffix=='g':
            multiplier = 1024**3
        elif suffix=='s':
            multiplier = 512

        return int(m.group(1))* multiplier

    def form(self, query, result):
        Standard.form(self, query, result)
        self.calculate_partition_offset(query, result)

    def make_iosource_args(self, query):
        offset = self.calculate_offset_suffix(query.get('offset','0'))
        
        args = [['subsys', self.subsys],
                ['offset', offset]]
        
        for f in query.getarray('filename'):
            args.append(['filename', f])

        return args

    def create(self, name, case, query):
        """ Given an iosource name, returns a file like object which represents it.

        name can be None, in which case this is an anonymous source (not cached).
        """
        key = "%s|%s" % (case, name)
        try:
            io = IO.IO_Cache.get(key)
        except KeyError: 
            import iosubsys

            args = self.make_iosource_args(query)
            io = iosubsys.iosource(args)

            ## Store the cache copy in:
            if name:
                IO.IO_Cache.put(io, key=key)
            
        return IOSubsysFD(io)

class SGZip(Advanced):
    """ Sgzip is pyflags native image file format """
    subsys = 'sgzip'

class EWF(Advanced):
    """ EWF is used by other forensic packages like Encase or FTK """
    subsys = 'ewf'

import Store

class CachedIO(IOSubsysFD):
    """ This is a cached version of the IOSubsysFD for filesystems for
    which reading is expensive.

    This is used for example by the remote filesystem. Typically when
    reading a filesystem, the same blocks need to be read over and
    over - for example reading the superblock list etc. This helps to
    alleviate this problem by caching commonly read blocks.
    """
    cache = Store.Store()
    def __init__(self,io):
        IOSubsysFD.__init__(self,io)

    def read(self, length=0):
        ## try to get the data out of the cache:
        key = "%s%s" % (self.readptr,length)
        try:
            data = self.cache.get(key)
        except Exception,e:
            data = self.io.read_random(length,self.readptr)
            self.cache.put(data, key=key)

        self.readptr += len(data)
        return data

class Remote(Advanced):
    """ This IO Source provides for remote access """
    mandatory_parameters = ['host','device']
    def form(self, query, result):
        ## Fill the query with some defaults:
        query.default('port','3533')
        
        result.textfield("Host",'host')
        result.textfield("Port",'port')
        result.textfield("Raw Device",'device')
        
        query['host']
        
        self.calculate_partition_offset(query, result)

    def create(self, name, case, query):
        key = "%s|%s" % (case, name)
        try:
            io = IO.IO_Cache.get(key)
        except KeyError:
            import remote
            offset = self.calculate_offset_suffix(query.get('offset','0'))

            io = remote.remote(host = query['host'],
                               port = int(query.get('port', 3533)),
                               device = query['device'],
                               offset = offset)

            ## Store the cache copy in:
            if name:
                IO.IO_Cache.put(io, key=key)
            
        return CachedIO(io)

class Mounted(Advanced):
    """ Treat a mounted directory as an image """
    subsys = 'sgzip'
