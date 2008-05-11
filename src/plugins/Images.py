""" This module defines all the standard Image drivers within PyFlag """

import pyflag.IO as IO
import pyflag.DB as DB
from FlagFramework import query_type
import pyflag.FlagFramework as FlagFramework
import sk,re,os,os.path
import pyflag.conf
config=pyflag.conf.ConfObject()

class IOSubsysFD:
    def __init__(self, io, name):
        self.io = io
        self.readptr = 0
        self.name = name
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

filename_re = re.compile("(.+?)(\d+)$")

class Advanced(IO.Image):
    """ This is a IO source which provides access to raw DD images
    with offsets.
    """
    order = 20
    subsys = "advanced"
    io = None

    def calculate_partition_offset(self, query, result, offset = 'offset'):
        """ A GUI function to allow the user to derive the offset by calling mmls """
        def mmls_popup(query,result):
            result.decoration = "naked"

            try:
                del query[offset]
            except: pass

            new_query = query.clone()
            filenames = query.getarray('filename')
            new_query.clear('filename')
            for f in filenames:
                new_query['filename'] = os.path.normpath("%s/%s" % (config.UPLOADDIR, f))

            ## Try creating the io source
            io = self.open(None, query['case'], new_query)
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
                result.row(i, tmp, "%010d" % (parts[i][0] + parts[i][1]),
                           "%010d" % parts[i][1] , parts[i][2])
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
        result.fileselector("Select %s image:" % self.__class__.__name__.split(".")[-1], name="filename", vfs=False)
        self.calculate_partition_offset(query, result)

    def make_iosource_args(self, query):
        offset = self.calculate_offset_suffix(query.get('offset','0'))
        
        args = [['subsys', self.subsys],
                ['offset', offset]]

        ## If a single Ewf file is given we try to glob all the
        ## filenames:
        filenames = query.getarray('filename')

        for f in filenames:
            ## Is it a symlink? This allows us to symlink to a single
            ## file from a fileset using a simple name. This makes it
            ## nice to manage the upload directory because you can
            ## just put a single symlink (e.g. freds_disk.E01) to the
            ## entire evidence set (could be huge and mounted
            ## somewhere different then the upload directory, e.g. an
            ## external driver).
            try:
                link_f = os.readlink(f)
                if not link_f.startswith("/"):
                    f = os.path.join(os.path.dirname(f), link_f)
                else:
                    f = link_f
            except OSError:
                pass

            ## If the filename we were provided with, ends with a
            ## digit we assume that its part of an evidence set.
            m = filename_re.match(f)
            
            if m:
                globbed_filenames = []
                dirname , base = os.path.split(m.group(1))
                for new_f in os.listdir(dirname):
                    if new_f.startswith(base) and filename_re.match(new_f):
                        globbed_filenames.append(os.path.join(dirname, new_f))
    

                if not globbed_filenames:
                    raise IOError("Unable to find file %s" % f)

                ## This list must be sorted on the numeric extension
                ## (Even if its not 0 padded so an alphabetic sort
                ## works - I have seen some cases where the images
                ## were named image.1 image.10 image.100):
                def comp(x,y):
                    m1 = filename_re.match(x)
                    m2 = filename_re.match(y)
                    if not m1 or not m2: return 0
                    return int(m1.group(2)) - int(m2.group(2))

                globbed_filenames.sort(comp)
            else:
                globbed_filenames = [f]
                
            for f in globbed_filenames:
                args.append(['filename', f])

        return args

    def create(self, name, case, query):
        """ Given an iosource name, returns a file like object which represents it.

        name can be None, in which case this is an anonymous source (not cached).
        """
        import iosubsys        
        args = self.make_iosource_args(query)
        io = iosubsys.iosource(args)

        return io

    def open(self, name, case, query=None):
        """
        This function opens a new instance of a file like object using
        the underlying subsystem.

        When we first get instantiated, self.io is None. We check our
        parameters and then call create to obtain a new self.io. The
        IO subsystem then caches this object (refered to by case and
        name). Subsequent open calls will use the same object which
        will ideally use the same self.io to instantiate a new
        IOSubsysFD() for each open call.
        """
        self.cache_io(name, case, query)
        return IOSubsysFD(self.io, name)

    def cache_io(self, name, case, query=None):
        if not self.io:
            dbh = DB.DBO(case)

            ## This basically checks that the query is sane.
            if query:
                ## Check that all our mandatory parameters have been provided:
                for p in self.mandatory_parameters:
                    if not query.has_key(p):
                        raise IOError("Mandatory parameter %s not provided" % p)

                ## Check that the name does not already exist:
                if name:
                    dbh.execute("select * from iosources where name = %r" , name)
                    if dbh.fetch():
                        raise IOError("An iosource of name %s already exists in this case" % name)

                    ## Try to make it
                    self.io = self.create(name, case, query)

                    ## If we get here we made it successfully so store in db:
                    dbh.insert('iosources',
                               name = query['iosource'],
                               type = self.__class__.__name__,
                               parameters = "%s" % query,
                               _fast = True)
                else:
                    self.io = self.create(name, case, query)

            ## No query provided, we need to fetch it from the db:
            else:
                dbh.check_index('iosources','name')
                dbh.execute("select parameters from iosources where name = %r" , name)
                row = dbh.fetch()
                self.io = self.create(name, case, query_type(string=row['parameters']))
                self.parameters = row['parameters']

class SGZip(Advanced):
    """ Sgzip is pyflags native image file format """
    subsys = 'sgzip'

class EWF(Advanced):
    """ EWF is used by other forensic packages like Encase or FTK """
    subsys = 'ewf'

class OffsettedFile(IOSubsysFD):
    def __init__(self, filename, offset):
        self.fd = IO.open_URL(filename)
        self.offset = offset
        self.fd.seek(0,2)
        self.size = self.fd.tell() - offset
        self.fd.seek(offset)
        self.readptr = 0
        
    def seek(self, offset, whence=0):
        IOSubsysFD.seek(self, offset, whence)
        self.fd.seek(self.readptr + self.offset)

    def read(self, length=0):
        result = self.fd.read(length)
        self.readptr += len(result)
        return result

class Standard(Advanced):
    """ Standard image types as obtained by dd """
    order=10

    def form(self, query, result):
        result.fileselector("Select %s image:" % self.__class__.__name__.split(".")[-1], name="filename", vfs=True)
        self.calculate_partition_offset(query, result)

    def create(self, name, case, query):
        offset = self.calculate_offset_suffix(query.get('offset','0'))
        filename = query['filename']
        return OffsettedFile(filename, offset)

    def open(self, name, case, query=None):
        self.cache_io(name, case, query)
        self.io.seek(0)
        return self.io

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

    def read(self, length=0):
        ## try to get the data out of the cache:
        key = "%s%s" % (self.readptr,length)
        try:
            data = self.cache.get(key)
        except KeyError,e:
            data = self.io.read_random(length,self.readptr)
            self.cache.put(data, key=key)

        self.readptr += len(data)
        return data

import pyflag.tests as tests
class AdvancedTest(tests.ScannerTest):
    """ Test basic performance of Advanced IO Source """
    test_case = "PyFlagTestCase"
    test_file = "split/test_image.1"
    subsystem = "Advanced"
    offset = "16128s"
