""" This module defines all the standard Image drivers within PyFlag """

import pyflag.IO as IO
import pyflag.DB as DB
from FlagFramework import query_type
import pyflag.FlagFramework as FlagFramework
import sk,re,os,os.path,posixpath
import pyflag.conf
config=pyflag.conf.ConfObject()
import bisect

filename_re = re.compile("(.+?)(\d+)$")

class OffsettedFDFile:
    def __init__(self, fds, offset):
        self.fds = fds
        self.offset = offset
        self.readptr = 0
        ## This stores the offset at the begining of each file
        start = 0
        self.offsets = []
        for fd in fds:
            self.offsets.append(start)
            try:
                size = fd.size
            except AttributeError:
                fd.seek(0,2)
                size =fd.tell()

            start += size

        self.offsets.append(start)
        self.size = start
        self.seek(offset)

    def seek(self, offset, whence=0):
        """ fake seeking routine """
        readptr = self.readptr
        if whence==0:
            readptr = offset + self.offset
        elif whence==1:
            readptr += offset
        elif whence==2:
            readptr = self.size

        if readptr<self.offset:
            raise IOError("Seek before start of file")

        self.readptr = readptr

        ## Try and work out which file we are in
        self.fd_index = bisect.bisect_right(self.offsets, self.readptr)-1
        if self.fd_index < len(self.fds):
            ## Seek the actual fd
            self.fds[self.fd_index].seek(self.readptr - self.offsets[self.fd_index])

    def tell(self):
        """ return current read pointer """
        return self.readptr - self.offset

    def partial_read(self, length):
        """ Read from current fd as much as possible.
        """
        available_to_read = self.offsets[self.fd_index + 1] - self.readptr
        data = self.fds[self.fd_index].read(min(length, available_to_read))
        self.readptr += len(data)
        return data

    def read(self, length=0):
        """ read length bytes from subsystem starting at readptr """
        result = ''
        while len(result)<length:
            data = self.partial_read(length)
            if len(data)==0: break
            
            result += data
            length -= len(data)
            
        return result

    def close(self):
        """ close subsystem """
        pass

class OffsettedFile(OffsettedFDFile):
    def __init__(self, filenames, offset):
        if type(filenames)==str:
            filenames = [ filenames,]
        fds = [ IO.open_URL(filename) for filename in filenames ]
        OffsettedFDFile.__init__(self, fds, offset)

class Standard(IO.Image):
    """ Standard image types as obtained by dd """
    order=10
    ## This is a cached version of this iosource so we dont need to
    ## recreate it each time.
    io = None
    
    def calculate_partition_offset(self, query, result, offset = 'offset'):
        """ A GUI function to allow the user to derive the offset by calling mmls """
        def mmls_popup(query,result):
            result.decoration = "naked"

            try:
                del query[offset]
            except: pass

            io = self.create(None, query.get('case'), query)
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

    def form(self, query, result):
        result.fileselector("Select %s image:" % self.__class__.__name__.split(".")[-1], name="filename", vfs=True)
        self.calculate_partition_offset(query, result)

    def glob_filenames(self, filenames):
        """ Returns the array of files found by globbing filenames on
        numeric suffix
        """
        result = []
        for f in filenames:
            ## Ignore files which are urls
            if re.match("[^:]+://",f): return filenames

            if not f.startswith(os.path.normpath(config.UPLOADDIR)):
                f = FlagFramework.sane_join(config.UPLOADDIR,f)

            ## FIXME - this is of limited value because the user can
            ## just create multiple symlinks for each file
            if 0 and config.FOLLOW_SYMLINKS:
                ## Is it a symlink? This allows us to symlink to a
                ## single file from a fileset using a simple
                ## name. This makes it nice to manage the upload
                ## directory because you can just put a single symlink
                ## (e.g. freds_disk.E01) to the entire evidence set
                ## (could be huge and mounted somewhere different then
                ## the upload directory, e.g. an external driver). It
                ## does pose a security risk if untrusted users are
                ## able to create such a link (it essentially allows
                ## them to fetch files from anywhere on the system.)
                try:
                    link_f = os.readlink(f)
                    if not link_f.startswith("/"):
                        f = posixpath.join(posixpath.dirname(f), link_f)
                    else:
                        f = link_f
                except (OSError, AttributeError):
                    pass

            ## If the filename we were provided with, ends with a
            ## digit we assume that its part of an evidence set.
            m = filename_re.match(f)
            
            if m:
                globbed_filenames = []
                dirname , base = os.path.split(m.group(1))
                for new_f in os.listdir(dirname):
                    if new_f.startswith(base) and filename_re.match(new_f):
                        globbed_filenames.append(FlagFramework.sane_join(dirname, new_f))
    
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

            result.extend(globbed_filenames)

        return result
        
    def create(self, name, case, query):
        offset = FlagFramework.calculate_offset_suffix(query.get('offset','0'))
        filenames = self.glob_filenames(query.getarray('filename'))
        return OffsettedFile(filenames, offset)

    def open(self, name, case, query=None):
        self.cache_io(name, case, query)
        self.io.seek(0)
        return self.io

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
                               timezone = query.get('TZ',"SYSTEM"),
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

config.add_option("FOLLOW_SYMLINKS", default=True, action="store_false",
                  help="Should we follow symlinks in the upload directory? This has security implications if untrusted users are able to create files/symlinks in the upload directory.")

class EWF(Standard):
    """ EWF is used by other forensic packages like Encase or FTK """
    def form(self, query, result):
        result.fileselector("Select %s image:" % self.__class__.__name__.split(".")[-1], name="filename", vfs=False)
        self.calculate_partition_offset(query, result)        

    def create(self, name, case, query):
        offset = FlagFramework.calculate_offset_suffix(query.get('offset','0'))
        filenames = self.glob_filenames(query.getarray('filename'))
        print "Openning ewf file %s" % (filenames,)
        fd = pyewf.open(filenames)            
        return OffsettedFDFile((fd,), offset)

class AFF(Standard):
    """ Advanced Forensics Format, an open format for storage of forensic
    evidence """

    def create(self, name, case, query):
        offset = FlagFramework.calculate_offset_suffix(query.get('offset','0'))
        filenames = self.glob_filenames(query.getarray('filename'))
        fd = pyaff.open(filenames[0])
        return OffsettedFDFile((fd,), offset)

## Optionally turn off the classes which are not supported (due to
## lack of c modules)
try:
    import pyaff
except ImportError:
    def error(*args, **kwargs):
        raise RuntimeError("LibAFF is not installed - please install it and run configure again.")
    AFF = error

try:
    import pyewf
except ImportError:
    def error(*args, **kwargs):
        raise RuntimeError("LibEWF is not installed - please install it and run configure again.")
    EWF = error

import pyflag.tests as tests
class AdvancedTest2(tests.FDTest):
    """ Test basic performance of Split IO Source """
    def setUp(self):
        self.fd = OffsettedFile(["split/test_image.00",
                                 "split/test_image.01",
                                 "split/test_image.02"],0)

    def test10Advanced(self):
        """ Test the stitching around the join points """
        stitch = self.fd.offsets[1]
        self.fd.seek(stitch - 50)
        self.assertEqual(self.fd.tell(), stitch - 50)
        data1 = self.fd.read(500)
        data2 = self.fd.read(500)
        self.fd.seek(stitch - 50)
        self.assertEqual(data1+data2, self.fd.read(1000))
