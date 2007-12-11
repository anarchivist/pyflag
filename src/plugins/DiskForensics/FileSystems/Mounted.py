""" This implemented the Mounted Filesystem driver to provide access
to filesystem which we dont have a driver for. We use the kernel to
mount the filesystem on a directory in the upload directory. We dont
have access to slack, deleted files etc, but its something.
"""

import pyflag.FileSystem as FileSystem
import pyflag.pyflaglog as pyflaglog
from pyflag.FileSystem import FileSystem,DBFS,File
import pyflag.DB as DB
import pyflag.IO as IO
import pyflag.FlagFramework as FlagFramework
import time,os
import math
import bisect
import pyflag.conf
config=pyflag.conf.ConfObject()
import os.path
import stat

## This is just a psuedo filesystem to load the image into the VFS:
class Raw(DBFS):
    """ A psuedo file system to load raw images """
    name="Raw"
    order = 50

    def load(self, mount_point, iosource_name, scanners=None, directory = None):
        ## Ensure that mount point is normalised:
        mount_point = os.path.normpath(mount_point)
        DBFS.load(self, mount_point, iosource_name)

        ## Just add a single inode:
        self.VFSCreate("I%s" % iosource_name,'o0', "%s/raw_filesystem" % mount_point)

## This is the IO Source:
class Mounted(IO.Image):
    """ Treat a mounted directory as an image """
    size = 0
    def seek(self, offset, whence=0):
        pass

    def close(self):
        pass

    def read(self, length):
        return ''

    def form(self,query, result):
        result.fileselector("Select a directory or a file in the image", name="filename")

    def open(self, name, case, query=None):
        dbh = DB.DBO(case)

        if query:
            if query.has_key('filename'):
                ## Check to see that filename is in the upload dir:
                filename = os.path.normpath(query['filename'])
                query['directory'] = os.path.dirname(filename)
                
            if not query.has_key('directory'):
                raise IOError("Mandatory parameter 'directory' not provided")
            else:
                self.directory = query['directory']
                
        ## Check that the name does not already exist:
            if name:
                dbh.execute("select * from iosources where name = %r" , name)
                if dbh.fetch():
                    raise IOError("An iosource of name %s already exists in this case" % name)
                
                ## If we get here we made it successfully so store in db:
                dbh.insert('iosources',
                           name = query['iosource'],
                           type = self.__class__.__name__,
                           parameters = "%s" % query,
                           _fast = True)
        else:
            ## No query provided, we need to fetch it from the db:
            dbh.check_index('iosources','name')
            dbh.execute("select parameters from iosources where name = %r" , name)
            row = dbh.fetch()
            query = FlagFramework.query_type(string=row['parameters'])
            self.directory = query['directory']

        return self

class MountedFS(DBFS):
    """ A class implementing the mounted filesystem option """
    name = 'Mounted'
    order = 100

    def guess(self, fd, result, metadata):
        """ We can only really handle mounted IO sources, we cant
        actually handle anything else
        """
        DBFS.guess(self, fd, result, metadata)
        if fd.__class__.__name__ == 'Mounted':
            return 120
        else:
            return -1
    
    def load(self, mount_point, iosource_name):
        iosrc = IO.open(self.case, iosource_name)
        
        pyflaglog.log(pyflaglog.DEBUG,"Loading files from directory %s" % iosrc.directory)
        dbh_file=DB.DBO(self.case)
        dbh_file.mass_insert_start('file')
        
        dbh_inode=DB.DBO(self.case)
        dbh_inode.mass_insert_start('inode')
        
        ## This deals with a mounted filesystem - we dont get the full
        ## forensic joy, but we can handle more filesystems than
        ## sleuthkit can.  The downside is that the user has to mount
        ## the filesystem first, we also need to be running as root or
        ## we may not be able to stat all the files :-(
        def insert_into_table(mode ,root ,name):
            rel_root = FlagFramework.normpath(mount_point + "/" + root[len(iosrc.directory):] + "/")
            try:
                s=os.lstat(os.path.join(root,name))
            except OSError:
                pyflaglog.log(pyflaglog.WARNING, "Unable to stat %s - mount the directory with the uid option" % root)
                return

            inode = "I%s|M%s" % (iosource_name, s.st_ino)
            dbh_inode.insert('inode',
                             inode = inode,
                             uid = s.st_uid,
                             gid = s.st_gid,
                             _mtime = "from_unixtime(%s)" % s.st_mtime,
                             _atime = "from_unixtime(%s)" % s.st_atime,
                             _ctime = "from_unixtime(%s)" % s.st_ctime,
                             status = 'alloc',
                             mode = str(oct(s.st_mode)),
                             size = s.st_size,
                             _fast=True)
            inode_id = dbh_inode.autoincrement()
            
            dbh_file.mass_insert(inode_id = inode_id,
                                 inode = inode,
                                 mode = mode,
                                 status = 'alloc',
                                 path = rel_root,
                                 name = name)
                                 
            ## Fixme - handle symlinks
            try:
                link=os.readlink("%s/%s" % (root,name))
            except OSError:
                link=''

#            dbh.execute("insert into inode_%s set inode='M%s',uid=%r,gid=%r, mtime=%r,atime=%r,ctime=%r,mode=%r,links=%r,link=%r,size=%r",(self.table,s.st_ino,s.st_uid,s.st_gid,s.st_mtime,s.st_atime,s.st_ctime,str(oct(s.st_mode))[1:],s.st_nlink,link,s.st_size))

        ## Just walk over all the files and stat them all building the tables.
        for root, dirs, files in os.walk(iosrc.directory):
            for name in dirs:
                insert_into_table('d/d',root,name)
            for name in files:
                insert_into_table('r/r',root,name)

        dbh_file.mass_insert_commit()
        dbh_inode.mass_insert_commit()

class MountedFS_file(File):
    """ access to real file in filesystem """
    specifier = 'M'
    def __init__(self, case, fd, inode):
        File.__init__(self, case, fd, inode)
        #strategy: must determine basepath from parent, get our path
        #from db and then return the file:
        
        ## Note this _must_ work because we can only ever be called on
        ## a mounted iosource - it is an error otherwise:
        basepath = fd.io.directory

        self.case = case
        dbh = DB.DBO(case)
        dbh.check_index("file" ,"inode")
        dbh.execute("select path,name from file where inode=%r limit 1",(inode))
        row=dbh.fetch()
        path=basepath+'/'+row['path']+"/"+row['name']
        self.fd = open(path,'r')
    
    def close(self):
        self.fd.close()

    def seek(self, offset, rel=None):
        if rel!=None:
            self.fd.seek(offset,rel)
        else:
            self.fd.seek(offset)

    def read(self, length=None):
        if length!=None:
            return self.fd.read(length)
        else:
            return self.fd.read()

    def tell(self):
        return self.fd.tell()

## Unit tests:
import pyflag.tests as tests

class MountedTest(pyflag.tests.ScannerTest):
    """ Test the Mounted Psuedo Filesystem driver """
    test_case = "PyFlagTestCase"
    test_file = "pyflag_stdimage_0.3"
    subsystem = "Mounted"
    fstype = "Mounted"
