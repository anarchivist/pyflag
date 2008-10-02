""" This module contains the various file handlers PyFlag can use to
access different files.

FileHandlers are used to abstract access to files through a URL like
system. This makes it possible to load files from within the VFS, or
the real filesystem transparently.
"""
import pyflag.IO as IO
import os,gzip,re,posixpath
import pyflag.conf
config = pyflag.conf.ConfObject()
import pyflag.FileSystem as FileSystem
import pyflag.Registry as Registry
import pyflag.FlagFramework as FlagFramework

class FileMethod(IO.FileHandler):
    """ This method handler obtains files from PyFlag's Upload directory.

    Note that all paths are specified relative to the upload directory
    in order to ensure that no files above it are accessible. This is
    because PyFlag is primarily a web application and it would not
    make sense to expose system files to users.

    Note that URLs are similar to:

    file:///somefile.txt

    (i.e. there are 3 / after the : to symbolise that no name is
    specified. In fact the name is ignored here anyway)
    """
    method = "file"

    def open(self):
        ## Make sure there are no ../
        path = os.path.normpath(self.path)
        
        if not self.path.startswith(posixpath.normpath(config.UPLOADDIR)):
            file = os.path.normpath(os.path.sep.join([config.UPLOADDIR,path]))
        else:
            file = path

        ## We need to handle gzip files transparently here:
        try:
            ## Allow log files to be compressed.
            fd=gzip.open(file,'rb')
            
            ## gzip doesnt really verify the file until you read something:
            fd.read(10)
            fd.seek(0)
        except:
            fd=open(file,'rb')

        return fd

class VFSMethod(IO.FileHandler):
    """ This method accesses the VFS and retrieves a file from there.

    The URL format is:

    vfs://case/path
    
    """
    method = "vfs"

    def open(self):
        fsfd = FileSystem.DBFS(self.name)
        return fsfd.open(path = self.path)

class IOSourceMethod(IO.FileHandler):
    """ This method returns an IO Source expressed as a URL.

    The format is:

    io://driver/query_string

    For example:

    io://Advanced/filename=image.dd&offset=0

    This allows us to specify an io source everywhere a file is
    required. For example this is useful for a raid set which has each
    disk compressed, or a log file which is compressed using ewf etc.
    """
    method = "io"

    def open(self):
        try:
            image = Registry.IMAGES.dispatch(self.name)()
        except ValueError:
            raise RuntimeError("Unknown IOSource driver %s" % self.name)

        query = FlagFramework.query_type(string=self.path[1:])
        filenames = query.getarray('filename')
        query.clear('filename')

        ## Adjust all the filenames to be rooted at the UPLOADDIR:
        for f in filenames:
            query['filename'] = os.path.normpath(
                os.path.sep.join([config.UPLOADDIR, f]))
        
        return image.open(None, None, query=query)

class IOSourceMethod(IO.FileHandler):
    """ This method returns an IO Source expressed as a URL.

    The format is:

    io://driver/query_string

    For example:

    io://Advanced/filename=image.dd&offset=0
    """
    method = "io"

    def open(self):
        try:
            image = Registry.IMAGES.dispatch(self.name)()
        except ValueError:
            raise RuntimeError("Unknown IOSource driver %s" % self.name)

        query = FlagFramework.query_type(string=self.path[1:])
        filenames = query.getarray('filename')
        query.clear('filename')

        ## Adjust all the filenames to be rooted at the UPLOADDIR:
        for f in filenames:
            query['filename'] = os.path.normpath(
                os.path.sep.join([config.UPLOADDIR, f]))
        
        return image.open(None, None, query=query)


import pyflag.tests as tests

#class MethodHandlerTests(tests.FDTest):
#    pass
