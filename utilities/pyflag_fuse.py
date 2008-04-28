#!/usr/bin/env python
#

import os, sys
from errno import *
from stat import *
import fcntl

import fuse
from fuse import Fuse

import pyflag.conf
config = pyflag.conf.ConfObject()
import pyflag.DB as DB
import pyflag.IO as IO
import pyflag.FileSystem as FileSystem
import pyflag.Registry as Registry

Registry.Init()

#config.add_option("case", default=None,
#                  help="Case to load the files into (mandatory). Case must have been created already.")

#config.parse_options(final=False)

if not hasattr(fuse, '__version__'):
    raise RuntimeError, \
        "your fuse-py doesn't know of fuse.__version__, probably it's too old."

fuse.fuse_python_api = (0, 2)

fuse.feature_assert('stateful_files', 'has_init')

def flag2mode(flags):
    md = {os.O_RDONLY: 'r', os.O_WRONLY: 'w', os.O_RDWR: 'w+'}
    m = md[flags & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR)]

    if flags | os.O_APPEND:
        m = m.replace('w', 'a', 1)

    return m

class PyFlagVFS(Fuse):

    def __init__(self, *args, **kw):
        Fuse.__init__(self, *args, **kw)

        self.case="test"
        self.fs = FileSystem.DBFS(case=self.case)
        self.root = '/'

    def getattr(self, path):
        print "get getattr for %s" % path
        if path=='/': 
            return os.stat_result((16877, 1L, 1, 1, 0, 0, 4096L, 0, 0, 0))

        result = self.fs.lstat(path=path)
        if not result: 
            raise OSError("Unable to stat file %s" % path)

        return result

    def readlink(self, path):
        result = self.fs.readlink(path)
        if not result:
            raise OSError("Cannot read symbolic link %s" % path)

        return result

    def readdir(self, path, offset):
        if not path.endswith('/'): path=path+'/'
        for e in self.fs.ls(path=path):
            if e == "": continue
            yield fuse.Direntry(e)

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

    def access(self, path, mode):
        pass

    def statfs(self):
        return fuse.StatVfs()

    class PyFlagVFSFile(object):

        def __init__(self, path, flags, *mode):
            self.case="test"
            self.fs = FileSystem.DBFS(case=self.case)
            self.path = path
            self.file = self.fs.open(path=self.path)

        def read(self, length, offset):
            self.file.seek(offset)
            return self.file.read(length)

        def write(self, buf, offset):
            raise IOError("Unable to write to forensic filesystem on %s" % path)

        def release(self, flags):
            self.file.close()

        def fgetattr(self):
            return self.fs.lstat(path=self.path)

    def main(self, *a, **kw):

        self.file_class = self.PyFlagVFSFile
        return Fuse.main(self, *a, **kw)


def main():

    usage = """
PyFlag FUSE Filesystem: mounts the pyflag VFS into the operating system fs.

""" + Fuse.fusage

    server = Xmp(version="%prog " + fuse.__version__,
                 usage=usage,
                 dash_s_do='setsingle')

    server.parser.add_option(mountopt="root", metavar="PATH", default='/',
                             help="mirror filesystem from under PATH [default: %default]")
    server.parser.add_option("-c","--case",default=None,help="Case to open")
    server.parse(values=server, errex=1)

    try:
        if server.fuse_args.mount_expected():
            os.chdir(server.root)
    except OSError:
        print >> sys.stderr, "can't enter root of underlying filesystem"
        sys.exit(1)

    server.main()


if __name__ == '__main__':
    main()
