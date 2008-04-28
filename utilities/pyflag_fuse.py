#!/usr/bin/env python
# ******************************************************
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.86RC1 Date: Thu Jan 31 01:21:19 EST 2008$
# ******************************************************
#
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# *
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
# ******************************************************
"""
Utility to mount the PyFlag Virtual FileSystem using fuse.
"""
import os, sys
from errno import *
from stat import *
import fcntl

import fuse
from fuse import Fuse, FuseOptParse

import pyflag.DB as DB
import pyflag.IO as IO
import pyflag.FileSystem as FileSystem
import pyflag.Registry as Registry
import pyflag.pyflaglog as pyflaglog

import pyflag.conf
config = pyflag.conf.ConfObject()

Registry.Init()

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

class FuseError(IOError):
    """ A class to raise when we want to signal an error from the
    fs. Errnos are taken from /usr/include/asm-generic/errno-base.h
    """
    def __init__(self, message='',errno=1):
        self.errno = errno
        print message
        IOError.__init__(self,message)

class PyFlagVFS(Fuse):
    def __init__(self, *args, **kw):
        Fuse.__init__(self, *args, **kw)

        self.case=config.case
        self.fs = FileSystem.DBFS(case=self.case)
        self.root = config.fsroot

    def getattr(self, path):
        path = os.path.normpath("%s/%s" % (self.root, path))
        try:
            result = self.fs.lstat(path=path)
        except RuntimeError,e:
            raise FuseError("%s Not found" % path, 2)
        
        if not result:
            return os.stat_result((16877, 1L, 1, 1, 0, 0, 4096L, 0, 0, 0))

        return result

    def readlink(self, path):
        result = self.fs.readlink(path)
        if not result:
            raise FuseError("Cannot read symbolic link %s" % path, 2)

        return result

    def readdir(self, path, offset):
        path = os.path.normpath("%s/%s" % (self.root, path))
        if not path.endswith('/'): path=path+'/'
        for e in self.fs.ls(path=path):
            if e == "": continue
            yield fuse.Direntry(e)

    def unlink(self, path):
        raise FuseError("Unable to modify Virtual Filesystem")

    def rmdir(self, path):
        raise FuseError("Unable to modify Virtual Filesystem")

    def symlink(self, path, path1):
        raise FuseError("Unable to modify Virtual Filesystem")

    def rename(self, path, path1):
        raise FuseError("Unable to modify Virtual Filesystem")

    def link(self, path, path1):
        raise FuseError("Unable to modify Virtual Filesystem")

    def chmod(self, path, mode):
        raise FuseError("Unable to modify Virtual Filesystem")

    def chown(self, path, user, group):
        raise FuseError("Unable to modify Virtual Filesystem")

    def truncate(self, path, size):
        raise FuseError("Unable to modify Virtual Filesystem")
    
    def mknod(self, path, mode, dev):
        raise FuseError("Unable to modify Virtual Filesystem")
    
    def mkdir(self, path, mode):
        raise FuseError("Unable to modify Virtual Filesystem")

    def utime(self, path, times):
        raise FuseError("Unable to modify Virtual Filesystem")

    def access(self, path, mode):
        pass

    def statfs(self):
        return fuse.StatVfs()

    class PyFlagVFSFile(object):
        def __init__(self, path, flags, *mode):
            self.case=config.case
            self.fs = FileSystem.DBFS(case=self.case)
            path = os.path.normpath("%s/%s" % (config.fsroot, path))
            self.path = path
            self.file = self.fs.open(path=self.path)

        def read(self, length, offset):
            self.file.seek(offset)
            return self.file.read(length)

        def write(self, buf, offset):
            raise FuseError("Unable to write to forensic filesystem on %s" % path)

        def release(self, flags):
            self.file.close()

        def fgetattr(self):
            return self.fs.lstat(path=self.path)

        def direct_io(self, *args, **kwargs):
            raise FuseError("Direct IO not supported")

        def keep_cache(self, *args, **kwargs):
            raise FuseError("Direct IO not supported")

    def main(self, *a, **kw):

        self.file_class = self.PyFlagVFSFile
        return Fuse.main(self, *a, **kw)


## Help is handled a little differently for us because we need to
## print the fuse help too: (This is such a hack....)
def print_help():
    ## This is special because config is a singleton so self does not
    ## seem to be passed.
    self = config.optparser
    print self.format_help()

    ## This is so stupid - we need to create a whole instance to get
    ## the underlying library to print help... and the library insists
    ## on printing to stderr while we do to stdout... This hackery is
    ## to make it do what we want.
    sys.stdout.flush()
    errfd = sys.stderr.fileno()
    os.close(errfd)
    os.dup2(sys.stdout.fileno(), errfd)

    t = PyFlagVFS()
    t.fuse_args.setmod('showhelp')
    t.main()

## Hook onto the print_help
config.optparser.print_help = print_help

config.set_usage("""%prog [options] mountpoint
PyFlag FUSE Filesystem: mounts the pyflag VFS into the operating system fs.""",
                 version = "Version: %%prog PyFlag %s" % config.VERSION)

def main():
    config.add_option("debug",short_option='d', default=False, action='store_true',
                      help = "Fuse Debug")

    config.add_option("case", default=None,
                      help="Case to load the files into (mandatory). "
                      " Case must have been created already.")

    config.add_option("foreground", short_option='f', default=False, action='store_true',
                      help = 'Foreground')

    config.add_option("fuse_option",short_option='o', default=None,
                      help = 'Fuse specific options (see -h)')

    config.add_option("fsroot", short_option='r', default='/',
                      help="mirror filesystem from under PATH")

    config.parse_options()

    if not config.case:
        pyflaglog.log(pyflaglog.ERRORS, "A case must be specified")
        sys.exit(-1)

    if len(config.args)==0:
        pyflaglog.log(pyflaglog.ERRORS, "You must specify a mount point")
        sys.exit(-1)
    elif len(config.args)>1:
        pyflaglog.log(pyflaglog.ERRORS, "You must specify only one mount point")
        sys.exit(-1)
        
    server = PyFlagVFS(dash_s_do='setsingle')
    
    server.fuse_args.mountpoint = config.args[0]
    pyflaglog.log(pyflaglog.DEBUG,"Mounting on %s" % server.fuse_args.mountpoint)
    
    args = ['-s']
    if config.debug: args.append("-d")
    if config.foreground: args.append("-f")
    if config.fuse_option:
        args.append("-o")
        args.append(config.fuse_option)
    
    server.parse(args=args,values=server, errex=1)

    try:
        if server.fuse_args.mount_expected():
            os.chdir("/")
    except OSError:
        print >> sys.stderr, "can't enter root of underlying filesystem"
        sys.exit(1)

    server.main()


if __name__ == '__main__':
    main()
