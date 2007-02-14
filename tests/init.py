import pyflag.IO as IO
import pyflag.Registry as Registry
Registry.Init()
import pyflag.FileSystem as FileSystem
from FileSystem import DBFS

case = "demo"

## This gives us a handle to the VFS
fsfd = Registry.FILESYSTEMS.fs['DBFS'](case)

## WE just open a file in the VFS:
#fd=fsfd.open(inode="Itest|S1/2")

## And read it
#print fd.read()
