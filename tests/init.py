import pyflag.IO as IO
import pyflag.Registry as Registry
Registry.Init()

case = "demo"

## This gives us a handle to the VFS
fsfd = Registry.FILESYSTEMS.fs['DBFS'](case)
