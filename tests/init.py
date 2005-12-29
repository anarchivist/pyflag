import pyflag.Registry as Registry
import pyflag.FlagFramework as FlagFramework
import pyflag.conf
config=pyflag.conf.ConfObject()

import pyflag.IO as IO
Registry.Init()

case = "demo"
fsimage = "test"

io=IO.open(case,fsimage)
fsfd = Registry.FILESYSTEMS.fs['DBFS'](case,fsimage,io)
