import pyflag.Registry as Registry
import pyflag.IO as IO
Registry.Init()

io=IO.open("demo","test")
fsfd = Registry.FILESYSTEMS.fs['DBFS']('demo','test',io)
