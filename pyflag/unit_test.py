""" Python script to test the pyflag distribution.

This will eventually contain proper unit testing, for now it simply instantiates all the objects, hopefully touching everything they need.

This is used by the binary distribution building to remove files we do not touch from the core python distribution
"""
## Subsystem tests:
import SimpleHTTPServer
import cgi
import re,time,sys,popen2

import pyflag.conf as conf
config=conf.ConfObject()

import pyflag.HTMLUI as HTMLUI
ui=HTMLUI.HTMLUI()

import pyflag.FlagFramework as FlagFramework
flag=FlagFramework.Flag(ui)
hex=FlagFramework.HexDump("hello",ui)
query=FlagFramework.query_type(())
query['subsys']='standard'
query['io_filename']='/etc/passwd'

import iosubsys
import pyflag.IO as IO
io=IO.IOFactory(query)

import magic
m=magic.magic_open(magic.MAGIC_NONE)
if magic.magic_load(m,config.MAGICFILE) < 0:
    raise IOError

import pyflag.DB as DB
dbh=DB.DBO(None)
dbh.execute("select from_unixtime(0)")
dbh.fetch()

import pyflag.Ethereal
import pyflag.Exgrep

import pyflag.Graph as Graph
pl=Graph.Ploticus()

import pyflag.Sleuthkit as Sleuthkit
import pyflag.pyflagsh

import index
import glob
import time
import zipfile
import pickle

a=pickle.dumps("hello world")
if "hello world"!=pickle.loads(a):
	raise Exception
