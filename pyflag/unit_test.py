# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Name:  $ $Date: 2004/10/26 01:07:53 $
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
""" Python script to test the pyflag distribution.

This will eventually contain proper unit testing, for now it simply instantiates all the objects, hopefully touching everything they need.

This is used by the binary distribution building to remove files we do not touch from the core python distribution
"""
## Subsystem tests:
import SimpleHTTPServer
import cgi
import re,time,sys,popen2,types

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
    raise IOError("Unable to find magic file")

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
import md5
import threading

a=pickle.dumps("hello world")
if "hello world"!=pickle.loads(a):
	raise Exception

## Examine.py:
import tempfile,getopt,os.path

## Logfile:
import csv,pickle

## The PST file
import base64

## Gzip scanner
import gzip

## Whois utilities
import urllib

## Clamav scanner
import clamav

## Initialise registry to load all modules in.
import pyflag.Registry as Registry
Registry.Init()
