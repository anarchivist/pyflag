#!/usr/bin/env python
import pyflag.IO as IO
import sys
import sk
from stat import *

#img = open(sys.argv[1],'r')
#print "Will open %s" % sys.argv[1]

## This assumes that we have a case loaded
img = IO.open('winxp','test')
fs = sk.skfs(img)

def readfile(fs,inode):
    print "reading: %s" % inode
    fd = fs.open(inode=inode)
    while True:
        if not fd.read(4000000):
            break

# walk the directory tree
for root, dirs, files in fs.walk('/', unalloc=True, inodes=True):
    for f in files:
        try:
            print "processing: (%u) %s" % (f[0], f[1])
            s=fs.stat(inode=str(f[0]))
            print "length %s" % s[ST_SIZE]
            if int(f[0])==0: continue
            readfile(fs,str(f[0]))
        except IOError, e:
            print "Got error: %s" % e

# find any unlinked inodes here
for inode in fs.iwalk():
    fs.stat(inode=str(inode))
    readfile(fs,str(inode))
