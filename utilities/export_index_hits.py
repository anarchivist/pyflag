#!/usr/bin/env python
# This small script exports ALL files which score a hit in the
# index(keyword) scanner. The output directory is specified on the
# command line, output is organised as follows:
#
# outdir/keyword/vfspath
#
# keyword and vfspath have '/' chars replaced with '_' this is the
# only sanitisation performed, dont run this script as root! Also, if
# a file matches multiple search terms, it will get copied multiple
# times into the outdir. This script is intended to be used with
# fairly specific dictionaries which don't produce too many hits

import os.path
import sys
import pyflag.FileSystem as FileSystem
import pyflag.Registry as Registry
import pyflag.DB as DB
import pyflag.FlagFramework as FlagFramework
import plugins.DiskForensics.LogicalIndex as LogicalIndex

if(len(sys.argv) != 3):
    print "Usage: %s case outdir" % sys.argv[0]
    
case, outdir = sys.argv[1:]

# initialise pyflag
flag = FlagFramework.Flag()
FlagFramework.GLOBAL_FLAG_OBJ =flag

# get a vfs handle and some db handles
fsfd = Registry.FILESYSTEMS.fs['DBFS'](sys.argv[1])
dbh = DB.DBO(case=sys.argv[1])
dbh2 = DB.DBO(case=sys.argv[1])

dbh.execute("select word,offset from LogicalIndexOffsets, pyflag.dictionary where LogicalIndexOffsets.id=pyflag.dictionary.id")
for row in dbh:
    # create search term subdir in outdir
    subdir = "%s/%s" % (outdir, row['word'].replace(os.path.sep, '_'))
    if not os.path.exists(subdir):
        os.mkdir(subdir)
        
    # resolve the inode from the logical image offset
    inode = LogicalIndex.resolve_inode(dbh2, row['offset'])

    # find and sanitise the original path
    path = fsfd.lookup(inode=inode)
    path = path.replace(os.path.sep, '_')

    # open the input and output files
    fd = fsfd.open(inode=inode)
    outfd = open("/%s/%s" % (subdir, path), "w")
    
    # write and close
    outfd.write(fd.read())
    outfd.close()
    fd.close()
