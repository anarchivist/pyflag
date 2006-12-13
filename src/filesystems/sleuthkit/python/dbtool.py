#!/usr/bin/env python
# python implementation of dbtool using sk binding
# should produce the same results as dbtool (!)

import sys
import sk

fs = sk.skfs(sys.argv[1])
mnt = "mnt"
ios = "Iios"

def insert(inode, type, path, name):
    insert_file(inode, type, path, name)

    # only insert inode record if allocated
    if inode.alloc:
        insert_inode(inode)

def insert_file(inode, type, path, name):
    inodestr = "%s|D%d" % (ios, inode)
    pathstr = "%s%s/" % (mnt, path)

    if pathstr.startswith("//"):
        pathstr = pathstr[1:]
    if pathstr.endswith("//"):
        pathstr = pathstr[:-1]

    if inode.alloc:
        allocstr = "alloc"
    else:
        allocstr = "deleted"
        type = type[:-1]+'-'

    # print file entry
    print "INSERT INTO file (`inode`,`mode`, `status`, `path`, `name`) VALUES(%r,%r,%r,%r,%r);" % (inodestr, type, allocstr, pathstr, name)

def insert_inode(inode):
    inodestr = "%s|D%d" % (ios, inode)

    if inode.alloc:
        status = 'a'
    else:
        status = 'f'

    try:
        s = fs.stat(inode=str(inode))
        print "INSERT INTO inode (`inode`,`status`,`uid`, `gid`,`mtime`,`atime`, `ctime`,`dtime`,`mode`, `links`,`link`,`size`) VALUES(%r,%r,'%r','%r',from_unixtime(%d), from_unixtime(%d),from_unixtime(%d), from_unixtime(%d),'%r','%r',%r,'%r');" % (inodestr, status, s.st_uid, s.st_gid, s.st_mtime, s.st_atime, s.st_ctime, 0, s.st_mode, s.st_nlink, "", s.st_size)

    except IOError:
        pass

# insert root inode
insert_inode(fs.root_inum)

# walk the directory tree
for root, dirs, files in fs.walk('/', unalloc=True, inodes=True):
    for d in dirs:
        insert(d[0], 'd/d', root[1], d[1])
    for f in files:
        insert(f[0], 'r/r', root[1], f[1])

# find any unlinked inodes here
for s in fs.iwalk():
    insert_inode(s)

