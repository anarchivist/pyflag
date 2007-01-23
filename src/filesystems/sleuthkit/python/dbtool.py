#!/usr/bin/env python
# python implementation of dbtool using sk binding
# should produce the same results as dbtool (!)

import sys
import sk
import pyflag.DB as DB

img = open(sys.argv[1])
fs = sk.skfs(img)

mnt = "mnt"
ios = "Iios"

def runs(blocks):
    # converts an ordered list e.g. [1,2,3,4,7,8,9] into a list of
    # 'runs'; tuples of (start, length) e.g. [(1,4),(7,3)]
    if len(blocks) == 0:
        return

    index = 0
    start = None
    length = 1
    for i in blocks:
        if start==None:
            start = i
        elif i==start+length:
            length+=1
        else:
            yield index,start,length
            index += 1
            start = i
            length = 1

    yield index,start,length


def insert(inode, type, path, name):
    # insert the file record
    insert_file(inode, type, path, name)

    # insert inode record
    if inode.alloc == 1:
        insert_inode(inode)

def insert_file(inode, type, path, name):
    # dont do anything for realloc inodes
    if inode.alloc == 2:
        return

    inodestr = "%s|D%s" % (ios, inode)
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
    # dont do anything for realloc inodes
    if inode.alloc == 2:
        return

    inodestr = "%s|D%s" % (ios, inode)

    if inode.alloc:
        status = 'a'
    else:
        status = 'f'

    try:
        f = fs.open(inode=str(inode))
        s = fs.fstat(f)
        print "INSERT INTO inode (`inode`,`status`,`uid`, `gid`,`mtime`,`atime`, `ctime`,`dtime`,`mode`, `links`,`link`,`size`)  VALUES(%r,%r,'%r','%r',from_unixtime(%d), from_unixtime(%d),from_unixtime(%d), from_unixtime(%d),'%r','%r',%r,'%r');" % (inodestr, status, s.st_uid, s.st_gid, s.st_mtime, s.st_atime, s.st_ctime, 0, s.st_mode, s.st_nlink, "", s.st_size)

    except IOError:
        pass

    #insert block runs
    index = 0
    for (index, start, count) in runs(f.blocks()):
        print "INSERT INTO block values ( %s, %s, %s, %s )" % (inodestr,index,start,count)

if __name__ == "__main__":

    # insert root inode
    insert_inode(fs.root_inum)

    # walk the directory tree
    for root, dirs, files in fs.walk('/', unalloc=True, inodes=True):
        for d in dirs:
            insert_file(d[0], 'd/d', root[1], d[1])
            insert(d[0], 'd/d', root[1], d[1])
        for f in files:
            pass
            #insert(f[0], 'r/r', root[1], f[1])

    # find any unlinked inodes here
    #for s in fs.iwalk():
    #    insert_inode(s)

    # add contiguous unallocated blocks here as 'unallocated' files.
    # the offset driver over the iosource should work for this
    unalloc_blocks = []
    count=0
    last = (0,0)
    dbh_unalloc = DB.DBO("unalloctest")
    dbh_unalloc.execute("select * from block order by block asc")
    print fs.block_size
    print fs.first_block
    print fs.last_block
    for row in dbh_unalloc:
        ## We make a list of all blocks which are unallocated:
        ## This is the end of the unallocated block just before this one:
        new_block = ( last[0],row['block']-last[0])
        if new_block[1]>0:
            ## Add the offset into the db table:
            offset = new_block[0] * fs.block_size
            size = new_block[1] * fs.block_size
            
            ## Add a new VFS node:
            print "I%s" % "foobar", ' o%s:%s' % (offset, size), " /_unallocated_/o%08d" % count
            count+=1
            unalloc_blocks.append(new_block)
            
        last=(row['block']+row['count'],0,row['inode'])

    ## Now we need to add the last unalloced block. This starts at
    ## the last allocated block, and finished at the end of the IO
    ## source. The size of -1 makes the VFS driver keep reading till the end.
    offset = last[0] * fs.block_size
    print "I%s" % "foobar", ' o%s:%s' % (offset, 0), " /_unallocated_/o%08d" % count

