""" This scanner uses the indexing tools to scan the logical files within an image. This allows us to do keyword matching against compressed files, PST files etc.

Implementation Note:
The indextools engine stores a 64bit offset for the occurance of the indexed word. This number is split along a bit mask into two components: The block number and the offset within the block.

For example assume that the blocksize is 2^20 (=1,048,576). When the scanner is scanning a new file it allocates blocks of this size, and stores these into the database as inode vs blocknumber pairs. The indextools then stores blocknumber << 20 | offset_within_block.

When we need to retrieve this we get a list of offsets from the indextools. The problem them becomes how to map these indexes back into an inode and relative offset. We do this by selecting those rows which have the given blocknumber, finding out their inode and seeking the relative offset into the inode's file.

Example:
Suppose we find the word 'Linux' at the 27th byte of inode 5 (Assuming the first 4 inodes are smaller than the blocksize 2^20), indextools will store this offset as 5 << 20 | 27. We therefore insert into the database a row saying that block 5 belongs to inode 5.

When we retrieve this offset (o), we search through the db for the inode containing block o>>20 (5) and receive inode 5. We then seek o & (2^20-1) = 27 bytes into it.

Note that if a single file is larger than the blocksize, we have multiple entries in the database assigning a number of blocks to the same inode. This is not a problem if it is taken into account when reassembling the information.

"""
import pyflag.logging as logging
import pyflag.FlagFramework as FlagFramework
from Scanners import *
import index,os
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.DB as DB

## This blocksize is in bits (2^20)
BLOCKSIZE=20

class Index(GenScanFactory):
    """ Keyword Index files """
    def __init__(self,dbh,table):
        """ This creates the LogicalIndex table and initialised the index file """
        self.dbh=dbh
        ## These keep the current offset in the logical image. FIXME:
        ## When running in a distributed environment this is not
        ## accessible - maybe we need to pass this in the metadata?
        self.rel_offset = 0
        self.block=0
        
        self.table=table
        self.dbh.execute("create table if not exists `LogicalIndex_%s` (`inode` VARCHAR( 20 ) NOT NULL ,`block` BIGINT NOT NULL, primary key(block))",(table))
        self.filename = "%s/LogicalIndex_%s.idx" % (config.RESULTDIR,table)
        try:
            ## Is the file already there?
            self.index = index.Load(self.filename)
        except IOError:
            ## If not we create it
            self.index = index.index(self.filename)
            pydbh = DB.DBO(None)
            pydbh.execute("select word from dictionary")
            for row in pydbh:
                self.index.add(row['word'])
                
    def reset(self):
        """ This deletes the index file and drops the LogicalIndex table """
        ## First destroy the object and then try to remove the index file
        del self.index
        try:
            os.remove(self.filename)
        except OSError:
            pass
        
        self.dbh.execute("drop table if exists `LogicalIndex_%s`",(self.table))
        ## Here we reset all reports that searched this disk
        FlagFramework.reset_all(case=self.dbh.case,report='SearchIndex', family='DiskForensics')
        self.dbh.execute("drop table if exists `LogicalKeyword_%s`",(self.table))

    def destroy(self):
        ## Destroy our index handle which will close the file and free memory
        del self.index
        
    class Scan:
        def __init__(self, inode,ddfs,outer,factories=None):
            self.index = outer.index
            self.inode=inode
            self.dbh=outer.dbh
            self.outer=outer
            self.outer.rel_offset=0
            self.outer.block+=1
            self.dbh.execute("insert into `LogicalIndex_%s` set inode=%r,block=%r",(outer.table,inode,self.outer.block))

        def process(self,data,metadata=None):
            self.index.index_buffer(self.outer.block << BLOCKSIZE + self.outer.rel_offset ,data)
            self.outer.rel_offset+=len(data)
            ## If the file is longer than a block, we create a new block, and adjust the relative offset
            if self.outer.rel_offset > pow(2,BLOCKSIZE):
                self.outer.block+=1
                self.outer.rel_offset -= pow(2,BLOCKSIZE)
                self.dbh.execute("insert into `LogicalIndex_%s` set inode=%r,block=%r",(self.outer.table,self.inode,self.outer.block))
                
        def finish(self):
            pass
#            self.outer.offset=self.offset
