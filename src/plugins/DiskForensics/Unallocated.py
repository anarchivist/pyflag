# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.78 Date: Fri Aug 19 00:47:14 EST 2005$
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
""" This module analyses unallocated and slack space.

Basically it creates Virutual File System (VFS) objects for each stream of unallocated space. Such streams are found at the end of allocated blocks (slack space) as well as completely unallocated blocks. The unallocated blocks are then searched for files using the Exgrep technique. If files are found in the unallocated vfs files, the new VFS nodes are created for them and they are further scanned.

This has the effect of locating zip files in unallocated space and recursively openning them, performing keyword searchs etc.
"""
import os.path
import pyflag.logging as logging
from pyflag.Scanner import *
import zipfile,gzip
from pyflag.FileSystem import File
import pyflag.FileSystem as FileSystem
import pyflag.DB as DB
import pyflag.Exgrep as Exgrep
import pyflag.Scanner as Scanner

#hidden = True

class UnallocatedScan(GenScanFactory):
    """ Scan unallocated space for files.

    Unallocated space is defined as slack space (the space between the end of a file and the next block alignments) as well as unallocated blocks. This does not include allocated blocks which simply do not have file entries (e.g. deleted files). Deleted files are handled in another scanner.
    """
    order=100
    default = False

    class Drawer(Scanner.FSSpecialisedDrawer):
        description = "Filesystem Specific Analysis"
        name = "Filesystem Analysis"
        contains = ['UnallocatedScan','DeletedScan']
        default = True
        special_fs_name = 'AutoFS'
        
    def reset(self):
        GenScanFactory.reset(self)
        self.dbh.execute("drop table if exists unallocated_%s" ,self.table)

    def prepare(self):
        """ Creates the unallocated VFS nodes at scanner initialisation.

        This works because scanners are invoked after all the physical Inodes are created in the blocks table - so we have visibility of allocated nodes. Note that VFS objects do not count since they typically do not have block allocations.
        """
        ## We remove older tables to ensure we always have the latest up to date table.
        self.dbh.execute("drop table if exists unallocated_%s" ,self.table)
        self.dbh.execute("CREATE TABLE unallocated_%s (`inode` VARCHAR(50) NOT NULL,`offset` BIGINT NOT NULL,`size` BIGINT NOT NULL)",self.table)
        unalloc_blocks = []

        ## We ask the filesystem whats the blocksize - if we dont know, we use 1
        try:
            blocksize=self.fsfd.blocksize
        except AttributeError:
            blocksize=1

        count=0
        ## Now we work out the unallocated blocks by looking at the blocks table:
        last = (0,0)
        self.dbh.execute("select * from block_%s order by block asc", self.table)
        dbh2 = self.dbh.clone()
        for row in self.dbh:
            ## We make a list of all blocks which are unallocated:
            ## This is the end of the unallocated block just before this one:
            new_block = ( last[0],row['block']-last[0])
            if new_block[1]>0:
                ## Add the offset into the db table:
                offset = new_block[0] * blocksize
                size = new_block[1] * blocksize
                dbh2.execute("insert into unallocated_%s set inode='U%s',offset=%r,size=%r",(
                    self.table, count, offset, size))

                ## Add a new VFS node:
                self.fsfd.VFSCreate(None,'U%s' % count, "/_unallocated_/%s" % offset, size=size)
                count+=1
                unalloc_blocks.append(new_block)

            last=(row['block']+row['count'],0,row['inode'])

        ## Now we need to add the last unalloced block. This starts at
        ## the last allocated block, and finished at the end of the IO
        ## source. The size of -1 makes the VFS driver keep reading till the end.
        offset = last[0] * blocksize
        dbh2.execute("insert into unallocated_%s set inode='U%s',offset=%r,size=%r", (self.table,count,offset, -1))

        ## Add a new VFS node:
        self.fsfd.VFSCreate(None,'U%s' % count, "/_unallocated_/%s" % offset)


    class Scan(BaseScanner):                
        def process(self,data,metadata=None):
            ## We only scan top level Unallocated inodes
            if self.inode.startswith('U') and "|" not in self.inode:
                for cut in Exgrep.process_string(data):
                    ## Create a VFS node:
                    offset = cut['offset']+self.fd.tell()
                    self.outer.fsfd.VFSCreate(self.inode,'U%s' % offset,"%s.%s" % (offset,cut['type']),size=cut['length'])
                    self.outer.dbh.execute("insert into unallocated_%s set inode='%s|U%s',offset=%r,size=%r" , (self.outer.table,self.inode,offset,offset,cut['length']))

                    ## Now scan the newfound file:
                    fd = self.ddfs.open(inode='%s|U%s' % (self.inode,offset))
                    tmp = fd.read(100)
                    fd.seek(0)
                    Scanner.scanfile(self.ddfs,fd,self.factories)
                ## End of for
                
        def finish(self):
            pass

## Deleted files scanner:
class DeletedScan(GenScanFactory):
    """ Create VFS nodes for deleted files.

    Deleted files are those which are allocated by the filesystem, but do not have a file entry. This makes them impossible to view through the normal GUI. By creating file table entries for those it is possible to view these inodes using the same GUI.
    """
    order=5
    default=True
    def prepare(self):
        """ Create the extra file entries in the file table.

        This scanner just inserts more entries into the file table. This means it needs intimate knowledge of the file/inode schema (rather than using the VFSCreate API). Since this scanner needs to have intimate knowledge of the schema to work out which inodes are deleted, this is probably ok. By inserting extra file entries, we dont need to have a VFS driver too. 
        """
        ## We may only execute this scanner once per filesystem:
        if not self.dbh.get_meta("deleted_scan_%s" % self.table):
            ## Create a deleted directory entry:
            dbh2=self.dbh.clone()
            self.dbh.execute("insert into file_%s set  inode='D0',mode='d/d',status='alloc',path='/',name='_deleted_'",self.table)
            self.dbh.execute("insert into inode_%s set  inode='D0', links=3,mode=40755 ,gid=0,uid=0",self.table)
            ## This will give us all the inodes which appear in the blocks
            ## table (i.e. they are allocated), but do not appear in the
            ## file table (i.e. do not have a filename).
            self.dbh.execute("select a.inode as inode from block_%s as a left join file_%s as b on a.inode=b.inode where isnull(b.inode) group by a.inode",(self.table,self.table))
            for row in self.dbh:
                dbh2.execute("insert into file_%s set inode=%r,mode='r/r',status='alloc',path='/_deleted_/',name=%r",(self.table,row['inode'],row['inode']))

            self.dbh.set_meta("deleted_scan_%s" % self.table,"Scanned")

## Unallocated space VFS Driver:
class Unallocated_File(FileSystem.File):
    """ A VFS driver for reading unallocated space off the disk.

    This driver reads the offset from the unallocated table which was previously prepared by the unallocated scanner.
    """
    specifier = 'U'
    
    def __init__(self,case,table,fd,inode):
        File.__init__(self, case, table, fd, inode)
        self.fd=fd
        self.dbh = DB.DBO(case)
        self.dbh.execute("select * from unallocated_%s where inode=%r",(table,inode))
        row=self.dbh.fetch()
        try:
            self.size=row['size']
            self.offset=row['offset']
        except KeyError:
            raise IOError

    def read(self,length=None):
        if self.size>0:
            if (length == None) or ((length + self.readptr) > self.size):
                length = self.size - self.readptr

            if length == 0:
                return ''
        else:
            if length==None:
                raise IOError("Unable to read entire IO source into memory")

        self.fd.seek(self.readptr+self.offset)
        result =self.fd.read(length)
        self.readptr+=len(result)
        return result
