# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Name:  $ $Date: 2004/10/23 15:48:12 $
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

""" Module contains classes used to access filesystems loaded into the database.

When Flag loads a filesystem into the database, meta information about inodes, files and their allocation is stored within the database. The specific implementation of how this information is stored is abstracted here by use of the FileSystem object. The FileSystem object presents a well defined API to allow callers to query the case database about the filesystem.

The FileSystem class is an abstract class which is implemented as derived classes. Users of this class need to call the FS_Factory to get a concrete implementation. The implementation deals with representing the directory structure, and provides access to the files within the filesystem.

The File class abstracts an interface for accessing the data within a specific file inside the filesystem. Although this is very similar to the standard python file-like interface, there are some minor differences.

In order for callers to have access to a specific file on the filesystem, they need to instantiate a FileSystem object by using FS_Factory, and then ask this instance for a File object by using the FileSystem.open method. It is discouraged to instantiate a File object directly.

"""
import os,os.path
import pyflag.conf
config=pyflag.conf.ConfObject()

import pyflag.DB as DB
import pyflag.IO as IO
import pyflag.FlagFramework as FlagFramework
import pyflag.logging as logging
import time
import math
import bisect
import zipfile
import cStringIO

class FileSystem:
    """ This is the base class for accessing file systems in PyFlag. This class is abstract and is here purely for documentation purposes """
    def __init__(self, case, table, fd):
        """ Constructor for creating an new filesystem object """
        pass
    
    def longls(self,path='/'):
        """ list directory content longly """
        pass

    def ls(self, path="/", dirs=None):
        """list directory contents"""
        pass

    def dent_walk(self, path='/'):
        """A generator which returns directory entries under the given path, one at a time """
        pass

    def lookup(self, path=None,inode=None):
        """return the inode number for the given path, or else the path for the given inode number. """
        pass

    def open(self, path=None, inode=None):
        """ Opens the specified path or Inode providing a file like object.

        This object can then be used to read data from the specified file.
        @note: Only files may be opened, not directories."""
        pass

    def istat(self, path=None, inode=None):
        """ return a dict with information (istat) for the given inode or path. """
        pass

    def isdir(self,directory):
        """ Returns 1 if directory is a directory, 0 otherwise """
        pass

    def exists(self,path):
        """ Returns 1 if path exists, 0 otherwise """
        pass

    
    def scanfs(self, callbacks):
        """ Read every file in fs, and call given scanner callbacks for each file.
        
        callbacks is a list of scanner classes derived from Scanner.GenScan. These classes
        have a process and finish methods.
        For each file, scanfs will create a new object of each of the given classes,
        then begin reading the file in buffers of (say) 1MB, each time calling the 
        process method of each of the new objects with the buffer just read.
        When all data has been read from the file, scanfs will call the finished method of each object.
        It will then start over with the next file.
        
        The purpose of this method is to do all analysis which must read file data in one place
        for performance, currently this includes file typing, file hashing and virus scanning"""
        pass
    

class DBFS(FileSystem):
    """ Class for accessing filesystems using data in the database """
    def __init__(self, case, table, fd):
        """ Initialise the DBFS object """
        self.fd = fd
        self.table = table
        self.case = case
        self.dbh = DB.DBO(case)

    def longls(self,path='/'):
        self.dbh.execute("select mode,inode,name from file_%s where path=%r", (self.table, path))
        return [ dent for dent in self.dbh ]
    
    def ls(self, path="/", dirs=None):
        if(dirs == 1):
            self.dbh.execute("select name from file_%s where path=%r and mode='d/d'", (self.table, path))
        elif(dirs == 0):
            self.dbh.execute("select name from file_%s where path=%r and mode='r/r'", (self.table, path))
        else:
            self.dbh.execute("select name from file_%s where path=%r", (self.table, path))
        return [ dent['name'] for dent in self.dbh ]

    def dent_walk(self, path='/'):
        self.dbh.execute("select name, mode, status from file_%s where path=%r order by name" % (self.table, path))
        for i in self.dbh:
            yield(i)
    
    def lookup(self, path=None,inode=None):
        if path:
            dir,name = os.path.split(path)
            if not name:
                dir,name = os.path.split(path[:-1])
            if dir == '/':
                dir = ''

            self.dbh.execute("select inode from file_%s where path=%r and (name=%r or name=concat(%r,'/'))", (self.table,dir+'/',name,name))
            res = self.dbh.fetch()
            if not res:
                return None
            return res["inode"]
        else:
            self.dbh.execute("select concat(path,name) as path from file_%s where inode=%r", (self.table,inode))
            res = self.dbh.fetch()
            if not res:
                return None
            return res["path"]
    
    def open(self, path=None, inode=None):
        if not inode:
            inode = self.lookup(path)
        if not inode:
            raise IOError('Inode not found for file')

        ## Find out which handler is required for this file:
        try:
            ## If the inode is special it is of the form inode - type - descriptor. type is Z for zips
            temp = inode.split('|')
            if temp[-2] == 'Z':
                file=DBFS_file(self.case,self.table,self.fd,temp[0])
                return Zip_file(self.case,self.table,file,'|'.join(temp[:-2]),temp[-1])
        except IndexError:
            pass

        return DBFS_file(self.case, self.table, self.fd, inode)

    def istat(self, path=None, inode=None):
        if not inode:
            inode = self.lookup(path)
        if not inode:
            return None
        self.dbh.execute("select inode, status, uid, gid, from_unixtime(mtime) as `mtime`, from_unixtime(atime) as `atime`, from_unixtime(ctime) as `ctime`, from_unixtime(dtime) as `dtime`, mode, links, link, size from inode_%s where inode=%r",(self.table, inode))
        return self.dbh.fetch()

    def isdir(self,directory):
        if not directory.endswith('/'):
            directory+='/'
        self.dbh.execute("select mode from file_%s where path=%r",(self.table,directory))
        row=self.dbh.fetch()
        if row:
            return 1
        else:
            return 0
        
    def exists(self,path):
        dir,file=os.path.split(path)
        self.dbh.execute("select mode from file_%s where path=%r and name=%r",(self.table,dir,file))
        row=self.dbh.fetch()
        if row:
            return 1
        else:
            return 0

    def scanfile(self,fd,factories,inode):
        """ Given a file object and a list of factories, this function scans this file using the given factories """
        buffsize = 1024 * 1024
        # instantiate a scanner object from each of the factory
        objs = [c.Scan(inode,self,self.dbh,self.table,factories=factories) for c in factories]
        # read data (in chunks)
        while 1:
            ## This dict stores metadata about the file which may be filled in by some scanners in order to indicate some fact to other scanners.
            metadata = {}
            ## If the file is too fragmented, we skip it because it might take too long... NTFS is a shocking filesystem, with some files so fragmented that it takes a really long time to read them. In our experience these files are not important for scanning so we disable them here. Maybe this should be tunable?
            try:
                if len(fd.blocks)>1000 or fd.size>100000000:
                    return

                c=0
                for i in fd.blocks:
                    c+=i[1]

                ## If there are not enough blocks to do a reasonable chunk of the file, we skip them as well...
                if c>0 and c*fd.block_size<fd.size:
                    print "Skipping inode %s because there are not enough blocks %s < %s" % (fd.inode,c*fd.block_size,fd.size)
                    return
                
            except AttributeError:
                pass
            
            try:
                data = fd.read(buffsize)
                if not data: break
            except IOError:
                break
            # call process method of each class
            for o in objs:
                o.process(data,metadata=metadata)

        fd.close()
        # call finish object of each method
        for o in objs:
                o.finish()

    def scanfs(self, scanners, action=None):
        dbh2 = DB.DBO(self.case)
        dbh3=DB.DBO(self.case)
        # Instatiate a factory class for each of the given scanners
        factories = [ d(self.dbh,self.table) for d in scanners ]

        ## If the user asked to reset the scanners we do so here
        if action=='reset':
            for i in factories:
                try:
                    i.reset()
                except DB.DBError:
                    pass
            return

#        dbh3.execute('select inode, concat(path,name) as filename from file_%s where mode="r/r" and status="alloc" and inode not like "%%-Z-%%"',self.table)
        dbh3.execute('select inode, concat(path,name) as filename from file_%s where mode="r/r" and status="alloc"',self.table)
        count=0
        for row in dbh3:
            # open file
            count+=1
            if not count % 100:
                print "File (%s) is inode %s (%s)" % (count,row['inode'],row['filename'])
                
            try:
                fd = self.open(inode=row['inode'])
                self.scanfile(fd,factories,row['inode'])
            except Exception,e:
                logging.log(logging.ERRORS,"%r: %s" % (e,e))
                continue
        
        for c in factories:
            c.destroy()

class MountedFS(DBFS):
    """ This class implements FS access for mounted directories on the host """
    def open(self, path=None, inode=None):
        if not path:
            self.dbh.execute("select path,name from file_%s where inode=%r",(self.table, inode))
            row=self.dbh.fetch()
            path=row['path']+"/"+row['name']
        
        return MountedFS_file(self.case, self.table, self.fd, inode,os.path.normpath(self.fd.mount_point+path))

class File:
    """ This abstract base class documents the file like object used to read specific files in PyFlag. """
    def __init__(self, case, table, fd, inode):
        """ The constructor for this object.

        @note: This is not meant to be called directly, the File object must be created by a valid FileSystem object's open method.
        """
        pass

    def close(self):
        """ Fake close method. """
        pass
    
    def seek(self, offset, rel=None):
        """ Seeks to a specified position inside the file """
        pass
    
    def read(self, length=None):
        """ Reads length bytes from file, or less if there are less bytes in file. If length is None, returns the whole file """
        pass

    def tell(self):
        """ returns the current read pointer"""
        pass
    
class DBFS_file(File):
    """ Class for reading files within a loaded dd image, supports typical file-like operations, seek, tell, read """
    def __init__(self, case, table, fd, inode):
        self.dbh = DB.DBO(case)
        self.inode=inode
        self.fd = fd
        self.table = table
        self.readptr = 0
        try:
            self.dbh.execute("select value from meta_%s where name='block_size'",self.table);
            self.block_size = int(self.dbh.fetch()["value"])
        except TypeError:
            pass
        # fetch inode data
        self.dbh.execute("select * from inode_%s where inode=%r and status='alloc'", (self.table, inode))
        self.data = self.dbh.fetch()
        if not self.data:
            raise IOError("Could not locate inode %s"% inode)

        self.size = self.data['size']
        self.dbh.execute("select block,count,`index` from block_%s where inode=%r order by `index`", (self.table, inode))
        try:
            self.blocks = [ (row['block'],row['count'],row['index']) for row in self.dbh ]
        except KeyError:
            self.blocks = None
        self.index = [ d[2] for d in self.blocks ]
        
    def getval(property):
        try:
            return self.data[property]
        except KeyError:
            return None
        
    def seek(self, offset, rel=None):
        """ fake seeking routine, doesnt really seek, just updates the read pointer """
        if(rel):
            self.readptr += offset
        else:
            self.readptr = offset
        if(self.readptr > self.size):
            self.readptr = self.size

    def read(self, length=None):
        if (length == None) or ((length + self.readptr) > self.size):
            length = self.size - self.readptr

        if length == 0:
            return ''

        if not self.blocks:
            # now try to find blocks in the resident table
            self.dbh.execute("select data from resident_%s where inode=%r" % (self.table, self.data['inode']));
            row = self.dbh.fetch()
            if not row:
                raise IOError("Cant find any file data")
            data = row['data'][self.readptr:length+self.readptr]
	    self.readptr += length
	    return data

        fbuf=''
        while length>0:
        ## Where are we in the chunk?
            ddoffset,bytes_left = self.offset(self.readptr)
            
            self.fd.seek(ddoffset)
            if(bytes_left > length):
                fbuf += self.fd.read(length)
                self.readptr+=length
                return fbuf
            else:
                fbuf += self.fd.read(bytes_left)
                length-=bytes_left
                self.readptr+=bytes_left

        return fbuf
     
    def tell(self):
        return self.readptr

    def offset(self,offset):
        """ returns the offset into the current block group where the given offset is found"""
        ## The block in the file where the offset is found
        block = int(offset/self.block_size)

        ##Obtain the index of blocks array where the chunk is. This is the index at which self.index is 
        blocks_index=0
        try:
            while 1:
                if self.index[blocks_index]<=block<self.index[blocks_index+1]: break
                blocks_index+=1

        except IndexError:
            blocks_index=len(self.index)-1

        #If the end of the chunk found occurs before the block we seek, there is something wrong!!!
        if self.blocks[blocks_index][1]+self.blocks[blocks_index][2]<=block:
            raise IOError("Block table does not span seek block %s"%block,offset)

        ## Look the chunk up in the blocks array
        ddblock,count,index=self.blocks[blocks_index]

        ## The offset into the chunk in bytes
        chunk_offset = offset-index*self.block_size

        ## The dd offset in bytes
        ddoffset=ddblock*self.block_size+chunk_offset

        ## The number of bytes remaining in this chunk
        bytes_left = count*self.block_size-chunk_offset
        
        return ddoffset,bytes_left

class MountedFS_file(DBFS_file):
    def __init__(self, case, table, fd, inode, path):
#        DBFS_file.__init__(self,case, table, fd, inode)
        self.fd=open(path)
    
    def close(self):
        self.fd.close()

    def seek(self, offset, rel=None):
        if rel:
            self.fd.seek(offset,1)
        else:
            self.fd.seek(offset)

    def read(self, length=None):
        if length:
            return self.fd.read(length)
        else:
            return self.fd.read()

    def tell(self):
        return self.fd.tell()

class Zip_file(File):
    """ A file like object to read files from within zip files. Note that the zip file is specified as an inode in the DBFS """
    blocks=()
    
    def __init__(self,case,table,file,inode,sub_inode):
        ## Find the filename relative to the zip file:
        self.dbh=DB.DBO(case)
        self.case=case
        self.table=table
        self.dbh.execute("select concat(path,name) as filename from file_%s where inode=%r",(table,inode))
        zipfilename=self.dbh.fetch()['filename']
        self.dbh.execute("select concat(path,name) as filename from file_%s where inode='%s|Z|%s'",(table,inode,sub_inode))
        filename=self.dbh.fetch()['filename']

        if not filename.startswith(zipfilename): raise FlagFramework.FlagException("Error in tables: %s does not start with %s" %(filename,zipfilename))
        filename=filename[len(zipfilename)+1:]

        ## Handle recursive files:
        temp = inode.split('|')
        try:
            if temp[-2] == 'Z':
                f=Zip_file(self.case,self.table,file,'|'.join(temp[:-2]),temp[-1])
                fd=cStringIO.StringIO(f.read())
                z=zipfile.ZipFile(fd)
                self.data=z.read(filename)
                
        except Exception,e:
            z=zipfile.ZipFile(file)
            self.data=z.read(filename)
            
        self.pos=0
        self.size=len(self.data)
        
    def read(self,len=None):
        if len:
            temp=self.data[self.pos:self.pos+len]
            self.pos+=len
            return temp
        else: return self.data

    def close(self):
        pass
        
    def seek(self,pos):
        self.pos=pos


def FS_Factory(case,table,fd):
    """ This is the filesystem factory, it will create the most appropriate filesystem object available.

    @arg case: Case to use
    @arg table: The base name for all tables
    @arg fd: An already open iosource
    """
    ## If the iosource is special we handle it here:
    class_name = (("%s" % fd.__class__).split("."))[-1]
    if class_name== "mounted":
        return MountedFS(case,table,fd)
    else:
        return DBFS(case,table,fd)
