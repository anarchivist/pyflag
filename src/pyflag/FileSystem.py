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
#  Version: FLAG $Version: 0.80.1 Date: Tue Jan 24 13:51:25 NZDT 2006$
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

The FileSystem class is an abstract class which is implemented as derived classes. FileSystems implement this abstract class in plugins which are then registered in the registry. Users of this class need to use the registry to get specific implementations. The implementation deals with representing the directory structure, and provides access to the files within the filesystem.

The File class abstracts an interface for accessing the data within a specific file inside the filesystem. Although this is very similar to the standard python file-like interface, there are some minor differences.

In order for callers to have access to a specific file on the filesystem, they need to instantiate a FileSystem object by using the Registry, and then ask this instance for a File object by using the FileSystem.open method. It is discouraged to instantiate a File object directly.

Virtual Filesystems (vfs) are also supported by this subsystem in order to support archives such as zip and pst files. Files within filesystems are uniquely identified in the flag databases by an inode string. The inode string can have multiple parts delimited by the pipe ('|') character indicating that a virtual filesystem is to be used on the file. The first letter in the part indicates the virtual filesystem to use, here is an example:
'D123|Z14' Here 'D' indicates the DBFS filesystem, Z indicates the Zip vfs.
This inode therefore refers to the 14th file in the zip archive contained in inode 123 of the DBFS filesystem. VFS modules are also obtained using the registry.

Note that typically VFS modules go hand in hand with scanners, since scanner discover new files, calling VFSCreate on the filesystem to add them, and VFS drivers are used to read those from the Inode specifications.
"""
import os,os.path
import pyflag.conf
config=pyflag.conf.ConfObject()

import pyflag.DB as DB
import pyflag.IO as IO
import pyflag.FlagFramework as FlagFramework
from pyflag.FlagFramework import normpath
import pyflag.Registry as Registry
import pyflag.logging as logging
import time
import math
import bisect
import zipfile
import cStringIO
import pyflag.Scanner as Scanner

class FileSystem:
    """ This is the base class for accessing file systems in PyFlag. This class is abstract and is here purely for documentation purposes.

    @cvar name: The name of the filesystem to show in the loadfs dialog
    """
    def __init__(self, case, table, iosource):
        """ Constructor for creating an new filesystem object

        @arg case: Case to use
        @arg table: The base name for all tables
        @arg iosource: An already open data source, may be iosource, or another 'File'
        """
        pass
    
    name = None
    
    def load(self):
        """ This method loads the filesystem into the database.

        Currently the database schema is standardised by the DBFS class, and all other filesystems just extend the load method to implement different drivers for loading the filesystem into the database. For reading and manipulating the filesystem, the DBFS methods are used.
        """
        pass

    def delete(self):
        """ This method should remove the database which contains the filesystem """
        pass
    
    def longls(self,path='/'):
        """ list directory content longly """
        pass

    def VFSCreate(self,root_inode,inode):
        """ This method creates inodes within the virtual filesystem.

        This facility allows callers to extend the VFS to include more virtual files.
        """

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

        if not inode:
            inode = self.lookup(path)
        if not inode:
            raise IOError('Inode not found for file')

        ## We should be allowed to open inodes which do not exist in
        ## the filesystem proper, but the VFS may be able to do
        ## something with them -- all it means is that we cant really
        ## navigate to them.
#        if not path:
#            path = self.lookup(inode=inode)
#        if not path:
#            raise IOError('File not found for inode %s' % inode)

        # open the file, first pass will generally be 'D' or 'M'
        # then any virtual file systems (vfs) will kick in
        parts = inode.split('|')
        sofar = [] # the inode part up to the file we want
        ## We start with the FileSystem iosource as the file like object for use, and then as each file is opened, we update retfd.
        retfd = self.iosource
        for part in parts:
            sofar.append(part)
            try:
                retfd = Registry.VFS_FILES.vfslist[part[0]](self.case, self.table, retfd, '|'.join(sofar))
            except IndexError:
                raise IOError, "Unable to open inode: %s, no VFS" % part

        return retfd

    def istat(self, path=None, inode=None):
        """ return a dict with information (istat) for the given inode or path. """
        pass

    def isdir(self,directory):
        """ Returns 1 if directory is a directory, 0 otherwise """
        pass

    def exists(self,path):
        """ Returns 1 if path exists, 0 otherwise """
        pass

    def resetscanfs(self,callbacks):
        """ This is called to reset all the scanners. """
        
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
    def __init__(self, case, table, iosource):
        """ Initialise the DBFS object """
        self.iosource=iosource
        self.table = table
        self.case = case
        self.dbh = DB.DBO(case)
        try:
            self.dbh.execute("select value from meta_%s where name='block_size'",self.table);
            self.blocksize = int(self.dbh.fetch()["value"])
        except:
            self.blocksize = 1024

    def load(self):
        """ Sets up the schema for loading the filesystem.

        Note that derived classes need to actually do the loading
        after they call the base class.
        """
        sdbh = DB.DBO(self.case)
        sdbh.MySQLHarness("%s/dbtool -t %s -d create blah" %(config.FLAG_BIN,self.table))

    def delete(self):
        dbh = DB.DBO(self.case)
        dbh.MySQLHarness("%s/dbtool -t %s -d drop" %(config.FLAG_BIN,self.table))

    def VFSCreate(self,root_inode,inode,new_filename,directory=False ,gid=0, uid=0, mode=100777, **properties):
        """ Extends the DB filesystem to include further virtual filesystem entries.

        Note that there must be an appropriate VFS driver for the added inodes, or else they may not be viewable.
        @arg root_inode: The inode that will serve as the root for the new inode. If None, we create a root Inode.
        @arg inode: The proposed inode name for the new inode (without the | to the root_inode). This needs to be understood by the VFS driver.
        @arg new_filename: The prposed new filename for the VFS file. This may contain directories in which case sub directories will also be created.
        @arg directory: If true we create a directory node.
        """
        ## filename is the filename in the filesystem for the parent directory.
        if root_inode:
            filename = self.lookup(inode=root_inode)
        else:
            filename = '/'

        ## Check if the directories all exist properly:
        dirs = os.path.dirname(new_filename).split('/')
        name = os.path.basename(new_filename)

        ## This creates subdirectories for node if they are missing.
        for d in range(len(dirs)):
            if not dirs[d]: continue
            if d>0:
                path = normpath("%s/%s/" % (filename,"/".join(dirs[:d])))
            else:
                path = normpath("%s/" % filename)

            self.dbh.execute("select * from file_%s where path=%r and name=%r and mode='d/d'",(self.table, path, dirs[d]))
            if not self.dbh.fetch():
                ## Directory does not exist, so we need to create it:
                if root_inode != None:
                    self.dbh.execute("insert into file_%s set path=%r,name=%r,status='alloc',mode='d/d',inode='%s|%s-'",(self.table,path,dirs[d],root_inode,inode))
#                    self.dbh.execute("update inode_%s  set mode=%r, links=%r where inode=%r",(self.table,40755, 3,inode))
                    self.dbh.execute("insert into inode_%s  set mode=%r, links=%r , inode='%s|%s-',gid=0,uid=0,size=1",(self.table,40755, 4,root_inode,inode))
                else:
                    self.dbh.execute("insert into file_%s set path=%r,name=%r,status='alloc',mode='d/d',inode='%s-'",(self.table,path,dirs[d],inode))
                    self.dbh.execute("insert into inode_%s  set mode=%r, links=%r , inode='%s-',gid=0,uid=0,size=1",(self.table,40755, 4,inode))
                    
        path = normpath("%s/%s/" % (filename,os.path.dirname(new_filename)))
        ## Add the file itself to the file table (only if name was specified)
#      if not name: return
        
        if root_inode:
            self.dbh.execute("insert into file_%s set status='alloc',mode='r/r',inode='%s|%s',path=%r, name=%r",(self.table,root_inode,inode,normpath(path+'/'),name))
        else:
            self.dbh.execute("insert into file_%s set status='alloc',mode='r/r',inode='%s',path=%r, name=%r",(self.table,inode,normpath(path+'/'),name))

        ## Add the file to the inode table:
        extra = ','.join(["%s=%%r" % p for p in properties.keys()])
        if extra:
            extra=','+extra

        if root_inode!=None:
            self.dbh.execute("insert into inode_%s set inode='%s|%s',mode=%s,links=4,gid=%s,uid=%s" + extra ,[self.table, root_inode,inode,mode,gid,uid] + properties.values())
        else:
            self.dbh.execute("insert into inode_%s set inode='%s',mode=%s,links=4,gid=%s,uid=%s" + extra ,[self.table, inode,mode,gid,uid] + properties.values())
        
        ## Set the root file to be a d/d entry so it looks like its a virtual directory:
        self.dbh.execute("select * from file_%s where mode='d/d' and inode=%r and status='alloc'",(self.table,root_inode))
        if not self.dbh.fetch():
            self.dbh.execute("select * from file_%s where mode='r/r' and inode=%r and status='alloc'",(self.table,root_inode))
            row = self.dbh.fetch()
            if row:
                self.dbh.execute("insert into file_%s set mode='d/d',inode=%r,status='alloc',path=%r,name=%r",(self.table,root_inode,row['path'],row['name']))
                self.dbh.execute("update inode_%s  set mode=%r, links=%r where inode=%r",(self.table,40755, 3,root_inode))

    def longls(self,path='/', dirs = None):
        if self.isdir(path):
            ## If we are listing a directory, we list the files inside the directory            
            if not path.endswith('/'):
                path=path+'/'

            where =" path=%r " % path
        else:
            ## We are listing the exact file specified:
            where =" path=%r and name=%r" %  (os.path.dirname(path)+'/' , os.path.basename(path))
                   
        mode =''
        if(dirs == 1):
            mode=" and mode like 'd%'"
        elif(dirs == 0):
            mode=" and mode like 'r%'"

        self.dbh.execute("select path,mode,inode,name from file_%s where %s %s", (self.table, where, mode))

        ## This is done rather than return the generator to ensure that self.dbh does not get interfered with...
        return [dent for dent in self.dbh]
    
    def ls(self, path="/", dirs=None):
        return [ dent['name'] for dent in self.longls(path,dirs) ]

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
            self.dbh.execute("select concat(path,name) as path from file_%s where inode=%r order by status", (self.table,inode))
            res = self.dbh.fetch()
            if not res:
                return None
            return res["path"]
        
    def istat(self, path=None, inode=None):
        if not inode:
            inode = self.lookup(path)
        if not inode:
            return None
        self.dbh.execute("select inode, status, uid, gid, mtime as mtime_epoch, from_unixtime(mtime) as `mtime`, atime as atime_epoch, from_unixtime(atime) as `atime`, ctime as ctime_epoch, from_unixtime(ctime) as `ctime`, from_unixtime(dtime) as `dtime`, mode, links, link, size from inode_%s where inode=%r",(self.table, inode))
        return self.dbh.fetch()

    def isdir(self,directory):
        directory=os.path.normpath(directory)
        if directory=='/': return 1
        
        dirname=FlagFramework.normpath(os.path.dirname(directory)+'/')
        self.dbh.execute("select mode from file_%s where path=%r and name=%r and mode like 'd%%' ",(self.table,dirname,os.path.basename(directory)))
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

    def resetscanfs(self,scanners):
        for i in scanners:
            try:
                i.reset()
            except DB.DBError,e:
                logging.log(logging.ERRORS,"Could not reset Scanner %s: %s" % (i,e))
        
    def scanfs(self, scanners, action=None):
        ## Prepare the scanner factory for scanning:
        for s in scanners:
            s.prepare()
        
        dbh2 = DB.DBO(self.case)
        dbh3=DB.DBO(self.case)

        dbh3.execute('select inode, concat(path,name) as filename from file_%s where mode="r/r" and status="alloc"',self.table)
        count=0
        for row in dbh3:
            # open file
            count+=1
            if not count % 100:
                logging.log(logging.INFO,"File (%s) is inode %s (%s)" % (count,row['inode'],row['filename']))
                
            try:
                fd = self.open(inode=row['inode'])
                Scanner.scanfile(self,fd,scanners)
                fd.close()
            except Exception,e:
                logging.log(logging.ERRORS,"%r: %s" % (e,e))
                continue
        
        for c in scanners:
            c.destroy()

class File:
    """ This abstract base class documents the file like object used to read specific files in PyFlag.

    @cvar stat_cbs: A list of callbacks that should be used to render specific statistics displays about this file. These are basically callbacks for the notebook interface cb(query,result).
    @cvar stat_names: A list of names for the above callbacks.
    """
    specifier = None
    ## These can be overridden by the caller if they want to add stats to the ViewFile report
    #stat_cbs = None
    #stat_names = None
    
    def __init__(self, case, table, fd, inode):
        """ The constructor for this object.
        @arg case: Case to use
        @arg table: The base name for all tables
        @arg fd: An already open data source, may be iosource, or another 'File'
        @arg inode: The inode of the file to open, the while inode ending with the part relevant to this vfs
        @note: This is not meant to be called directly, the File object must be created by a valid FileSystem object's open method.
        """
        # each file should remember its own part of the inode
        self.case = case
        self.table = table
        self.fd = fd
        self.inode = inode
        self.readptr =0
        self.size=0
        self.dbh=DB.DBO(case)

    def close(self):
        """ Fake close method. """
        pass
    
    def seek(self, offset, rel=None):
        """ Seeks to a specified position inside the file """
        if rel==1:
            self.readptr += offset

        ## Seek relative to size
        elif rel==2:
            self.readptr = self.size + offset
        else:
            self.readptr = offset
            
        if(self.size>0 and self.readptr > self.size):
            self.readptr = self.size

        if self.readptr<0: self.readptr=0
        
        return self.readptr
         
    def tell(self):
        """ returns the current read pointer"""
        return self.readptr

    def read(self, length=None):
        """ Reads length bytes from file, or less if there are less bytes in file. If length is None, returns the whole file """
        pass

    def stats(self):
        """ Returns a dict of statistics about the content of the file. """
        pass

    def __iter__(self):
        self.seek(0)
        return self

    def next(self):
        data=self.read(1024*1024)
        if len(data)!=0:
            return data
        else:
            raise StopIteration

    def readline(self,delimiter='\n'):
        """ Emulates a readline by reading upto the \n """
        buffer = ''
        start = self.tell()
        while 1:
            try:
                o = buffer.index(delimiter)+1
                self.seek(start+o)
                return buffer[:o]
            except ValueError:
                data=self.read(256)
                if len(data)==0: return buffer
                buffer += data

class CachedFile(File):
    """ This class is used to give a VFS driver automatic file caching capability. This should speed it up if re-creating the file on the fly is too expensive.

    To use, inherit from this class as well as the class you wish to cache and set target_class to the VFS driver. E.g:
    class CachedStreamFile(CachedFile,StreamFile):
        specifier = 'S'
        target_class = StreamFile

    """
    cached_fd = None
    target_class = None
    
    def get_temp_path(self):
        """ Returns the full path to a temporary file based on filename.
        """
        filename = self.inode.replace('/','-')
        result= "%s/case_%s/%s" % (config.RESULTDIR,self.case,filename)
        return result

    def __init__(self, case, table, fd, inode):
        File.__init__(self, case, table, fd, inode)

        cached_filename = self.get_temp_path()
        try:
            ## open the previously cached copy
            self.cached_fd = open(cached_filename,'r')

            ## Find our size:
            self.cached_fd.seek(0,2)
            self.size=self.cached_fd.tell()
            
        except IOError,e:
            ## It does not exist: Create a new cached copy:
            fd = open(cached_filename,'w')

            try:
                self.size=self.cache(fd)
                ## If we can not open the original file, we bail
            except:
                os.unlink(cached_filename)
                raise
                
            ## Reopen file for reading
            self.cached_fd = open(cached_filename,'r')

        self.cached_fd.seek(0)
        self.readptr=0

    def cache(self,fd):
        """ Creates the cache file given by fd.

        Note the fd is already open for writing, we just need to write into it.
        @return: the total size of the written file.
        """
        ## Init ourself:
        self.target_class.__init__(self,self.case,self.table,self.fd,self.inode)
        
        size=0
        ## Copy ourself into the file
        while 1:
            data=self.target_class.read(self,1024*1024)
            if len(data)==0: break
            fd.write(data)
            size+=len(data)
            
        return size
        
    def read(self,length=None):
        if not self.cached_fd:
            self.cache()

        if length!=None:
            ## The amount of data available to read:
            available = self.size-self.readptr
            
            if length>available:
                length=available
                
            result=self.cached_fd.read(length)
        else:
            result=self.cached_fd.read(self.size-self.readptr)

        self.readptr+=len(result)
        return result

    def readline(self):
        if not self.cached_fd:
            self.cache()
            
        result=self.cached_fd.readline()
        self.readptr+=len(result)
        return result

    def tell(self):
        if not self.cached_fd:
            self.cache()

        return self.readptr

    def seek(self,offset,whence=0):
        if not self.cached_fd:
            self.cache()

        if whence==0:
            self.readptr=offset
        elif whence==1:
            self.readptr+=offset
        elif whence==2:
            self.readptr=self.size+offset
    
        self.cached_fd.seek(self.readptr)
