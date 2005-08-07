# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.76 Date: Sun Apr 17 21:48:37 EST 2005$
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
""" This module provides support for compressed file formats such as Zip and Gzip.

The scanner recurses into zip files, executing the scanner factory train on files within the ZIP file.

This feature complements the ZIP and Gzip filesystem driver to ensure that zip and gzip files are transparently viewable by the FLAG GUI.
"""
import os.path
import pyflag.logging as logging
from pyflag.Scanner import *
import zipfile,gzip,tarfile
from pyflag.FileSystem import File , CachedFile
import pyflag.FlagFramework as FlagFramework
import time,re,os
import StringIO
import pyflag.Scanner as Scanner
import gzip

class ZipScan(GenScanFactory):
    """ Recurse into Zip Files """
    order=99
    default = True
    depends = 'TypeScan'
    
    def destroy(self):
        pass
    
    class Scan(StoreAndScanType):
        types = (
            'application/x-zip',
            )

        def external_process(self,name):
            """ This is run on the extracted file """
            zip=zipfile.ZipFile(name)
            
            ## List all the files in the zip file:
            dircount = 0
            namelist = zip.namelist()
            for i in range(len(namelist)):
                ## Add the file into the VFS
                try:
                    ## Convert the time to a common format.
                    t = time.mktime(list(zip.infolist()[i].date_time) +[0,0,0])
                except:
                    t=0

                ## If the entry corresponds to just a directory we ignore it.
                if not os.path.basename(namelist[i]): continue

                self.ddfs.VFSCreate(self.inode,"Z%s" % i,namelist[i],size=zip.infolist()[i].file_size,mtime=t)

                ## Now call the scanners on this new file (FIXME limit the recursion level here)
                fd = StringIO.StringIO(zip.read(namelist[i]))
                fd.inode = "%s|Z%s" % (self.inode,i)
                Scanner.scanfile(self.ddfs,fd,self.factories)

class GZScan(ZipScan):
    """ Decompress Gzip files """

    class Drawer(Scanner.Drawer):
        description = "Compressed file support"
        name = "Compressed File"
        contains = ['GZScan','TarScan','ZipScan']
        default = False
        
    class Scan(ScanIfType):
        """ If we hit a gzip file, we just create a new Inode entry in the VFS """
        types = (
            'application/x-gzip' ,
            )
        
        def __init__(self, inode,ddfs,outer,factories=None,fd=None):
            print "Initialising scanner %r" %  self
            ScanIfType.__init__(self, inode,ddfs,outer,factories)
            self.filename = None

        def process(self, data, metadata=None):
            ScanIfType.process(self,data,metadata)
            if not self.boring_status and not self.filename:
                ## We need to find the name of the original uncompressed
                ## file so we can set a sensible VFS file name. This is
                ## the algorithm used:
                ## 1) We try to decompress the first data block from the file to see if the original name is in the header
                ## 2) Failing this we check if the inodes filename ends with .gz
                ## 3) Failing that, we call the new file "data"
                a=FlagFramework.Magic()
                a.buffer(data)
                match = re.search(a.magic,'was "([^"]+)"')
                if match:
                    self.filename = match.groups(1)
                    return

                original_filename = os.path.basename(self.ddfs.lookup(inode=self.inode))
                if original_filename.endswith(".gz"):
                    self.filename=original_filename[:-3]
                    return

                self.filename="Uncompressed"

        def finish(self):
            if self.filename:
                print "Adding a gzip node for file %s" % self.filename
                self.ddfs.VFSCreate(self.inode,"G0",self.filename)

                new_inode="%s|G0" % (self.inode)
                ## Scan the new file using the scanner train:
                fd=self.ddfs.open(inode=new_inode)
                Scanner.scanfile(self.ddfs,fd,self.factories)
                fd.close()            

class TarScan(GenScanFactory):
    """ Recurse into Tar Files """
    order=99
    default = True
    depends = [ 'TypeScan' ]

    def destroy(self):
        pass
    
    class Scan(StoreAndScanType):
        types = (
            'application/x-tar',
            )

        def external_process(self,name):
            """ This is run on the extracted file """
	        #Get a TarFile object
            tar=tarfile.TarFile(name)
            
            ## List all the files in the tar file:
            dircount = 0
            namelist = tar.getnames()
            for i in range(len(namelist)):

                ## If the entry corresponds to just a directory we ignore it.
                if not os.path.basename(namelist[i]): continue
                
                ## Add the file into the VFS
                self.ddfs.VFSCreate(
                    self.inode,"T%s" % i,namelist[i],
                    size=tar.getmember(namelist[i]).size,
                    mtime=tar.getmember(namelist[i]).mtime,
                    uid=tar.getmember(namelist[i]).uid,
                    gid=tar.getmember(namelist[i]).gid,
                    mode=oct(tar.getmember(namelist[i]).mode),
                    )
                
                new_inode="%s|T%s" % (self.inode,i)
                ## Scan the new file using the scanner train:
                fd=self.ddfs.open(inode=new_inode)
                Scanner.scanfile(self.ddfs,fd,self.factories)
                fd.close()
		
## These are the corresponding VFS modules:
class Zip_file(File):
    """ A file like object to read files from within zip files. Note that the zip file is specified as an inode in the DBFS """
    specifier = 'Z'
    
    def __init__(self, case, table, fd, inode):
        File.__init__(self, case, table, fd, inode)
        # strategy:
        # inode is the index into the namelist of the zip file (i hope this is consistant!!)
        # just read that file!
        parts = inode.split('|')
        try:
            z = zipfile.ZipFile(fd,'r')
            self.data = z.read(z.namelist()[int(parts[-1][1:])])
        except (IndexError, KeyError):
            raise IOError, "Zip_File: cant find index"
        
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

class GZ_file(CachedFile):
    """ A file like object to read gzipped files. """
    specifier = 'G'
    def cache(self,fd):
        self.gz = gzip.GzipFile(fileobj=self.fd)
        count = 0
        
        ## Copy ourself into the file
        while 1:
            data=self.gz.read(1024*1024)
            count += len(data)
            print "Read %s" % len(data)
            if len(data)==0: break
            fd.write(data)

        return count

class Tar_file(File):
    """ A file like object to read files from within tar files. Note that the tar file is specified as an inode in the DBFS """
    specifier = 'T'
    
    def __init__(self, case, table, fd, inode):
        File.__init__(self, case, table, fd, inode)
        # strategy:
        # inode is the index into the namelist of the tar file (i hope this is consistant!!)
        # just read that file!
        parts = inode.split('|')
        try:
            t = tarfile.TarFile(fileobj=fd)
            name=t.getnames()[int(parts[-1][1:])]
            self.data = t.extractfile(name).read()
        except (IndexError, KeyError):
            raise IOError, "Tar_File: cant find index"
        
        self.readptr=0
        self.size=t.getmember(name).size
                
    def read(self,len=None):
        if len:
            temp=self.data[self.readptr:self.readptr+len]
            self.readptr+=len
            return temp
        else: return self.data

    def close(self):
        pass
