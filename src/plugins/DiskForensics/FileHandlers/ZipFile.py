# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.82 Date: Sat Jun 24 23:38:33 EST 2006$
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
import os.path,sys
import pyflag.logging as logging
from pyflag.Scanner import *
import zipfile,gzip,tarfile, zlib
from pyflag.FileSystem import File
import pyflag.FlagFramework as FlagFramework
import time,re,os
import StringIO
import pyflag.Scanner as Scanner
import gzip
import plugins.DiskForensics.DiskForensics as DiskForensics

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

        def external_process(self,fd):
            """ This is run on the extracted file """
            logging.log(logging.VERBOSE_DEBUG, "Decompressing Zip File %s" % fd.name)
            self.fd.zip_handle=zipfile.ZipFile(fd.name)

            pathname = self.ddfs.lookup(inode = self.inode)
            
            ## List all the files in the zip file:
            dircount = 0
            namelist = self.fd.zip_handle.namelist()
            for i in range(len(namelist)):
                ## Add the file into the VFS
                try:
                    ## Convert the time to a common format.
                    t = time.mktime(list(self.fd.zip_handle.infolist()[i].date_time) +[0,0,0])
                except:
                    t=0

                ## If the entry corresponds to just a directory we ignore it.
                if not os.path.basename(namelist[i]): continue
                inode = "%s|Z%s" % (self.inode,i)

                self.ddfs.VFSCreate(None,
                                    inode,pathname+"/"+namelist[i],
                                    size=self.fd.zip_handle.infolist()[i].file_size,
                                    mtime=t)

                ## Now call the scanners on this new file (FIXME limit
                ## the recursion level here)
                fd = ZipFile(self.dbh.case, self.fd, inode, dbh=self.dbh)
#                fd = self.ddfs.open(inode = inode)
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
            ScanIfType.__init__(self, inode,ddfs,outer,factories,fd=fd)
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
                magic = a.buffer(data)
                match = re.search(magic,'was "([^"]+)"')
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

        def external_process(self,fd):
            """ This is run on the extracted file """
            #Get a TarFile object
            tar=tarfile.TarFile(fileobj=fd)
            
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
		
## These are the corresponding VFS modules:
class ZipFile(DiskForensics.DBFS_file):
    """ A file like object to read files from within zip files. Note
    that the zip file is specified as an inode in the DBFS

    We essentially decompress the file on the disk because the file
    may be exceptionally large.
    """
    specifier = 'Z'
    
    def __init__(self, case, fd, inode, dbh=None):
        DiskForensics.DBFS_file.__init__(self, case, fd, inode, dbh)

        ## Zip file handling requires repeated access into the zip
        ## file. Caching our input fd really helps to speed things
        ## up... This causes our input fd to be disk cached
        fd.cache()

        ## If we are already cached on disk, we dont need to
        ## decompress anything
        if self.cached_fd: return

        ## Initialise our internal variables:
        self.seek(0)

    def read(self,length=sys.maxint):
        ## Call our baseclass to see if we have cached data:
        try:
            return File.read(self,length)
        except IOError:
            pass

        ## This is done in order to decompress the file in small
        ## chunks. We try to return as much data as was required
        ## and not much more
        try:
            ## Consume the data left over from previous reads
            result = self.left_over[:length]
            self.left_over=self.left_over[length:]

            ## We keep reading compressed data until we can satify
            ## the desired length
            while len(result)<length and self.compressed_length>0:
                ## Read up to 1k of the file:
                available_clength = min(self.blocksize,self.compressed_length)
                cdata = self.z.fp.read(available_clength)
                self.compressed_length -= available_clength

                if self.type == zipfile.ZIP_DEFLATED:
                    ## Now Decompress that:
                    ddata = self.d.decompress(cdata)
                elif self.type == zipfile.ZIP_STORED:
                    ddata = cdata
                else:
                    raise RuntimeError("Compression method %s is not supported" % self.type)

                ## How much data do we require?
                required_length = length - len(result)
                result += ddata[:required_length]

                ## This will be '' if we have not finished making
                ## up the result, and store the rest for next time
                ## if we have
                self.left_over = ddata[required_length:]

        except (IndexError, KeyError, zipfile.BadZipfile),e:
            raise IOError("Zip_File: (%s)" % e)

        self.readptr += len(result)
        return result

    def seek(self, offset, rel=None):
        File.seek(self,offset,rel)

        if self.cached_fd: return

        ## We want to reinitialise the file pointer:
        if self.readptr==0:
            try:
                ## This is a performance boost - We try to cache the
                ## zipfile object in our parent - if its not done
                ## previously to speed up future accesses to other
                ## files within the zip file. This will ensure we only
                ## need to read the zip directory once instead of many
                ## times for each zip member.
                self.z = self.fd.zip_handle
            except AttributeError:
                try:
                    logging.log(logging.VERBOSE_DEBUG, "Reading Zip Directory for %s" % self.fd.inode)
                    self.z = zipfile.ZipFile(self.fd,'r')
                    self.fd.zip_handle = self.z
                except zipfile.BadZipfile,e:
                    raise IOError("Zip_File: (%s)" % e)

            parts = self.inode.split('|')
            index = int(parts[-1][1:])
            self.zinfo = self.z.filelist[index]

            ## Prepare our parent's readptr to be at the right place
            self.z.fp.seek(self.zinfo.file_offset,0)

            ## The decompressor we are going to use
            self.d = zlib.decompressobj(-15)
            self.compressed_length = self.zinfo.compress_size
            self.type = self.zinfo.compress_type

            ## We try to choose sensible buffer sizes
            if self.type == zipfile.ZIP_STORED:
                self.blocksize = 1024*1024
            else:
                self.blocksize = 1024

            ## This stores the extra data which was decompressed, but not
            ## consumed by previous reads.
            self.left_over=''
        else:
            ## We need to seek to somewhere in the middle of the zip
            ## file. This is bad because we need to essentially
            ## decompress all the data in that file until the desired
            ## point. If this happens we need to warn the user that
            ## they better cache this file on the disk. FIXME: Should
            ## we automatically force caching here?
            if self.type == zipfile.ZIP_DEFLATED:
                logging.log(logging.DEBUG, "Required to seek to offset %s in Zip File %s. This is inefficient, forcing disk caching." % (self.readptr, self.inode))
                self.cache()
                #File.__init__(self,self.case,self.fd,self.inode,self.dbh)
                self.seek(offset, rel)
                return
            
            self.seek(0,0)
            self.read(self.readptr)

    def close(self):
        pass

class GZ_file(DiskForensics.DBFS_file):
    """ A file like object to read gzipped files. """
    specifier = 'G'
    
    def __init__(self, case, fd, inode, dbh=None):
        File.__init__(self, case, fd, inode, dbh)

        self.cache()
        
    def force_cache(self):
        cached_filename = self.get_temp_path()
        fd = open(cached_filename, 'w')
        self.fd.cache()
        gz = gzip.GzipFile(fileobj=self.fd, mode='r')
        count = 0
        step = 1024
        
        ## Copy ourself into the file - This is in case we have errors
        ## in the file, we try to read as much as possible:
        while 1:
            try:
                data=gz.read(step)
            except IOError,e:
                step /= 2
                if step<10:
                    logging.log(logging.DEBUG, "Error reading from %s, could only get %s bytes" % (self.fd.inode, count));
                    break
                
                else:
                    continue
            
            count += len(data)
            if len(data)==0: break
            fd.write(data)

        self.cached_fd =  open(cached_filename, 'r')
        return count

class Tar_file(DiskForensics.DBFS_file):
    """ A file like object to read files from within tar files. Note that the tar file is specified as an inode in the DBFS """
    specifier = 'T'
    
    def __init__(self, case, fd, inode, dbh=None):
        File.__init__(self, case, fd, inode, dbh)

        ## Tar file handling requires repeated access into the tar
        ## file. Caching our input fd really helps to speed things
        ## up...
        fd.cache()
        
        # strategy:
        # inode is the index into the namelist of the tar file (i hope this is consistant!!)
        # just read that file!
        parts = inode.split('|')

        try:
            t = self.fd.tar_handle
        except AttributeError:
            try:
                t = tarfile.TarFile(fileobj=fd)
                self.fd.tar_handle = t
            except tarfile.CompressionError,e:
                raise IOError("Tar file: %s" % e)
        
        try:
            name=t.getnames()[int(parts[-1][1:])]
            self.data = t.extractfile(name).read()
        except (IndexError, KeyError):
            raise IOError, "Tar_File: cant find index"
        
        self.readptr=0
        self.size=t.getmember(name).size
                
    def read(self,len=None):
        ## Call our baseclass to see if we have cached data:
        try:
            return File.read(self,len)
        except IOError:
            pass

        if len:
            temp=self.data[self.readptr:self.readptr+len]
            self.readptr+=len
            return temp
        else: return self.data

    def close(self):
        pass
