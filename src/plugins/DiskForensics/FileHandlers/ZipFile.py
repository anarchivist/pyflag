# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.84RC1 Date: Fri Feb  9 08:22:13 EST 2007$
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

Note that the scanner reads the central directory to recover
compressed file offsets with in the zip file. The carver does not and
finds zip file contents where ever they appear within the zip -
hopefull the both return the same thing, but in the case of a multi
file zip file the carver will work better than the scanner.
"""
import os.path,sys
import pyflag.pyflaglog as pyflaglog
from pyflag.Scanner import *
import zipfile,gzip,tarfile, zlib
from pyflag.FileSystem import File
import pyflag.FlagFramework as FlagFramework
import time,re,os
import StringIO
import pyflag.Scanner as Scanner
import gzip
import plugins.DiskForensics.DiskForensics as DiskForensics
import pyflag.Store as Store
import FileFormats.Zip as Zip

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
            pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "Decompressing Zip File %s" % fd.name)
            cache_key = "%s:%s" % (self.case , self.fd.inode)

            ## Try to read the fd as a zip file
            z = zipfile.ZipFile(fd,'r')

            pathname = self.ddfs.lookup(inode = self.inode)
            
            ## List all the files in the zip file:
            dircount = 0
            namelist = z.namelist()
            for i in range(len(namelist)):
                ## Add the file into the VFS
                try:
                    ## Convert the time to a common format.
                    t = time.mktime(list(z.infolist()[i].date_time) +[0,0,0])
                except:
                    t=0

                ## If the entry corresponds to just a directory we ignore it.
                if not os.path.basename(namelist[i]): continue

                info = z.infolist()[i]
                inode = "%s|Z%s:%s" % (self.inode,info.header_offset, info.compress_size)

                self.ddfs.VFSCreate(None,
                                    inode,pathname+"/"+namelist[i],
                                    size=info.file_size,
                                    mtime=t)

                ## Now call the scanners on this new file (FIXME limit
                ## the recursion level here)
                #fd = ZipFile(self.case, self.fd, inode)
                fd = self.ddfs.open(inode = inode)
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

ZIPCACHE = Store.Store(max_size=5)
		
## These are the corresponding VFS modules:
class ZipFile(File):
    """ A file like object to read files from within zip files.

    We essentially decompress the file on the disk because the file
    may be exceptionally large.
    """
    specifier = 'Z'
    
    def __init__(self, case, fd, inode):
        File.__init__(self, case, fd, inode)

        ## Make sure our parent is cached:
        self.fd.cache()

        ## Parse out inode - if we got the compressed length provided,
        ## we use that, otherwise we calculate it from the zipfile
        ## header
        parts = inode.split('|')
        ourpart = parts[-1][1:]
        try:
            offset, size = ourpart.split(":")
            self.compressed_length = int(size)
            offset = int(offset)
        except:
            offset = int(ourpart)

        ## Ensure that we can read the file header:
        b = Zip.Buffer(fd=fd)[offset:]
        self.header = Zip.ZipFileHeader(b)

        ## This is sometimes invalid and set to zero - should we query
        ## the db?
        self.size = int(self.header['uncompr_size'])
        
        if not self.compressed_length:
            self.compressed_length = int(self.header['compr_size'])
            
        self.type = int(self.header['compression_method'])

        ## Where does the data start?
        self.init()

    def init(self):
        self.d = zlib.decompressobj(-15)
        self.left_over = ''
        self.blocksize = 1024*10

        offset = self.header['data'].buffer.offset
        
        ## Seek our fd to there:
        self.fd.seek(offset)
        
    def read(self,length=None):
        ## Call our baseclass to see if we have cached data:
        try:
            return File.read(self,length)
        except IOError:
            pass

        ## Read as much as possible
        if length==None:
            length = sys.maxint
            
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
                cdata = self.fd.read(available_clength)
                self.compressed_length -= available_clength

                if self.type == Zip.ZIP_DEFLATED:
                    ## Now Decompress that:
                    ddata = self.d.decompress(cdata)
                elif self.type == Zip.ZIP_STORED:
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
        if self.readptr!=0 and self.type == Zip.ZIP_DEFLATED:
            pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "Required to seek to offset %s in Zip File %s (%s,%s). This is inefficient, forcing disk caching." % (self.readptr, self.inode, offset,rel))
            self.init()
            self.cache()

            self.seek(offset, rel)
            return

class GZ_file(DiskForensics.DBFS_file):
    """ A file like object to read gzipped files. """
    specifier = 'G'
    
    def __init__(self, case, fd, inode):
        File.__init__(self, case, fd, inode)
        self.gz = None

    def read(self, length=None):
        try:
            return File.read(self,length)
        except IOError:
            pass

        if not self.gz:
            self.gz = gzip.GzipFile(fileobj=self.fd, mode='r')
            
        count = 0
        step = 1024

        result = ''
        
        ## Copy ourself into the file - This is in case we have errors
        ## in the file, we try to read as much as possible:
        while 1:
            try:
                data=self.gz.read(step)
            except IOError,e:
                step /= 2
                if step<10:
                    pyflaglog.log(pyflaglog.DEBUG, "Error reading from %s, could only get %s bytes" % (self.fd.inode, count));
                    break
                
                else:
                    continue
            
            count += len(data)
            if len(data)==0: break
            result+=data

        return result

    def seek(self,offset,rel=None):
        File.seek(self,offset,rel)

        if self.cached_fd: return

        ## If we were asked to seek in a gzip file:
        if self.readptr!=0:
            pyflaglog.log(pyflaglog.VERBOSE_DEBUG,"Asked to seek to %s in gzip file %s. This is expensive, caching on disk." % (self.readptr, self.inode))
            self.cache()

            self.seek(offset,rel)

class Tar_file(DiskForensics.DBFS_file):
    """ A file like object to read files from within tar files. Note that the tar file is specified as an inode in the DBFS """
    specifier = 'T'
    
    def __init__(self, case, fd, inode):
        File.__init__(self, case, fd, inode)

        ## Tar file handling requires repeated access into the tar
        ## file. Caching our input fd really helps to speed things
        ## up...
        fd.cache()
        
        # strategy:
        # inode is the index into the namelist of the tar file (i hope this is consistant!!)
        # just read that file!
        parts = inode.split('|')

        try:
            t = ZIPCACHE.get(self.fd.inode)
        except (AttributeError, KeyError):
            try:
                t = tarfile.TarFile(fileobj=fd)
                ZIPCACHE.put(t, key=self.fd.inode)
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

invalid_filename = re.compile('[^a-zA-Z0-9!@#$%^&()_+-=*{}\\|]')
class ZipFileCarver(Scanner.Carver):
    """ This is a special carver for zip files """
    regexs = ['PK\x03\x04']

    def add_inode(self, fd, offset, factories):
        """ We think we have a zip file here. """
        b = Zip.Buffer(fd=fd)[offset:]
        try:
            header = Zip.ZipFileHeader(b)
            size = int(header['uncompr_size'])
            compressed_length = int(header['compr_size'])

            ## Some zip programs seem to leave this at 0 - because its
            ## already in the central directory. Unfortunately the
            ## carver currently does not look at the central directory
            ## - so we just make it a reasonable value
            if compressed_length==0:
                compressed_length = 100*1024
                
            name = header['zip_path'].get_value()
	    if len(name)==0 or invalid_filename.search(name):
                pyflaglog.log(pyflaglog.DEBUG, "Thought the name %r is invalid - skipping file" % name[:10])
                return 10

            header_offset = header['data'].buffer.offset
        except:
            return 10

        new_inode = "%s|Z%s:%s" % (fd.inode, offset, compressed_length)
        self._add_inode(new_inode, size, name, fd, factories)
        return size

## UnitTests:
import unittest
import pyflag.pyflagsh as pyflagsh
import pyflag.tests

class ZipScanTest(pyflag.tests.ScannerTest):
    """ Zip File handling Tests """
    test_case = "PyFlagTestCase"
    test_file = "pyflag_stdimage_0.2.sgz"
    subsystem = 'sgzip'
    offset = "16128s"

    def test_type_scan(self):
        """ Check the Zip scanner works """
        dbh = DB.DBO(self.test_case)

        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env, command="scan",
                             argv=["*",'ZipScan','GZScan','TarScan','TypeScan'])

        dbh.execute("select count(*) as count from inode where inode like '%|Z%'")
        count = dbh.fetch()['count']
        self.failIf(count==0, "Could not find any zip files?")
        
        dbh.execute("select count(*) as count from inode where inode like '%|G0'")
        count = dbh.fetch()['count']
        self.failIf(count==0, "Could not find any gzip files?")

        ## FIXME: No tar files in the test image
        #dbh.execute("select count(*) as count from inode where inode like '%|T%'")
        #count = dbh.fetch()['count']
        #self.failIf(count==0, "Could not find any tar files?")

import pyflag.tests

class ZipScanTest2(pyflag.tests.ScannerTest):
    """ Test handling of zip bombs """
    test_case = "PyFlagZipCase"
    test_file = "zip_test.iso.sgz"
    subsystem = 'sgzip'

    def test01RunScanner(self):
        """ Test Zip scanner handling of very large zip files """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env, command="scan",
                             argv=["*",'ZipScan', 'TypeScan'])
