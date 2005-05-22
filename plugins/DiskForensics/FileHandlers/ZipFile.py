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
import zipfile,gzip
from pyflag.FileSystem import File
import time
import StringIO
import pyflag.Scanner as Scanner

class ZipScan(GenScanFactory):
    """ Recurse into Zip Files """
    order=99
    default = False
    
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
                self.ddfs.VFSCreate(self.inode,"Z%s" % i,namelist[i],size=zip.infolist()[i].file_size,mtime=t)

                ## Now call the scanners on this new file (FIXME limit the recursion level here)
                fd = StringIO.StringIO(zip.read(namelist[i]))
                fd.inode = "%s|Z%s" % (self.inode,i)
                Scanner.scanfile(self.ddfs,fd,self.factories)
                
class GZScan(ZipScan):
    """ Recurse into gziped files """
    default= False
    class Scan(StoreAndScanType):
        types = (
            'application/x-gzip',
            )
        
        def external_process(self,name):
            gz=gzip.open(name)
            i=0
            ## filename is the filename in the filesystem for the zip file.
            filename = self.ddfs.lookup(inode=self.inode)

            ## Add a psuedo file in the filesystem
            self.ddfs.dbh.execute("insert into file_%s set path=%r,name=%r,status='alloc',mode='r/r',inode='%s|G0'",(self.ddfs.table,filename+'/','data',self.inode))

            data=gz.read()
            
            ## Add the file to the inode table:
            self.ddfs.dbh.execute("insert into inode_%s set inode='%s|G0',size=%r",(self.ddfs.table, self.inode,len(data)))

            ## Now call the scanners on this new file (FIXME limit the recursion level here. FIXME: Implement a generic scanner method for progressive scanning of files)
            if self.factories:
                objs = [c.Scan("%s|G%s" % (self.inode, str(i)),self.ddfs,c,factories=self.factories) for c in self.factories]
                    
                metadata={}
                for o in objs:
                    try:
                        o.process(data,metadata=metadata)
                        o.finish()
                    except Exception,e:
                        logging.log(logging.ERRORS,"Scanner (%s) Error: %s" %(o,e))

            ## Set the gzip file to be a d/d entry so it looks like its a virtual directory:
            self.ddfs.dbh.execute("select * from file_%s where mode='r/r' and inode=%r order by status",(self.ddfs.table,self.inode))
            row=self.ddfs.dbh.fetch()
            self.ddfs.dbh.execute("insert into file_%s set mode='d/d',inode=%r,status=%r,path=%r,name=%r",(self.ddfs.table,self.inode,row['status'],row['path'],row['name']))

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
        
    def seek(self,pos):
        self.pos=pos


import gzip

class GZip_file(File):
    """ A file like object to read gziped files. """
    specifier="G"
    
    def __init__(self, case, table, fd, inode):
        File.__init__(self, case, table, fd, inode)
        try:
            self.gz = gzip.GzipFile(fileobj=fd)
        except Exception,e:
            raise IOError, "GZip_File: Error %s" %e

        self.size=0
        self.pos=0

    def read(self,len=None):
        if len!=None:
            self.pos+=len
            return self.gz.read(len)
        else:
            self.pos=self.size
            return self.gz.read()

    def close(self):
        self.gz.close()
        
    def seek(self,pos,rel=None):
        if rel==1:
            self.pos+=pos
        else:
            self.pos=pos
            
        self.gz.seek(self.pos)
