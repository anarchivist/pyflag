""" This module contains FileSystem drivers based on the sleuthkit.

Most of the code in the this implementation is found in the dbtool executable, which uses the sleuthkit libraries to analyse the filesystem and convert it into the standard expected by the DBFS class
"""

import pyflag.FileSystem as FileSystem
import pyflag.logging as logging
from pyflag.FileSystem import FileSystem,DBFS
import pyflag.DB as DB
import pyflag.IO as IO
import pyflag.FlagFramework as FlagFramework
import time,os
import math
import bisect
import pyflag.conf
config=pyflag.conf.ConfObject()

class Ext2(DBFS):
    """ A class implementing the Ext2 module from SK """
    sk_type = "linux-ext2"
    name = "Linux ext2"

    def load(self):
        DBFS.load(self)
        sdbh = DB.DBO(self.case)

        # run sleuthkit
        string= "%s -i %r -o %r %r -t %r -f %r %r"%(config.IOWRAPPER,
                                                     self.iosource.subsystem,
                                                     self.iosource.make_parameter_list(),config.SLEUTHKIT,
                                                     self.table,self.sk_type,self.table)

        sdbh.MySQLHarness(
            string
            )

class Ext3(Ext2):
    sk_type = "linux-ext3"
    name = "Linux ext3"

class BSDi(Ext2):
    sk_type = "bsdi"
    name="BSDi FFS"

class FAT(Ext2):
    sk_type='fat'
    name="FAT (Autodetect)"

class FAT12(Ext2):
    sk_type='fat12'
    name="FAT 12"

class FAT16(Ext2):
    sk_type='fat16'
    name="FAT 16"

class FAT32(Ext2):
    sk_type='fat32'
    name="FAT 32"

class FreeBSD(Ext2):
    sk_type='freebsd'
    name="FreeBSD FFS"

class NetBSD(Ext2):
    sk_type='netbsd'
    name="NetBSD FFS"

class NTFS(Ext2):
    sk_type='ntfs'
    name='Sleuthkits NTFS'

class OpenBSD(Ext2):
    sk_type='openbsd'
    name="OpenBSD FFS"

class Solaris(Ext2):
    sk_type='solaris'
    name="Solaris FFS"

class Raw(Ext2):
    sk_type='raw'
    name="Raw"

class Mounted(DBFS):
    """ A class implementing the mounted filesystem option """
    name = 'Mounted'
    def load(self):
        logging.log(logging.DEBUG,"Loading files from directory %s" % self.iosource.mount_point)
        dbh = DB.DBO(self.case)
        ## Create the tables for the filesystem
        dbh.MySQLHarness("%s -t %s -d create blah" %(config.SLEUTHKIT,self.table))

        ## This deals with a mounted filesystem -
        ## we dont get the full forensic joy, but we can handle more filesystems than sleuthkit can.
        ## The downside is that the user has to mount the filesystem first,
        ## we also need to be running as root or we may not be able to stat all the files :-(
        def insert_into_table(mode,root,name):
            rel_root="/"+root[len(self.iosource.mount_point):]+"/"
            if rel_root=="//": rel_root="/"
            s=os.lstat(os.path.join(root,name))
            dbh.execute("insert into file_%s set inode='M%s',mode=%r,status='alloc',path=%r,name=%r",(self.table, s.st_ino, mode, rel_root, name))
            try:
                link=os.readlink("%s/%s" % (root,name))
            except OSError:
                link=''
            
            dbh.execute("insert into inode_%s set inode='M%s',uid=%r,gid=%r, mtime=%r,atime=%r,ctime=%r,mode=%r,links=%r,link=%r,size=%r",(self.table,s.st_ino,s.st_uid,s.st_gid,s.st_mtime,s.st_atime,s.st_ctime,str(oct(s.st_mode))[1:],s.st_nlink,link,s.st_size))

        ## Just walk over all the files and stat them all building the tables.
        for root, dirs, files in os.walk(self.iosource.mount_point):
            for name in dirs:
                insert_into_table('d/d',root,name)
            for name in files:
                insert_into_table('r/r',root,name)

        ## End mounted filesystem handling
        return
