""" This module contains FileSystem drivers based on the sleuthkit.

Most of the code in the this implementation is found in the dbtool executable, which uses the sleuthkit libraries to analyse the filesystem and convert it into the standard expected by the DBFS class
"""

import pyflag.FileSystem as FileSystem
import pyflag.pyflaglog as pyflaglog
from pyflag.FileSystem import FileSystem,DBFS,File
import pyflag.DB as DB
import pyflag.IO as IO
import pyflag.FlagFramework as FlagFramework
import time,os
import math
import bisect
import pyflag.conf
config=pyflag.conf.ConfObject()
import os.path

class Raw(DBFS):
    """ A psuedo file system to load raw images """
    name="Raw"

    def load(self, mount_point, iosource_name):
        ## Ensure that mount point is normalised:
        mount_point = os.path.normpath(mount_point)
        DBFS.load(self, mount_point, iosource_name)

        ## Just add a single inode:
        self.VFSCreate("I%s" % iosource_name,'o0', "%s/raw_filesystem" % mount_point)

## FIXME - This is now broken
class Mounted(DBFS):
    """ A class implementing the mounted filesystem option """
    name = 'Mounted'
    def load(self, mount_point, iosource_name):
        pyflaglog.log(pyflaglog.DEBUG,"Loading files from directory %s" % self.iosource.mount_point)
        
        dbh=DB.DBO(self.case)
        ## Create the tables for the filesystem
        dbh.MySQLHarness("%s -n %s -d create -m / blah" %(config.SLEUTHKIT,iosource_name))

        ## This deals with a mounted filesystem - we dont get the full
        ## forensic joy, but we can handle more filesystems than
        ## sleuthkit can.  The downside is that the user has to mount
        ## the filesystem first, we also need to be running as root or
        ## we may not be able to stat all the files :-(
        def insert_into_table(mode,root,name):
            rel_root="/"+root[len(self.iosource.mount_point):]+"/"
            if rel_root=="//": rel_root="/"
            s=os.lstat(os.path.join(root,name))
            dbh.execute("insert into file set inode='M%s',mode=%r,status='alloc',path=%r,name=%r",(self.table, s.st_ino, mode, rel_root, name))
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

import sk
import Store

SKCACHE = Store.Store()

class Sleuthkit_File(File):
    """ access to skfile """
    specifier = 'K'
    skfd = None

    def close(self):
        self.skfd.close()

    def __init__(self, case, fd, inode):
        File.__init__(self,case,fd,inode)
        
        cache_key = "%s:%s" % (self.case, self.fd.inode)
        try:
            fs = SKCACHE.get(cache_key)
        except KeyError:
            fs = sk.skfs(self.fd)
            SKCACHE.put(fs, key=cache_key)

        inode = self.inode[self.inode.find('|K')+2:]
        self.skfd = fs.open(inode=inode)
        self.skfd.seek(0,2)
        self.size = self.skfd.tell()
        self.skfd.seek(0)
        self.block_size = fs.block_size

    def seek(self, offset, rel=None):
        File.seek(self,offset,rel)

        if self.cached_fd: return
        self.skfd.seek(self.readptr, slack=self.slack, overread=self.overread)

    def read(self, length=None):
        ## Call our baseclass to see if we have cached data:
        try:
            return File.read(self,length)
        except IOError:
            pass

        if length!=None:
            result= self.skfd.read(length, slack=self.slack, overread=self.overread)
        else:
            result= self.skfd.read(slack=self.slack, overread=self.overread)

        self.readptr = self.skfd.tell()

        return result

class Sleuthkit(DBFS):
    """ A new improved Sleuthit based filesystem """
    name = 'Sleuthkit'

    def load(self, mount_point, iosource_name, scanners = None, directory=None):
        """ Loads the filesystem on mount point from iosource_name. If
        scanners are specified - generate jobs for workers as soon as
        the inodes are added. If directory is specified we only load
        the specified directory.
        """
        ## Ensure that mount point is normalised:
        mount_point = os.path.normpath(mount_point)
        DBFS.load(self, mount_point, iosource_name)

        # open the skfs
        iosrc = IO.open(self.case, iosource_name)
        fs = sk.skfs(iosrc)

        dbh_file=DB.DBO(self.case)
        dbh_inode=DB.DBO(self.case)
        dbh_block=DB.DBO(self.case)
        if scanners:
            scanner_string = ",".join(scanners)
            pdbh = DB.DBO()
            pdbh.mass_insert_start('jobs')
            cookie = int(time.time())
        
        dbh_file.cursor.ignore_warnings = True
        dbh_inode.cursor.ignore_warnings = True
        dbh_block.cursor.ignore_warnings = True

        dbh_file.mass_insert_start("file")
        dbh_inode.mass_insert_start("inode")
        dbh_block.mass_insert_start("block")

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

            inodestr = "I%s|K%s" % (iosource_name, inode)
            pathstr = "%s%s/" % (mount_point, path)

            if pathstr.startswith("//"):
                pathstr = pathstr[1:]
            if pathstr.endswith("//"):
                pathstr = pathstr[:-1]

            if inode.alloc:
                allocstr = "alloc"
            else:
                allocstr = "deleted"
                type = type[:-1]+'-'

            # insert file entry
            dbh_file.mass_insert(
                inode = inodestr,
                mode = type,
                status = allocstr,
                path = pathstr,
                name = name
                )

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

        def insert_inode(inode):
            # dont do anything for realloc inodes
            if inode.alloc == 2:
                return

            inodestr = "I%s|K%s" % (iosource_name, inode)

            if inode.alloc:
                status = 'alloc'
            else:
                status = 'unalloc'

            try:
                f = fs.open(inode=str(inode))
                s = fs.fstat(f)
                dbh_inode.mass_insert(
                    inode = inodestr,
                    status = status,
                    uid = s.st_uid,
                    gid = s.st_gid,
                    _mtime = "from_unixtime(%d)" % s.st_mtime,
                    _atime = "from_unixtime(%d)" % s.st_atime,
                    _ctime = "from_unixtime(%d)" % s.st_ctime,
                    mode = s.st_mode,
                    links = s.st_nlink,
                    link = "",
                    size = s.st_size
                    )
                
                #insert block runs
                index = 0
                for (index, start, count) in runs(f.blocks()):
                    dbh_block.mass_insert(
                        inode = inodestr,
                        index = index,
                        block = start,
                        count = count
                    )
                #f.close()

            except IOError:
                pass

            ## If needed schedule inode for scanning:
            if scanners:
                pdbh.mass_insert(
                    command = 'Scan',
                    arg1 = self.case,
                    arg2 = inode,
                    arg3= scanner_string,
                    cookie=cookie,
                    )

        # insert root inode
        insert_inode(fs.root_inum)

        if directory:
            root_dir = directory
        else:
            root_dir = '/'

        # walk the directory tree
        for root, dirs, files in fs.walk(root_dir, unalloc=True, inodes=True):
            dbh_file.mass_insert(inode = '', mode = 'd/d',
                                 status = 'alloc', path=mount_point+root[1],
                                 name = '')
            for d in dirs:
                #insert_file(d[0], 'd/d', root[1], d[1])
                insert(d[0], 'd/d', root[1], d[1])
            for f in files:
                insert(f[0], 'r/r', root[1], f[1])
                
            if directory and root != root_dir:
                break

        # have to commit now, because the next bit uses the blocks table
        dbh_file.mass_insert_commit()
        dbh_inode.mass_insert_commit()
        dbh_block.mass_insert_commit()

        if root_dir=='/':
            # find any unlinked inodes here. Note that in some filesystems, a
            # 'deleted' directory may have been found and added in the walk above.
            insert_file(sk.skinode(0, 0, 0, 1), 'd/d', '/', '_deleted_')
            for s in fs.iwalk():
                insert_inode(s)
                insert_file(s, '-/-', '/_deleted_', "%s" % s)

            # add contiguous unallocated blocks here as 'unallocated' files.
            # the offset driver over the iosource should work for this
            #unalloc_blocks = []
            count=0
            last = (0,0)
            dbh_unalloc = DB.DBO(self.case)
            ## Make sure the table is sorted here:
            dbh_unalloc.execute("alter table block add index block(block asc)")
            dbh_unalloc.execute("select * from block order by block asc")
            for row in dbh_unalloc:
                ## We make a list of all blocks which are unallocated:
                ## This is the end of the unallocated block just before this one:
                new_block = ( last[0],row['block']-last[0])
                if new_block[1]>0:
                    ## Add the offset into the db table:
                    offset = new_block[0] * fs.block_size
                    size = new_block[1] * fs.block_size
                    
                    ## Add a new VFS node:
                    ##self.VFSCreate("I%s" % iosource_name,'o%s:%s' % (offset, size),
                    ##               "/_unallocated_/o%08d" % count, size=size, _fast=True)

                    ## This is much faster than the above:
                    inode = 'I%s|o%s:%s' % (iosource_name, offset,size)
                    dbh_file.mass_insert(status = 'alloc',
                                         path = mount_point + '/_unallocated_/',
                                         inode = inode,
                                         name = "o%08d" % count,
                                         mode = 'r/r')

                    dbh_inode.mass_insert(status = 'alloc',
                                          inode = inode,
                                          mode = '40755',
                                          links = 4,
                                          size = size
                                          )

                    count+=1
                    #unalloc_blocks.append(new_block)
                    
                last=(row['block']+row['count'],0,row['inode'])
    
            ## Now we need to add the last unalloced block. This starts at
            ## the last allocated block, and finished at the end of the IO
            ## source. The size of -1 makes the VFS driver keep reading till the end.
            offset = last[0] * fs.block_size
            self.VFSCreate("I%s" % iosource_name, 'o%s:%s' % (offset, 0),
                           "/_unallocated_/o%08d" % count)

            ## We no longer need the index on the blocks table
            ## (because we never really use it) - and we dont really
            ## need to entries in the table either. FIXME: Add a
            ## method for an File class to find its block allocation
            ## on disk.
            dbh_block.execute("alter table block drop index block")
            dbh_block.delete('block', where=1)            

class SKFSEventHandler(FlagFramework.EventHandler):
    def exit(self, dbh, case):
        global SKCACHE

        for skfs in SKCACHE:
            skfs.close()

    def reset(self, dbh, case):
        cache_key = "%s:.*" % (case,)
        global SKCACHE

        SKCACHE.expire(cache_key)

## Unit Tests:
import unittest, md5
import pyflag.pyflagsh as pyflagsh
import pyflag.tests as tests

class NTFSTests(unittest.TestCase):
    """ Sleuthkit NTFS Support """
    order = 1
    test_case = "PyFlagNTFSTestCase"
    def test01LoadNTFSFileSystem(self):
        """ Test Loading of NTFS Filesystem """
        pyflagsh.shell_execv(command="execute",
                             argv=["Case Management.Remove case",'remove_case=%s' % self.test_case])

        pyflagsh.shell_execv(command="execute",
                             argv=["Case Management.Create new case",'create_case=%s' % self.test_case])

        pyflagsh.shell_execv(command="execute",
                             argv=["Load Data.Load IO Data Source",'case=%s' % self.test_case,
                                   "iosource=test",
                                   "subsys=EWF",
                                   "filename=%s/ntfs_image.e01" % config.UPLOADDIR,
                                   ])
        pyflagsh.shell_execv(command="execute",
                             argv=["Load Data.Load Filesystem image",'case=%s' % self.test_case,
                                   "iosource=test",
                                   "fstype=Sleuthkit",
                                   "mount_point=/"])
        
        dbh = DB.DBO(self.test_case)
        dbh.execute("select count(*) as count from inode")
        row = dbh.fetch()
        self.assertEqual(row['count'],139)
        dbh.execute("select count(*) as count from file")
        row = dbh.fetch()
        self.assertEqual(row['count'],152)

    def test02ReadNTFSFile(self):
        """ Test reading a regular NTFS file """
        self.fsfd = DBFS(self.test_case)
        ## This file is Images/250px-Holmes_by_Paget.jpg
        fd = self.fsfd.open(inode='Itest|K33-128-4')
        data = fd.read()
        m = md5.new()
        m.update(data)
        self.assertEqual(m.hexdigest(),'f9c4ea83dfcdcf5eb441e130359f4a0d')
        
    def test03ReadNTFSCompressed(self):
        """ Test reading a compressed NTFS file """
        self.fsfd = DBFS(self.test_case)
        fd = self.fsfd.open("/Books/80day11.txt")
        m = md5.new()
        m.update(fd.read())
        self.assertEqual(m.hexdigest(),'f5b394b5d0ca8c9ce206353e71d1d1f2')

    def test04LocatingNTFS_ADS(self):
        """ Test for finding ADS files """
        ## Do type scanning:
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env, command="scan",
                             argv=["*",'TypeScan'])

        dbh = DB.DBO(self.test_case)
        dbh.execute('select * from type where type like "%executable%" and inode like "%33-128-7%"')
        row = dbh.fetch()

        self.assert_(row, "Executable within ADS was not found???")

class SKFSTests(tests.FDTest):
    """ Tests Sleuthkit file like object """
    test_case = "PyFlagNTFSTestCase"
    test_inode = "Itest|K33-128-4"

class SKFSTests2(tests.FDTest):
    """ Test Sleuthkit file like object for compressed files """
    test_case = "PyFlagNTFSTestCase"
    test_file = "/Books/80day11.txt"

    def setUp(self):
        self.fs = DBFS(self.test_case)
        self.fd = self.fs.open(self.test_file)

class LargeFileTest(pyflag.tests.ScannerTest):
    """ Test that pyflag can load very large images efficiently """
    test_case = "WinXp"
    test_file = "winxp.sgz"
    subsystem = 'SGZip'
    level = 15
    
   
    def test01RunScanners(self):
	""" Run all scanners on the image """ 
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env, command="scan",
#                             argv=["*",'TypeScan','MD5Scan','VirScan','DLLScan','IEIndex','RFC2822','RegistryScan','OLEScan','PstScan','IndexScan'])
                             argv=["*",'*'])
