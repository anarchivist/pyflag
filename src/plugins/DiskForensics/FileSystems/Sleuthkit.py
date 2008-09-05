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
import os.path, posixpath
import stat

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
        ## We can not support caching to disk because we need to
        ## support over-read (which may not be turned on when caching
        ## to disk - but will be required later).
##        try:
##            return File.read(self,length)
##        except IOError:
##            pass

        self.skfd.seek(self.readptr)
        
        if length!=None:
            result= self.skfd.read(length, slack=self.slack, overread=self.overread)
        else:
            result= self.skfd.read(slack=self.slack, overread=self.overread)

        self.readptr = self.skfd.tell()

        return result

    def explain(self, query,result):
        self.fd.explain(query, result)

        ## List the blocks in this file:
        tmp = result.__class__(result)
        if self.inode.endswith('*'):
        	tmp.para("This file has been reallocated, the following metadata is for the currently allocated file and may not reflect the filename selected. See http://www.pyflag.net/cgi-bin/moin.cgi/FileTypes")
        tmp.para("Block size is %s bytes. The following blocks make up the file:" % self.block_size)
        tmp.row("Block","Extent", **{'type':'heading', 'class': 'explain'})
        dbh = DB.DBO(self.case)
        dbh.execute("select * from block where inode = %r order by `index`" , self.inode)
        for row in dbh:
            tmp.row(row['block'], row['count'], **{'class': 'explain'})

        result.row("Sleuthkit File %s" % self.inode[1:],tmp, **{'class':'explainrow'})
            
class Sleuthkit(DBFS):
    """ A new improved Sleuthit based filesystem """
    name = 'Sleuthkit'
    order = 5

    def load(self, mount_point, iosource_name, scanners = None, directory=None):
        """ Loads the filesystem on mount point from iosource_name. If
        scanners are specified - generate jobs for workers as soon as
        the inodes are added. If directory is specified we only load
        the specified directory.
        """
        ## Ensure that mount point is normalised:
        mount_point = posixpath.normpath(mount_point)
        DBFS.load(self, mount_point, iosource_name)

        # open the skfs
        iosrc = self.iosource
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
        #dbh_inode.mass_insert_start("inode")
        dbh_block.mass_insert_start("block")

        def insert_file(inode_id, inode, type, path, name):
            path = path.decode("utf8","ignore")
            name = name.decode("utf8","ignore")
            
            inodestr = "I%s|K%s" % (iosource_name, inode)
            pathstr = "%s%s/" % (mount_point, path)

            if pathstr.startswith("//"):
                pathstr = pathstr[1:]
            if pathstr.endswith("//"):
                pathstr = pathstr[:-1]

            if inode.alloc == 0:
                allocstr = "deleted"
                type = type[:-1]+'-'
            elif inode.alloc == 1:
                allocstr = "alloc"
            elif inode.alloc == 2:
                allocstr = "realloc"

            fields = {
                "inode":inodestr,
                "mode":type,
                "status":allocstr,
                "path":pathstr,
                "name":name
            }

            if(inode_id):
            	fields['inode_id'] = inode_id

            try:
                fields["link"] = fs.readlink(inode=inode)
            except IOError:
                pass

            # insert file entry
            dbh_file.mass_insert(**fields)

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
            """ Inserts inode into database and returns new inode_id and a
            stat object for the newly inserted inode """
            inode_id = None

            # dont do anything for realloc inodes or those with an invalid
            # inode number. inode_id 1 is the default (dummy) entry
            #if inode.alloc == 2 or str(inode) == "0-0-0":
            if str(inode) == "0-0-0":
                return 1

            inodestr = "I%s|K%s" % (iosource_name, inode)

            if inode.alloc:
                status = 'alloc'
            else:
                status = 'deleted'

            try:
                f = fs.open(inode=str(inode))
                s = fs.fstat(f)
                dbh_inode.insert( "inode",
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
                                  size = s.st_size,
                                  _fast = True
                                  )
                inode_id = dbh_inode.autoincrement()
                
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
                    arg2 = inodestr,
                    arg3= scanner_string,
                    cookie=cookie,
                    )
            return inode_id

        # insert root inode
        insert_inode(fs.root_inum)

        if directory:
            root_dir = directory
        else:
            root_dir = '/'

        # insert deleted inodes
        deleted_inodes = {}
        if root_dir=='/':
            # find any unlinked inodes here. Note that in some filesystems, a
            # 'deleted' directory may have been found and added in the walk above.
            for s in fs.iwalk():
                deleted_inodes["%s" % s] = (insert_inode(s),s)

        # walk the directory tree
        for root, dirs, files in fs.walk(root_dir, unalloc=True, inodes=True):
            dbh_file.mass_insert(inode = '', mode = 'd/d',
                                 status = 'alloc', path=FlagFramework.normpath(mount_point+root[1].decode("utf8")),
                                 name = '')

            ## if a entry is marked as 'realloc' it is an artifact of NTFS
            ## directory b-tree re-sorting, quite often there is still an
            ## alloc entry with exactly the same name, so the realloc entry
            ## becomes redundant. However, when there is no alloc entry for
            ## the realloc entry, it becomes important forenic data.
            for d in dirs:
               	if d[0].alloc == 2: # realloc
               	    dirs2 = [ x for x in dirs if x != d and x[1] == d[1] and str(x[0]) == str(d[0])[:-1] ]
               	    if dirs2: continue

                inum = str(d[0])
                if inum in deleted_inodes:
                    inode_id = deleted_inodes[inum][0]
                    del deleted_inodes[inum]
                else:
                    inode_id = insert_inode(d[0])
                insert_file(inode_id, d[0], 'd/d', root[1], d[1])

            for f in files:
               	if f[0].alloc == 2: # realloc
                    files2 = [ x for x in files if x != f and x[1] == f[1] and str(x[0]) == str(f[0])[:-1] ]
                    if files2: continue

            	inum = str(f[0])
                if inum in deleted_inodes:
                    inode_id = deleted_inodes[inum][0]
                    del deleted_inodes[inum]
                else:
                    inode_id = insert_inode(f[0])
                insert_file(inode_id, f[0], 'r/r', root[1], f[1])
                
            if directory and root != root_dir:
                break

        # have to commit now, because the next bit uses the blocks table
        dbh_file.mass_insert_commit()
        dbh_inode.mass_insert_commit()
        dbh_block.mass_insert_commit()

        if root_dir=='/':
            ## Drop any indexes for the time to speed up inserts:
            try:
                dbh_block.execute("drop index block on block")
            except DB.DBError: pass
            
            # add any remaining (unlinked) deleted inodes
            insert_file(None, sk.skinode(0, 0, 0, 1), 'd/d', '/', '_deleted_')
            for s in deleted_inodes:
                insert_file(deleted_inodes[s][0], deleted_inodes[s][1], '-/-', '/_deleted_', "%s" % s)

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
                    dbh_inode.insert("inode", status = 'alloc',
                                          inode = inode,
                                          mode = '40755',
                                          links = 4,
                                          size = size
                                          )

                    inode_id = dbh_inode.autoincrement()
                    dbh_file.mass_insert(status = 'alloc',
                                         path = FlagFramework.normpath(mount_point + '/_unallocated_/'),
                                         inode = inode,
                                         inode_id = inode_id,
                                         name = "o%08d" % count,
                                         mode = 'r/r')

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
            #dbh_block.execute("alter table block drop index block")
            #dbh_block.delete('block', where=1)            

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
                                   "filename=ntfs_image.e01",
                                   ])
        pyflagsh.shell_execv(command="execute",
                             argv=["Load Data.Load Filesystem image",'case=%s' % self.test_case,
                                   "iosource=test",
                                   "fstype=Sleuthkit",
                                   "mount_point=/"])
        
        dbh = DB.DBO(self.test_case)
        dbh.execute("select count(*) as count from inode")
        row = dbh.fetch()
        self.assertEqual(row['count'],140)
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
        dbh.execute('select type.type from type,inode where type.inode_id=inode.inode_id and type like "%executable%" and inode.inode like "%33-128-7%"')
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
    """ Test that pyflag can load very large images efficiently (WinXp) """
    test_case = "WinXp"
    test_file = "winxp"
    subsystem = 'Standard'
    level = 15
    
    def test01RunScanners(self):
	""" Run all scanners on the image """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env, command="scan",
#                             argv=["*",'TypeScan','MD5Scan','DLLScan','IEIndex','RFC2822','RegistryScan','OLEScan','PstScan','IndexScan'])
                             argv=["*",'*'])

