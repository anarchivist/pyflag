""" The Digital Forensics Tool Testing Images are a standard set of forensic tool testing images.

This file contains unit tests against these. In order to run these tests you need to download all the images from:

http://dftt.sourceforge.net/

and unzip them in the upload directory.
"""
import unittest
import pyflag.pyflagsh as pyflagsh
import pyflag.tests
import pyflag.DB as DB
import pyflag.FileSystem as FileSystem

class JpegSearchTest(pyflag.tests.ScannerTest):
    """ Test DFTT image 8: Jpeg image search #1 """
    test_case = "dftt"
    test_file = "8-jpeg-search/8-jpeg-search.dd"
    subsystem = 'standard'

    def check_for_file(self, sql='1'):
        dbh=DB.DBO(self.test_case)
        dbh.execute("select type.inode as inode,type.type,path,name from file join type on file.inode=type.inode where type.type like '%%JPEG%%' and %s limit 1", sql)
        row = dbh.fetch()
        if not row: return None

        ## Check that its a real file:
        fsfd = FileSystem.DBFS(self.test_case)
        fd = fsfd.open(inode = row['inode'])
        data = fd.read()
        if len(data) == 0:
            raise IOError("Can not read file %s%s (%s) %r" % (row['path'],row['name'], row['inode'], data))

        return row

    def test01RunScanner(self):
        """ Loading Case """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env, command="scan",
                             argv=["*",'CarveScan', 'ZipScan', 'TarScan', 'GZScan', 'TypeScan', 'IndexScan'])

    ## The following are just tests against the results:
    def test02(self):
        """ Did the search results include the alloc\\file1.jpg picture?  """
        self.assert_(self.check_for_file('path="/alloc/" and name="file1.jpg"'))

    def test03(self):
        """ Did the search results include the alloc\\file2.dat picture? """
        self.assert_(self.check_for_file('path="/alloc/" and name="file2.dat"'))

    ## We Dont recognise this an a jpeg
    def test04(self):
        """ Did the search results include the invalid\\file3.jpg file? """
        self.assertEqual(None, self.check_for_file('path="/invalid/" and name="file3.dat"'))

    ## This is recognised as a jpeg even though its not, because of its magic header.
    def test05(self):
        """ Did the search results include the invalid\\file4.jpg file? """
        self.assert_(self.check_for_file('path="/invalid/" and name="file4.jpg"'))

    ## We Dont recognise this an a jpeg
    def test06(self):
        """ Did the search results include the invalid\\file5.rtf file? """
        self.assertEqual(None, self.check_for_file('path="/invalid/" and name="file5.rtf"'))

    def test07(self):
        """ Did the search results include the deleted picture in MFT entry #32 (del1/file6.jpg)? """
        self.assert_(self.check_for_file('type.inode like "%K32-128-3%"'))

    def test08(self):
        """ Did the search results include the deleted picture in MFT entry #31 (del2/file7.jpg)? """
        self.assert_(self.check_for_file('type.inode like "%K31-128-3%"'))

    def test09(self):
        """ Did the search results include the picture inside of archive\\file8.zip? """
        self.assert_(self.check_for_file('path="/archive/file8.zip/"'))

    def test10(self):
        """ Did the search results include the picture inside of archive\\file9.boo? """
        self.assert_(self.check_for_file('path="/archive/file9.boo/"'))

    def test11(self):
        """ Did the search results include the picture inside of archive\\file10.tar.gz? """
        self.assert_(self.check_for_file('path="/archive/file10.tar.gz/file10.tar/"'))

    def test12(self):
        """ Did the search results include the misc\\file11.dat file? """
        self.assert_(self.check_for_file('path="/misc/file11.dat/"'))
        
    def test13(self):
        """ Did the search results include the misc\\file12.doc file? """
        self.assert_(self.check_for_file('path="/misc/file12.doc/"'))

    def test14(self):
        """ Did the search results include the misc\\file13.dll:here picture? """
        self.assert_(self.check_for_file('path="/misc/" and name="file13.dll:here"'))
