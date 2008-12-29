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
import pyflag.conf
config=pyflag.conf.ConfObject()

class KeyWordSearchTest(pyflag.tests.ScannerTest):
    """ Test DFTT image 2: FAT Keyword Test """
    test_case = 'dftt'
    test_file = "2-kwsrch-fat/fat-img-kw.dd"
    subsystem = 'Standard'

    ## Copied from DFTT page - id,string, sector, offset, file, note
    case_sensitive_keywords = [
	[1,'first',	 271,	 167,	'/file1.dat','in file'],
	[2,'SECOND',	 272,	288,	'/file2.dat','in file'],
 	[2,'SECOND',	 239,	480,	None,	    'in dentry - file name'],
	[3,'1cross1',	 271,	508,	'/file1.dat','crosses two allocated files'],
	[4,'2cross2',	 273,	508,	'/file3.dat','crosses consecutive sectors in a file'],
	[5,'3cross3',	 282,	1020,	'/_unallocated_/o00000001',	    'crosses in unalloc'],
	[6,'1slack1',	 272,	396,	'/file2.dat','crosses a file into slack'],
        ## This was change to measure the offset from the start of the file:
	[7,'2slack2',	 273,	1020,	'/file3.dat','crosses slack into a file'],
	[8,'3slack3',	 276,	897,	'/file4.dat','in slack'],
	[9,'1fragment1', 275,	507,	'/file4.dat','crosses fragmented sectors'],
	[10,'2fragment sentence2',	278,	502,	'/file6.dat',	'crosses fragmented sectors on ' ''],
        ## We seem to find this twice:
	[11,'deleted',	 276,	230,	'/_unallocated_/o00000001',	'deleted file'],
        [11,'deleted',	 276,	230,	'/_ILE5.DAT',	'deleted file'],
	[12,'a?b\c*d$e#f[g^',279,	160,	'/file7.dat',	'regexp values'],
        ]
    
    case_insesitive_keywords = []
    regex_keywords = [
        [14,r'f[\w]rst',	        ['first']],
        [15,r'f[a-z]r[0-9]?s[\s]*t',	["first"]],
        [16,r'd[a-z]l.?t.?d',	        ["deleted"]],
        [17,r'[0-9][r-t][\s]?[j-m][\s]?[a-c]{2,2}[\s]?[j-m][0-9]',
                                        ['1slack1', '2slack2', '3slack']],
        [18,r'[1572943][\s]?fr.{2,3}ent[\s]?',
                                        ['1fragment', '2fragment ']],
        [19,r'a\??[a-c]\\*[a-c]\**', 	['a?b\c*']],
        [20,r'\s\??x?y?Q?[a-c]\\*u*[a-c]\**d\$[0-9]*e#',
                                        ['a?b\c*d$e#']],
        ]

    def find_expected_output(self, word, id, filename, offset, array, data):
        for i in range(len(self.case_sensitive_keywords)):
            row = self.case_sensitive_keywords[i]
            if id==row[0] and filename==row[4] and offset==row[3]:
                self.case_sensitive_keywords.pop(i)
                return 

            if data==row[1]:
                self.case_sensitive_keywords.pop(i)
                break


        for i in range(len(self.regex_keywords)):
            if id==self.regex_keywords[i][0]:
                array = self.regex_keywords[i][2]
                for j in range(len(array)):
                    if array[j]==data:
                        array.pop(j)
                        return

        #self.fail("Unable to find a match for %s" % word)
        print "Unable to find a match for %s" % word

    def test01RunScanner(self):
        """ Running scanners """
        ## Populate the key words into the dictionary:
        dbh = DB.DBO()
        for row in self.case_sensitive_keywords:
            id = row[0]
            w = row[1]
            dbh.delete('dictionary','id=%r' % (id+1000), _fast=True)
            dbh.insert('dictionary', _fast=True,
                       **{'id':id+1000, 'class':"DFTT",
                          'type': 'literal', 'word':w})

        for row in self.regex_keywords:
            id = row[0]
            w = row[1]
            dbh.delete('dictionary','id=%r' % (id+1000), _fast=True)
            dbh.insert('dictionary', _fast = True,
                       **{'id':id+1000, 'class':"DFTT",
                          'type': 'regex', 'word':w})

        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env, command="scan",
                             argv=["*",'IndexScan'])

    def test02TestOutput(self):
        """ Testing output """
        dbh = DB.DBO(self.test_case)
        fsfd = FileSystem.DBFS(self.test_case)
        dbh.execute("select inode_id, word_id, word,offset,length from LogicalIndexOffsets join %s.dictionary on LogicalIndexOffsets.word_id=%s.dictionary.id where id>1000 and id<1020", (config.FLAGDB,config.FLAGDB))
        for row in dbh:
            patg, inode, inode_id = fsfd.lookup(inode_id = row['inode_id'])
            fd = fsfd.open(inode=inode)
            fd.overread = True
            fd.slack = True
            fd.seek(row['offset'])
            data = fd.read(row['length'])
            filename, inode,inode_id = fsfd.lookup(inode = inode)
            print "Looking for %s: Found in %s (%s) at offset %s length %s %r" % (
                row['word'], filename, inode, row['offset'], row['length'],data)
            #self.assertEqual(data.lower(), row['word'].lower())
            self.find_expected_output(row['word'], row['word_id']-1000, filename,
                                      row['offset'], self.case_sensitive_keywords, data)

        print "Left over %s" % self.case_sensitive_keywords

class JpegSearchTest(pyflag.tests.ScannerTest):
    """ Test DFTT image 8: Jpeg image search #1 """
    test_case = "dftt"
    test_file = "8-jpeg-search/8-jpeg-search.dd"
    subsystem = 'Standard'

    def check_for_file(self, sql='1'):
        dbh=DB.DBO(self.test_case)
        dbh.execute("select inode.inode as inode,type.type,path,name from file,type,inode where file.inode_id=type.inode_id and inode.inode_id=type.inode_id and type.type like '%%JPEG%%' and %s limit 1", sql)
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
        """ Running scanners """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env, command="scan",
                             argv=["*",'ZipScan', 'TarScan', 'GZScan'])

        pyflagsh.shell_execv(env=env, command="scan",
                             argv=["*",'JPEGCarver', 'ZipScan', 'TarScan', 'GZScan', 'TypeScan', 'IndexScan'])

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
        self.assert_(self.check_for_file('inode.inode like "%K32-128-3%"'))

    def test08(self):
        """ Did the search results include the deleted picture in MFT entry #31 (del2/file7.jpg)? """
        self.assert_(self.check_for_file('inode.inode like "%K31-128-3%"'))

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
