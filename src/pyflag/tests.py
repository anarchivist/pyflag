# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.86RC1 Date: Thu Jan 31 01:21:19 EST 2008$
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
""" This file defines a variety of things related to tests """
import unittest
from pyflag.FileSystem import DBFS
import pyflag.pyflagsh as pyflagsh
import pyflag.conf
config=pyflag.conf.ConfObject()

class FDTest(unittest.TestCase):
    ## These must be overridden with a file which is at least 100
    ## bytes long
    test_case = ""
    test_inode = ""
    
    def setUp(self):
        self.fs = DBFS(self.test_case)
        self.fd = self.fs.open(inode=self.test_inode)

    def test01HaveValidSize(self):
        """ Test for valid size """
        self.assert_(self.fd,"No fd found")
        size=self.fd.size
        ## Go to the end:
        self.fd.seek(0,2)
        self.assert_(size != 0, "Size is zero")
        self.assertEqual(self.fd.tell(),size,"Seek to end of file does not agree with size")

    def test02ReadingTests(self):
        """ Test reading ranges """
        ## Note we assume the file is at least 100 bytes long...
        data = self.fd.read(100)
        self.assertEqual(len(data),100, "Data length read does not agree with read - or file too short?")
        self.assertEqual(self.fd.tell(),100, "Seek after read does not agree")

        ## Check seeking and reading:
        self.fd.seek(50,0)
        self.assertEqual(data[50:], self.fd.read(50), "Seek and read does not agree")

    def test03SeekingTests(self):
        """ Test seeking """
        self.fd.seek(50)
        self.assertEqual(self.fd.tell(),50,"Absolute Seek does not agree with tell")

        ## Relative seeking:
        self.fd.seek(50,1)
        self.assertEqual(self.fd.tell(),100,"Relative seek does not agree")

        ## Seeking before the start of file should raise
        self.assertRaises(IOError, lambda : self.fd.seek(-5000,1))
        
        ## Check that a read at the end returns zero:
        self.fd.seek(0,2)
        self.assertEqual(self.fd.read(),'', "Read data past end of file")

## This is a generic test framework for scanners - we load a new test
## case from scratch and execute the scanners.
class ScannerTest(unittest.TestCase):
    ## Must be overridden
    test_case = ""
    test_file = ""
    subsystem = "EWF"
    fstype = "Sleuthkit"
    offset = 0
    mount_point = '/'
    TZ="SYSTEM"

    def test00preLoadCase(self):
        """ Load test Case"""
        try:
            pyflagsh.shell_execv(command="execute",
                                 argv=["Case Management.Remove case",'remove_case=%s' % self.test_case])
        except: pass
        
        pyflagsh.shell_execv(command="execute",
                             argv=["Case Management.Create new case",'create_case=%s' % self.test_case])

        if not self.test_file: return
        pyflagsh.shell_execv(command="execute",
                             argv=["Load Data.Load IO Data Source",'case=%s' % self.test_case,
                                   "iosource=test",
                                   "subsys=%s" % self.subsystem,
                                   "filename=%s" % ( self.test_file),
                                   "offset=%s"%self.offset,
                                   "TZ=%s" % self.TZ
                                   ])

        pyflagsh.shell_execv(command="execute",
                             argv=["Load Data.Load Filesystem image",'case=%s' % self.test_case,
                                   "iosource=test",
                                   "fstype=%s" % self.fstype,
                                   "mount_point=%s" % self.mount_point])
