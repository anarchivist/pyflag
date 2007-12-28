# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.85 Date: Fri Dec 28 16:12:30 EST 2007$
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
""" This Module will automatically load in IE History files (index.dat) files.

We use the files's magic to trigger the scanner off - so its imperative that the TypeScan scanner also be run or this will not work. We also provide a report to view the history files.
"""
import os.path
import pyflag.Scanner as Scanner
import pyflag.Reports as Reports
import pyflag.conf
config=pyflag.conf.ConfObject()
import FileFormats.IECache as IECache
import pyflag.DB as DB
from pyflag.TableObj import StringType, TimestampType, FilenameType, InodeIDType
import pyflag.FlagFramework as FlagFramework

class IEIndexEventHandler(FlagFramework.EventHandler):
    def create(self, dbh, case):
        dbh.execute("""CREATE TABLE IF NOT EXISTS ie_history (
        `inode_id` int not null,
        `type` VARCHAR(20) NOT NULL,
        `url` TEXT NOT NULL,
        `modified` TIMESTAMP DEFAULT 0,
        `accessed` TIMESTAMP DEFAULT 0,
        `filename` VARCHAR(500),
        `headers` TEXT)""")                

class IEIndex(Scanner.GenScanFactory):
    """ Load in IE History files """
    default = True
    depends = ['TypeScan']

    ## FIXME: Implement multiple_inode_reset
    def reset(self, inode):
        Scanner.GenScanFactory.reset(self, inode)
        dbh=DB.DBO(self.case)
        dbh.execute("delete from ie_history")

    class Scan(Scanner.StoreAndScanType):
        types = ['application/x-ie-index']

        def external_process(self,fd):
            dbh=DB.DBO(self.case)
            dbh.mass_insert_start('ie_history')
            inode_id = self.fd.lookup_id()
            history = IECache.IEHistoryFile(fd)
            for event in history:
                if event:
                    dbh.mass_insert(inode_id = inode_id,
                                    type = event['type'],
                                    url = event['url'],
                                    modified = event['modified_time'],
                                    accessed = event['accessed_time'],
                                    filename = event['filename'],
                                    headers = event['data'])

import pyflag.tests
import pyflag.pyflagsh as pyflagsh

class IECacheScanTest(pyflag.tests.ScannerTest):
    """ Test IE History scanner """
    test_case = "PyFlagTestCase"
    test_file = "pyflag_stdimage_0.4.e01"
    subsystem = 'EWF'
    offset = "16128s"

    def test01RunScanner(self):
        """ Test IE History scanner """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env, command="scan",
                             argv=["*",'IEIndex'])

