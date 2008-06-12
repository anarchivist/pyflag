# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.87-pre1 Date: Thu Jun 12 00:48:38 EST 2008$
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
import os.path, cStringIO
import pyflag.Scanner as Scanner
import pyflag.Reports as Reports
import pyflag.conf
config=pyflag.conf.ConfObject()
import FileFormats.IECache as IECache
import pyflag.DB as DB
from pyflag.ColumnTypes import StringType, TimestampType, FilenameType, InodeIDType, LongStringType, IntegerType
import pyflag.FlagFramework as FlagFramework

class IECaseTable(FlagFramework.CaseTable):
    """ IE History Table - Stores all Internet Explored History """
    name = 'ie_history'
    columns = [
        [ InodeIDType, {} ],
        [ IntegerType, dict(name='Offset', column='offset')],
        [ StringType, dict(name='Type', column='type', width=20) ],
        [ StringType, dict(name='URL', column='url', width=500) ],
        [ TimestampType, dict(name='Modified', column='modified') ],
        [ TimestampType, dict(name='Accessed', column='accessed') ],
        [ StringType, dict(name='Filename', column='filename', width=500) ],
        [ LongStringType, dict(name='Headers', column='headers') ],
        ]

    index = ['url','inode_id']

class IECarver(Scanner.GenScanFactory):
    """ An IE History carver """
    default = True
    depends = []

    class Scan(Scanner.BaseScanner):
        def process(self, buf, metadata = None):
            """ We try to find a URL entry here """
            b = IECache.Buffer(fd = cStringIO.StringIO(buf))
            dbh = DB.DBO(self.case)
            dbh.mass_insert_start('ie_history')
            
            buff_offset = 0
            while 1:
                buff_offset = buf.find("URL ", buff_offset)
                if buff_offset<0 or len(buf) - buff_offset < 0x70:
                    break

                ## Now we do couple of checks before we plunge in:
                if "\x01\x00 \x00" == buf[buff_offset + 0x40 : buff_offset + 0x44]:
                    event = IECache.URLEntry(b[buff_offset:])
                    args = dict(inode_id = self.fd.inode_id,
                                offset = buff_offset,
                                type  = event['type'],
                                url = event['url'],
                                _modified = 'from_unixtime(%d)' % event['modified_time'].get_value(),
                                _accessed = 'from_unixtime(%d)' % event['accessed_time'].get_value(),
                                filename = event['filename'],)
                    try:
                        args['headers'] = event['data']
                    except: pass
                    dbh.mass_insert(args)
                    
                buff_offset += 1
    
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
                                    _modified = 'from_unixtime(%d)' % event['modified_time'].get_value(),
                                    _accessed = 'from_unixtime(%d)' % event['accessed_time'].get_value(),
                                    filename = event['filename'],
                                    headers = event['data'])

import pyflag.tests
import pyflag.pyflagsh as pyflagsh

class IECacheCarverTest(pyflag.tests.ScannerTest):
    """ Test IE History carver """
    test_case = "PyFlagTestCase"
    test_file = "pyflag_stdimage_0.4.dd"
    subsystem = 'Standard'
    offset = "0"
    fstype = "Raw"
    
    def test01RunScanner(self):
        """ Test IE History scanner """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env, command="scan",
                             argv=["*",'IECarver'])

        dbh = DB.DBO(self.test_case)
        dbh.execute("select count(*) as c from ie_history")
        row = dbh.fetch()['c']
        print "Got %s rows" % row
        self.assert_(row >= 20)

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

