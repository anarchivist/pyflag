# Michael Cohen <scudette@users.sourceforge.net>
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

""" This is a carver for IE History files. It depends on the IEHistory
File handler to create all the tables etc.
"""
import pyflag.Scanner as Scanner
import JPEGCarver
import pyflag.format as format
import pyflag.DB as DB
import FileFormats.IECache as IECache
import cStringIO

class IECarver(JPEGCarver.JPEGCarver):
    """ An IE History carver """
    default = True
    depends = 'IndexScan'
    group = "Carvers"
    regexs = ['URL ']
    
    class Scan(JPEGCarver.CarverScan):
        def examine_hit(self, fd, offset, length):
            fd.seek(offset)

            ## This effectively localises the match to make sure we
            ## dont try to read wild pointers
            b = format.Buffer(fd=cStringIO.StringIO(fd.read(0x700)))

            ## Try to parse it as an URLEntry
            try:
                event = IECache.URLEntry(b)
            except:
                return
            
            ## Size is too big
            if event['size'].get_value() > 10:
                return

            args = dict(inode_id = self.fd.inode_id,
                        offset = offset,
                        length = event['size'].get_value() * IECache.blocksize,
                        type  = event['type'].get_value().decode("ascii","ignore"),
                        url = event['url'].get_value().decode("ascii","ignore"),
                        _modified = 'from_unixtime(%d)' % event['modified_time'].get_value(),
                        _accessed = 'from_unixtime(%d)' % event['accessed_time'].get_value(),
                        filename = event['filename'],)
            try:
                args['headers'] = event['data']
            except: pass
            dbh = DB.DBO(self.case)
            dbh.insert("ie_history", **args)
                

import pyflag.tests
import pyflag.pyflagsh as pyflagsh

class IECacheCarverTest(pyflag.tests.ScannerTest):
    """ Test IE History carver """
    test_case = "PyFlagTestCase"
    test_file = "pyflag_stdimage_0.4.e01"
    subsystem = 'EWF'
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
