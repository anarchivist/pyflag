# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
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
""" This modules add support for the ClamAV virus scanner to virus scan all files in the filesystem.

We provide a scanner class and a report to query the results of this scanner.
"""
import pyflag.FlagFramework as FlagFramework
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.FileSystem as FileSystem
import pyflag.Reports as Reports
import pyflag.DB as DB
import os.path
import pyflag.pyflaglog as pyflaglog
from pyflag.Scanner import *
from pyflag.ColumnTypes import StringType, TimestampType, InodeIDType, FilenameType, IntegerType

WARNING_ISSUED = False

## We can only work if we are connected to the clamd server. If not,
## this module will not be available. See more information at
## http://www.pyflag.net/PyFlagWiki/ClamAvConfiguration
import pyflag.pyclamd as pyclamd

## Allow the user to specify a different socket:
config.add_option("CLAMAV_SOCKET", default="/var/run/clamav/clamd.ctl",
                  help = "The location to the clamd socket. If we cant connect"
                  " virus scanning will not be available")

active = True

try:
    pyclamd.init_unix_socket(config.CLAMAV_SOCKET)

    if not pyclamd.ping():
        raise pyclamd.ScanError("Server not pingable")
except (pyclamd.ScanError, TypeError, ValueError):
    pyflaglog.log(pyflaglog.WARNING, "Unable to contact clamav - Virus scanning will not be available")
    active = False
    
class VirusTable(FlagFramework.CaseTable):
    """ Virus Table - Lists Viruses/Tojans detected """
    name = 'virus'
    columns = [ [ InodeIDType, dict(case = None) ],
                [ StringType, dict(name='Virus', column = 'virus')],
                ]
    index = [ 'inode_id']

class VirScan(GenScanFactory):
    """ Scan file for viruses """
    def destroy(self):
        dbh=DB.DBO(self.case)
        dbh.check_index('virus','inode')

    def reset(self, inode):
        GenScanFactory.reset(self, inode)
        dbh=DB.DBO(self.case)
        dbh.execute('delete from virus')

    class Scan(MemoryScan):
        def __init__(self, inode,ddfs,outer,factories=None,fd=None):
            MemoryScan.__init__(self, inode,ddfs,outer,factories,fd=fd)
            self.virus = None

        def process_buffer(self,buf):
            if not self.virus:
                self.virus=pyclamd.scan_stream(buf)

        def finish(self):
            dbh=DB.DBO(self.case)
            if self.virus:
                inode_id = self.fd.lookup_id()
                dbh.insert('virus',
                           inode_id=inode_id,
                           virus=self.virus['stream'])

class VirusScan(Reports.report):
    """ Scan Filesystem for Viruses using clamav"""
    name = "Virus Scan (clamav)"
    family = "Disk Forensics"
    description="This report will scan for viruses and display a table of viruses found"

    def display(self,query,result):
        result.heading("Virus Scan Results")
        dbh=self.DBO(query['case'])
        result.table(
            elements = [ InodeIDType(case=query['case']),
                         FilenameType(case=query['case']),
                         StringType('Virus Detected','virus') ],
            table='virus',
            case=query['case'],
            )

import pyflag.Stats as Stats
class VirusStats(Stats.Handler):
    name = "Viruses,Trojans"

    def render_tree(self, branch, query):
        dbh = DB.DBO(self.case)
        ## Top level view - we only show the File Types stats branch
        ## if we have any types there.
        if not branch[0]:
            dbh.execute("select count(*) as a from virus")
            row = dbh.fetch()
            if row['a']>0:
                yield (self.name, self.name, 'branch')
        elif branch[0] != self.name:
            return
        elif len(branch)==1:
            dbh.execute("select virus from virus group by virus")
            for row in dbh:
                t = row['virus'][:20]
                yield (row['virus'].replace("/","__"), t, 'leaf')

    def render_pane(self, branch, query, result):
        ## We may only draw on the pane that belongs to us:
        if branch[0] != self.name:
            return

        if len(branch)==1:
            result.heading("Show infected files")
            result.text("Lists all the files infected with a particular virus")
        else:
            t = branch[1].replace("__",'/')
            result.table(
                elements = [ InodeIDType(case = self.case),
                             FilenameType(case = self.case),
                             IntegerType('Size','size', table = 'inode'),
                             TimestampType('Timestamp','mtime', table='inode')],
                table = 'virus',
                where = 'virus.virus = %r ' % t,
                case = self.case,
                )

    
## UnitTests:
import unittest
import pyflag.pyflagsh as pyflagsh
import pyflag.tests

class VirusScanTest(pyflag.tests.ScannerTest):
    """ Virus Scanner Tests """
    test_case = "PyFlag Test Case"
    test_file = "pyflag_stdimage_0.4.sgz"
    subsystem = 'SGZip'
    offset = "16128s"
    
    order = 20
    def test_scanner(self):
        """ Check the virus scanner works """
        dbh = DB.DBO(self.test_case)

        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env, command="scan",
                             argv=["*",'VirScan','ZipScan','TypeScan'])

        dbh.execute("select * from virus limit 1")
        row = dbh.fetch()

        ## We expect to pick this rootkit:
        self.assert_(row, "Unable to find any viruses")
        self.assert_("NTRootKit" in row['virus'] , "Unable to find Trojan.NTRootKit.044")
        
