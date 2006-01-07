# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.78 Date: Fri Aug 19 00:47:14 EST 2005$
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
import pyflag.logging as logging
from pyflag.Scanner import *

import clamav

class VScan:
    """ Singleton class to manage virus scanner access """
    ## May need to do locking in future, if libclamav is not reentrant.
    scanner = None

    def __init__(self):
        if not VScan.scanner:
            VScan.scanner=clamav.loaddbdir(clamav.retdbdir(), None, None)
            VScan.scanner=clamav.loaddbdir(config.CLAMDIR, None, VScan.scanner)
            if not VScan.scanner or clamav.buildtrie(VScan.scanner) != 0:
                raise IOError("Could not load virus scanner")

    def scan(self,buf):
        """ Scan the given buffer, and return a virus name or 'None'"""
        ret = clamav.scanbuff(buf, VScan.scanner)
        if ret == 0:
            return None
        elif ret[0] == 1:
            return ret[1]
        else:
            logging.log(logging.WARNING, "Scanning Error: %s" % clamav.reterror(ret))

class VirScan(GenScanFactory):
    """ Scan file for viruses """
    def __init__(self,dbh, table,fsfd):
        dbh.execute(""" CREATE TABLE IF NOT EXISTS `virus_%s` (
        `inode` varchar( 20 ) NOT NULL,
        `virus` tinytext NOT NULL )""", table)
        self.dbh=dbh
        self.table=table

    def destroy(self):
        self.dbh.execute('ALTER TABLE virus_%s ADD INDEX(inode)', self.table)

    def reset(self):
        GenScanFactory.reset(self)
        self.dbh.execute('drop table virus_%s',self.table)

    class Scan(MemoryScan):
        def __init__(self, inode,ddfs,outer,factories=None,fd=None):
            MemoryScan.__init__(self, inode,ddfs,outer,factories)
            self.virus = None
            self.scanner = VScan()

        def process_buffer(self,buf):
            if not self.virus:
                self.virus=self.scanner.scan(buf)

        def finish(self):
            if self.virus:
                self.dbh.execute("INSERT INTO virus_%s VALUES(%r,%r)", (self.table, self.inode, self.virus))

class VirusScan(Reports.report):
    """ Scan Filesystem for Viruses using clamav"""
    parameters = {'fsimage':'fsimage'}
    name = "Virus Scan (clamav)"
    family = "Disk Forensics"
    description="This report will scan for viruses and display a table of viruses found"
    def form(self,query,result):
        try:
            result.case_selector()
            if query['case']!=config.FLAGDB:
               result.meta_selector(case=query['case'],property='fsimage')
        except KeyError:
            return result

    def display(self,query,result):
        result.heading("Virus Scan for %s" % query['fsimage'])
        dbh=self.DBO(query['case'])
        tablename = dbh.MakeSQLSafe(query['fsimage'])

        try:
            result.table(
                columns=('a.inode','concat(path,name)', 'virus'),
                names=('Inode','Filename','Virus Detected'),
                table='virus_%s as a join file_%s as b on a.inode=b.inode ' % (tablename,tablename),
                case=query['case'],
                links=[ FlagFramework.query_type((),case=query['case'],family=query['family'],fsimage=query['fsimage'],report='ViewFile',__target__='inode')]
                )
        except DB.DBError,e:
            result.para("Unable to display Virus table, maybe you did not run the virus scanner over the filesystem?")
            result.para("The error I got was %s"%e)
            
