# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.82 Date: Sat Jun 24 23:38:33 EST 2006$
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
""" This module provides support for hash comparisons (MD5) using the NSRL.

We provide a scanner for calculating the MD5 of all files on the filesystem. As well as a report to examine the results.
"""
import pyflag.FlagFramework as FlagFramework
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.FileSystem as FileSystem
import pyflag.Reports as Reports
import pyflag.DB as DB
import os.path
from pyflag.Scanner import *
from pyflag.TableObj import ColumnType, TimestampType, InodeType
                  
import md5
class MD5Scan(GenScanFactory):
    """ Scan file and record file Hash (MD5Sum) """
    default = True
    depends = ['TypeScan']

    def __init__(self,fsfd):
        GenScanFactory.__init__(self, fsfd)
        dbh=DB.DBO(self.case)
        dbh.execute(""" CREATE TABLE IF NOT EXISTS `hash` (
        `inode` varchar( 250 ) NOT NULL default '',
        `md5` char( 32 ) NOT NULL default '',
        `binary_md5` char( 16 ) binary NOT NULL default '',
        `NSRL_product` varchar(250),
        `NSRL_filename` varchar(60) not NULL default '',
        `FileType` tinytext
        )""")

        dbh_flag=DB.DBO(None)
        dbh_flag.check_index("NSRL_hashes","md5",4)
        dbh_flag.check_index("NSRL_products","Code")

    class Scan(ScanIfType):
        def __init__(self, inode,ddfs,outer,factories=None,fd=None):
            BaseScanner.__init__(self, inode,ddfs,outer,factories, fd=fd)
            self.m = md5.new()
            self.type = None
            self.length = 0

        def process(self, data,metadata=None):
            self.boring(metadata,data)
            self.type = metadata['magic']
            self.m.update(data)
            self.length+=len(data)

        def finish(self):
            ## Dont do short files
            if self.length<16: return
            
            dbh_flag=DB.DBO(None)
            dbh_flag.execute("select filename,Name from NSRL_hashes join NSRL_products on productcode=Code where md5=%r limit 1",self.m.digest())
            nsrl=dbh_flag.fetch()
            if not nsrl: nsrl={}
            
            dbh=DB.DBO(self.case)
            dbh.insert('hash',
                       inode = self.inode,
                       md5 = self.m.hexdigest(),
                       binary_md5 = self.m.digest(),
                       NSRL_product = nsrl.get('Name','-'),
                       NSRL_filename = nsrl.get('filename','-'),
                       FileType = self.type,
                       )

class HashComparison(Reports.report):
    """ Compares MD5 hash against the NSRL database to classify files """
    name = "MD5 Hash comparison"
    family = "Disk Forensics"
    description="This report will give a table for describing what the type of file this is based on the MD5 hash matches"

    def form(self,query,result):
        result.case_selector()

    def display(self,query,result):
        result.heading("MD5 Hash comparisons")
        dbh=self.DBO(query['case'])

        try:
            result.table(
                elements = [ InodeType(),
                             ColumnType('Filename','concat(path,name)'),
                             ColumnType('File Type', 'FileType'),
                             ColumnType('NSRL Product','NSRL_product'),
                             ColumnType('NSRL Filename','NSRL_filename'),
                             ColumnType('MD5','md5') ],
                table='hash join file using (inode)',
                case=query['case'],
                )
        except DB.DBError,e:
            result.para("Error reading the MD5 hash table. Did you remember to run the MD5Scan scanner?")
            result.para("Error reported was:")
            result.text(e,color="red")
         
