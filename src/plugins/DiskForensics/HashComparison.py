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
from pyflag.ColumnTypes import StringType, TimestampType, InodeIDType, FilenameType, ColumnType

import md5

config.add_option('hashdb', short_option='H', default="nsrldb",
                  help = "The database which will be used to store hash sets (like nsrl)")

class HashType(ColumnType):
    def __init__(self, **kwargs):
        ColumnType.__init__(self, name="MD5", column='binary_md5', **kwargs)

    def create(self):
        return "`%s` binary( 16 ) NOT NULL default ''" % self.column

    def display(self, value, row, result):
        return value.encode("hex").upper()

class HashCaseTable(FlagFramework.CaseTable):
    """ Hash Table - Lists MD5 hashes and NSRL Matches """
    name = 'hash'
    columns = [ [ InodeIDType, dict() ],
                [ HashType, {} ],
                [ StringType, dict(name='NSRL Product',
                                   column='NSRL_product',
                                   ) ],
                [ StringType, dict(name='NSRL Filename',
                                   column='NSRL_filename',
                                   width=60) ],
                ]
    
class HashTables(FlagFramework.EventHandler):
    def init_default_db(self, dbh, case):
        # Remember to add indexes to this table after uploading the
        # NSRL. Use the nsrl_load.py script.
        ## We initialise the nsrl database if it does not already exist:
        try:
            dbh.execute("""CREATE database if not exists `%s`""", config.HASHDB)
            ndbh = DB.DBO(config.HASHDB)
            
            ndbh.execute("""CREATE TABLE if not exists `NSRL_hashes` (
            `md5` varchar(16) NOT NULL default '',
            `filename` varchar(60) NOT NULL default '',
            `productcode` int(11) NOT NULL default '0',
            `oscode` varchar(60) NOT NULL default ''
            ) engine=MyISAM""")
            
            ndbh.execute("""CREATE TABLE if not exists `NSRL_products` (
            `Code` mediumint(9) NOT NULL default '0',
            `Name` varchar(250) NOT NULL default '',
            `Version` varchar(20) NOT NULL default '',
            `OpSystemCode` varchar(20) NOT NULL default '',
            `ApplicationType` varchar(250) NOT NULL default ''
            ) engine=MyISAM COMMENT='Stores NSRL Products'""")
            
            ndbh.insert("NSRL_products",
                        code=0,
                        name='Unknown',
                        _fast=True);
        except Exception,e:
            print e
            pass


class MD5Scan(GenScanFactory):
    """ Scan file and record file Hash (MD5Sum) """
    default = True
    depends = ['TypeScan']

    def __init__(self,fsfd):
        GenScanFactory.__init__(self, fsfd)
        
        ## Make sure we have indexes on the NSRL tables:
        dbh_flag=DB.DBO(config.HASHDB)
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
            self.m.update(data)
            self.length+=len(data)

        def finish(self):
            ## Dont do short files
            if self.length<16: return
            
            dbh_flag=DB.DBO(config.HASHDB)
            dbh_flag.execute("select filename,Name from NSRL_hashes join NSRL_products on productcode=Code where md5=%r limit 1",self.m.digest())
            nsrl=dbh_flag.fetch()
            if not nsrl: nsrl={}
            
            dbh=DB.DBO(self.case)
            inode_id = self.fd.lookup_id()
            dbh.insert('hash',
                       inode_id = inode_id,
                       binary_md5 = self.m.digest(),
                       NSRL_product = nsrl.get('Name','-'),
                       NSRL_filename = nsrl.get('filename','-'),
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
        dbh.check_index('hash','inode_id')
        
        try:
            result.table(
                elements = [ InodeIDType(case=query['case']),
                             FilenameType(case=query['case']),
                             StringType('File Type', 'type', table='type'),
                             StringType('NSRL Product','NSRL_product', table='hash'),
                             StringType('NSRL Filename','NSRL_filename', table='hash'),
                             HashType() ],
                table='hash',
                case=query['case'],
                )
        except DB.DBError,e:
            result.para("Error reading the MD5 hash table. Did you remember to run the MD5Scan scanner?")
            result.para("Error reported was:")
            result.text(e,style="red")
         
## UnitTests:
import unittest
import pyflag.pyflagsh as pyflagsh
import pyflag.tests

class HashScanTest(pyflag.tests.ScannerTest):
    """ Hash Scanner Tests """
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
                             argv=["*",'MD5Scan'])        
