# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.80.1 Date: Tue Jan 24 13:51:25 NZDT 2006$
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
import pyflag.logging as logging
from pyflag.Scanner import *
                  
import md5
class MD5Scan(GenScanFactory):
    """ Scan file and record file Hash (MD5Sum) """
    default = False
    depends = ['TypeScan']

    def __init__(self,fsfd):
        GenScanFactory.__init__(self, fsfd)
        
        self.dbh.execute(""" CREATE TABLE IF NOT EXISTS `md5` (
        `inode` varchar( 250 ) NOT NULL default '',
        `md5` varchar( 35 ) NOT NULL default '',
        `binary_md5` varchar( 16 ) binary NOT NULL default '',
        `NSRL_productcode` int(11) not NULL default '0',
        `NSRL_filename` varchar(60) not NULL default ''
        )""")

    def reset(self):
        GenScanFactory.reset(self)
        self.dbh.execute("drop table `md5`")

    def destroy(self):
        pass

    class Scan(BaseScanner):
        def __init__(self, inode,ddfs,outer,factories=None,fd=None):
            BaseScanner.__init__(self, inode,ddfs,outer,factories, fd=fd)
            self.m = md5.new()

##            # Check that we have not done this inode before
##            self.dbh.check_index("md5","inode")
##            self.dbh.execute("select * from md5 where inode=%r",(inode))
##            if self.dbh.fetch():
##                self.ignore=1
##            else:
##                self.ignore=0

        def process(self, data,metadata=None):
            self.m.update(data)
            if len(data)<16: self.ignore=True

        def finish(self):
            if self.ignore:
                return
            
            dbh_flag=DB.DBO(None)
            dbh_flag.check_index("NSRL_hashes","md5",4)
            dbh_flag.execute("select filename,productcode from NSRL_hashes where md5=%r",self.m.digest())
            nsrl=dbh_flag.fetch()
            if not nsrl: nsrl={}

            self.dbh.execute('INSERT INTO md5 set inode=%r,md5=%r,binary_md5=%r,NSRL_productcode=%r, NSRL_filename=%r', (self.inode, self.m.hexdigest(),self.m.digest(),nsrl.get('productcode',0),nsrl.get('filename','')))

class HashComparison(Reports.report):
    """ Compares MD5 hash against the NSRL database to classify files """
    name = "MD5 Hash comparison"
    family = "Disk Forensics"
    description="This report will give a table for describing what the type of file this is based on the MD5 hash matches"
    progress_dict = {}

    def form(self,query,result):
        result.case_selector()

    def progress(self,query,result):
        result.heading("Calculating Hash tables");

    def reset(self,query):
        dbh = self.DBO(query['case'])
        dbh.execute('drop table hash');

    def analyse(self,query):
        dbh = self.DBO(query['case'])
        pdbh=self.DBO(None)
        try:
            pdbh.check_index("NSRL_products","Code")
        except DB.DBError,e:
            raise Reports.ReportError("Unable to find an NSRL table in the pyflag database. Create one using the utilities/load_nstl.py script." % e)
            
        try:
            dbh.check_index("type","inode")
            dbh.execute("drop table if exists  `hash`")
            dbh.execute("create table `hash` select a.inode as `Inode`,concat(path,b.name) as `Filename`,d.type as `File Type`,if(c.Code=0,'Unknown',c.Name) as `NSRL Product`,c.Code as `NSRL Code`,a.NSRL_filename,md5 as `MD5` from md5 as a join %s.NSRL_products as c join type as d on (a.NSRL_productcode=c.Code and d.inode=a.inode) left join file as b on (a.inode=b.inode) group by Inode,`NSRL Code`,MD5",(config.FLAGDB,))
        except DB.DBError,e:
            raise Reports.ReportError("Unable to find the types table for the current image. Did you run the TypeScan Scanner?.\n Error received was %s" % e)
        
    def display(self,query,result):
        result.heading("MD5 Hash comparisons")
        dbh=self.DBO(query['case'])

        def RenderNSRL(value):
            tmp=self.ui(result)
            if value>0:
                tmp.icon("yes.png")
            else:
                tmp.icon("no.png")

            return tmp

        try:
            result.table(
                columns=('Inode','Filename', '`File Type`', '`NSRL Product`','NSRL_filename', '`MD5`'),
                names=('Inode','Filename','File Type','NSRL Product','NSRLFilename','MD5'),
                table='hash ',
                case=query['case'],
                links=[ FlagFramework.query_type((),case=query['case'],family=query['family'],report='ViewFile',__target__='inode')]
                )
        except DB.DBError,e:
            result.para("Error reading the MD5 hash table. Did you remember to run the MD5Scan scanner?")
            result.para("Error reported was:")
            result.text(e,color="red")
         
