# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.76 Date: Sun Apr 17 21:48:37 EST 2005$
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
    """ scan file and record file Hash (MD5Sum) """
    default = True
    def __init__(self,dbh, table,fsfd):
        dbh.execute(""" CREATE TABLE IF NOT EXISTS `md5_%s` (
        `inode` varchar( 20 ) NOT NULL default '',
        `md5` varchar( 35 ) NOT NULL default '',
        `binary_md5` varchar( 16 ) binary NOT NULL default '',
        `NSRL_productcode` int(11) not NULL default '0',
        `NSRL_filename` varchar(60) not NULL default ''
        )""",table)
        self.dbh=dbh
        self.table=table

    def reset(self):
        GenScanFactory.reset(self)
        self.dbh.execute("drop table `md5_%s`",self.table)

    def destroy(self):
        pass
#        self.dbh.execute('ALTER TABLE md5_%s ADD INDEX(inode, md5)', self.table)

    class Scan(BaseScanner):
        def __init__(self, inode,ddfs,outer,factories=None):
            BaseScanner.__init__(self, inode,ddfs,outer,factories)
            self.inode = inode
            self.ddfs=ddfs
            self.dbh=outer.dbh
            self.table=outer.table
            self.m = md5.new()

            # Check that we have not done this inode before
            self.dbh.check_index("md5_%s" % self.table,"inode")
            self.dbh.execute("select * from md5_%s where inode=%r",(self.table,inode))
            if self.dbh.fetch():
                self.ignore=1
            else:
                self.ignore=0

        def process(self, data,metadata=None):
            self.m.update(data)
            if len(data)<16: self.ignore=1

        def finish(self):
            if self.ignore:
                return
            
            dbh_flag=DB.DBO(None)
            dbh_flag.check_index("NSRL_hashes","md5",4)
            dbh_flag.execute("select filename,productcode from NSRL_hashes where md5=%r",self.m.digest())
            nsrl=dbh_flag.fetch()
            if not nsrl: nsrl={}

            self.dbh.execute('INSERT INTO md5_%s set inode=%r,md5=%r,binary_md5=%r,NSRL_productcode=%r, NSRL_filename=%r', (self.table, self.inode, self.m.hexdigest(),self.m.digest(),nsrl.get('productcode',''),nsrl.get('filename','')))

class HashComparison(Reports.report):
    """ Compares MD5 hash against the NSRL database to classify files """
    parameters = {'fsimage':'fsimage'}
    name = "MD5 Hash comparison"
    family = "Disk Forensics"
    description="This report will give a table for describing what the type of file this is based on the MD5 hash matches"
    progress_dict = {}

    def form(self,query,result):
        try:
            result.case_selector()
            if query['case']!=config.FLAGDB:
               result.meta_selector(case=query['case'],property='fsimage')
        except KeyError:
            return result

    def progress(self,query,result):
        result.heading("Calculating Hash tables");

    def reset(self,query):
        dbh = self.DBO(query['case'])
        tablename = dbh.MakeSQLSafe(query['fsimage'])
        dbh.execute('drop table hash_%s',tablename);

    def analyse(self,query):
        dbh = self.DBO(query['case'])
        pdbh=self.DBO(None)
        tablename = dbh.MakeSQLSafe(query['fsimage'])
        pdbh.check_index("NSRL_products","Code")
        dbh.check_index("type_%s" % tablename,"inode")
        dbh.execute("create table `hash_%s` select a.inode as `Inode`,concat(path,b.name) as `Filename`,d.type as `File Type`,if(c.Code=0,'Unknown',c.Name) as `NSRL Product`,c.Code as `NSRL Code`,a.NSRL_filename,md5 as `MD5` from md5_%s as a,%s.NSRL_products as c, type_%s as d left join file_%s as b on a.inode=b.inode   where  a.NSRL_productcode=c.Code and d.inode=a.inode group by Inode,`NSRL Code`,MD5",(tablename,tablename,config.FLAGDB,tablename,tablename))

    def display(self,query,result):
        result.heading("MD5 Hash comparisons for %s" % query['fsimage'])
        dbh=self.DBO(query['case'])
        tablename = dbh.MakeSQLSafe(query['fsimage'])

        def RenderNSRL(value):
            tmp=self.ui(result)
            if value>0:
                tmp.icon("yes.png")
            else:
                tmp.icon("no.png")

            return tmp
        
        result.table(
            columns=('Inode','Filename', '`File Type`', '`NSRL Product`','NSRL_filename', '`MD5`'),
            names=('Inode','Filename','File Type','NSRL Product','NSRLFilename','MD5'),
            table='hash_%s ' % (tablename),
            case=query['case'],
            links=[ FlagFramework.query_type((),case=query['case'],family=query['family'],fsimage=query['fsimage'],report='ViewFile',__target__='inode')]
            )
