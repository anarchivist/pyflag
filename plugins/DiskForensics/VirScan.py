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

    class Scan:
        def __init__(self, inode,ddfs,outer,factories=None):
            self.inode = inode
            self.window = ''
            self.dbh=outer.dbh
            self.table=outer.table
            self.virus = None
            self.windowsize = 1000
            self.scanner = VScan()

        def process(self, data,metadata=None):
            if not self.virus:
                buf = self.window + data
                self.virus = self.scanner.scan(buf)
                self.window = buf[-self.windowsize:]

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
            
