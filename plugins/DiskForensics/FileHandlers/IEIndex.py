""" This Module will automatically load in IE History files (index.dat) files.

We use the files's magic to trigger the scanner off - so its imperative that the TypeScan scanner also be run or this will not work. We also provide a report to view the history files.
"""
import os.path
import pyflag.logging as logging
import pyflag.Scanner as Scanner
import pyflag.Reports as Reports
import pyflag.conf
config=pyflag.conf.ConfObject()

## raise Exception("This module not finished yet")

class IEIndex(Scanner.GenScanFactory):
    """ Load in IE History files """
    def __init__(self,dbh, table,fsfd):
        self.dbh=dbh
        self.table=table

    def prepare(self):
        self.dbh.MySQLHarness("pasco -t %s -g create " % (self.table))

    def reset(self):
        self.dbh.MySQLHarness("pasco -t %s -g drop " % (self.table))
        
    def destroy(self):
        self.dbh.execute('ALTER TABLE history_%s ADD INDEX(url(10))', self.table)

    class Scan(Scanner.StoreAndScanType):
        types = ['application/x-ie-index']

        def external_process(self,name):
            self.dbh.MySQLHarness("pasco -t %s -p %r %s " % (self.table,self.ddfs.lookup(inode=self.inode),name))

class IEHistory(Reports.report):
    """ View IE browsing history with pasco"""
    parameters = {'fsimage':'fsimage'}
    name = "IE Browser History (pasco)"
    family = "Disk Forensics"
    description="This report will display all IE browsing history data found in index.dat files"
    def form(self,query,result):
        try:
            result.case_selector()
            if query['case']!=config.FLAGDB:
               result.meta_selector(case=query['case'],property='fsimage')
        except KeyError:
            return result

    def display(self,query,result):
        result.heading("IE History for %s" % query['fsimage'])
        dbh=self.DBO(query['case'])
        tablename = dbh.MakeSQLSafe(query['fsimage'])

        result.table(
            columns=('path','type','url','modified','accessed','concat(filepath,filename)','headers'),
            names=('Path','Type','URL','Modified','Accessed','Filename','Headers'),
            table=('history_%s' % (tablename)),
            case=query['case']
            )
