""" This Scanner will automatically load in IE History files (index.dat) files.

We use the files's magic to trigger this scanner off - so its imperative that the TypeScan scanner also be run or this will not work.
"""
import os.path
import pyflag.logging as logging
import pyflag.Scanner as Scanner

## raise Exception("This module not finished yet")

class IEIndex(Scanner.GenScanFactory):
    """ Load in IE History files """
    def __init__(self,dbh, table):
        self.dbh=dbh
        self.table=table
        dbh.MySQLHarness("pasco -t %s -g create " % (table))

    def reset(self):
        self.dbh.MySQLHarness("pasco -t %s -g drop " % (self.table))
        
    def destroy(self):
        self.dbh.execute('ALTER TABLE history_%s ADD INDEX(url(10))', self.table)

    class Scan(Scanner.StoreAndScan):
        def boring(self,metadata):
            if metadata['mime']=='application/x-ie-index':
                return False
            return True

        def external_process(self,name):
            self.dbh.MySQLHarness("pasco -t %s -p %r %s " % (self.table,self.ddfs.lookup(inode=self.inode),name))
