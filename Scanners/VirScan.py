""" A Scanner that uses ClamAV virus scanner to virus scan all files in the filesystem """
import pyflag.FlagFramework as FlagFramework
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.FileSystem as FileSystem
import pyflag.DB as DB
import os.path
import pyflag.logging as logging
from Scanners import *

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
    def __init__(self,dbh, table):
        dbh.execute(""" CREATE TABLE IF NOT EXISTS `virus_%s` (
        `inode` varchar( 20 ) NOT NULL,
        `virus` tinytext NOT NULL )""", table)
        self.dbh=dbh
        self.table=table

    def destroy(self):
        self.dbh.execute('ALTER TABLE virus_%s ADD INDEX(inode)', self.table)

    def reset(self):
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

