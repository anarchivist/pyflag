""" A Scanner for calculating the MD5 of all files on the filesystem """
import pyflag.FlagFramework as FlagFramework
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.FileSystem as FileSystem
import pyflag.DB as DB
import os.path
import pyflag.logging as logging
from Scanners import *
                  
import md5
class MD5Scan(GenScanFactory):
    """ scan file and record file Hash (MD5Sum) """

    def __init__(self,dbh, table):
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
        self.dbh.execute("drop table `md5_%s`",self.table)

    def destroy(self):
        self.dbh.execute('ALTER TABLE md5_%s ADD INDEX(inode, md5)', self.table)

    class Scan:
        def __init__(self, inode,ddfs,dbh,table,factories=None):
            self.inode = inode
            self.ddfs=ddfs
            self.dbh=dbh
            self.table=table
            self.m = md5.new()

            # Check that we have not done this inode before
            dbh.execute("select * from md5_%s where inode=%r",(self.table,inode))
            if dbh.fetch():
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
            dbh_flag.execute("select filename,productcode from NSRL_hashes where md5=%r",self.m.digest())
            nsrl=dbh_flag.fetch()
            if not nsrl: nsrl={}

            self.dbh.execute('INSERT INTO md5_%s set inode=%r,md5=%r,binary_md5=%r,NSRL_productcode=%r, NSRL_filename=%r', (self.table, self.inode, self.m.hexdigest(),self.m.digest(),nsrl.get('productcode',''),nsrl.get('filename','')))

