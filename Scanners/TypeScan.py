""" This scanner scans a file for its mime type and magic """
import magic
import pyflag.FlagFramework as FlagFramework
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.FileSystem as FileSystem
import pyflag.DB as DB
import os.path
import pyflag.logging as logging
from Scanners import *

class TypeScan(GenScanFactory):
    """ scan file and record file type (magic)

    In addition to recording the file type, this class can also perform
    an action based on the mime type of the file"""
        
    def __init__(self,dbh, table):
        dbh.execute(""" CREATE TABLE IF NOT EXISTS `type_%s` (
        `inode` varchar( 20 ) NOT NULL,
        `mime` varchar( 50 ) NOT NULL,
        `type` tinytext NOT NULL )""" , table)
        self.dbh=dbh
        self.table=table

    def reset(self):
        self.dbh.execute("drop table `type_%s`",self.table)
        self.dbh.execute("delete from `inode_%s` where inode like '%%|Z|%%'",self.table)
        self.dbh.execute("delete from `file_%s` where inode like '%%|Z|%%'",self.table)

    def destroy(self):
        self.dbh.execute('ALTER TABLE type_%s ADD INDEX(inode)', self.table)

    class Scan:
        size=0
        
        def __init__(self, inode,ddfs,outer,factories=None):
            self.dbh=outer.dbh
            self.table=outer.table
            self.ddfs = ddfs
            self.filename=self.ddfs.lookup(inode=inode)
            self.inode = inode
            self.type_mime = None
            self.type_str = None
        
        def process(self, data,metadata=None):
            if(self.size < 100):
                magic = FlagFramework.Magic(mode='mime')
                magic2 = FlagFramework.Magic()
                self.type_mime = magic.buffer(data)
                self.type_str = magic2.buffer(data)
                metadata['mime']=self.type_mime
                metadata['magic']=self.type_str

            self.size = self.size + len(data)

        def finish(self):
            # insert type into DB
            self.dbh.execute('INSERT INTO type_%s VALUES(%r, %r, %r)', (self.table, self.inode, self.type_mime, self.type_str))
            # if we have a mime handler for this data, call it
            logging.log(logging.DEBUG, "Handling inode %s = %s, mime type: %s, magic: %s" % (self.inode,self.filename,self.type_mime, self.type_str))
