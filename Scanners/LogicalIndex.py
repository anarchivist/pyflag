""" This scanner uses the indexing tools to scan the logical files within an image. This allows us to do keyword matching against compressed files, PST files etc.
"""
import pyflag.logging as logging
import pyflag.FlagFramework as FlagFramework
from Scanners import *
import index,os
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.DB as DB

class Index(GenScanFactory):
    """ Keyword Index files """
    def __init__(self,dbh,table):
        """ This creates the LogicalIndex table and initialised the index file """
        self.dbh=dbh
        ## This keeps the current offset in the logical image. FIXME:
        ## When running in a distributed environment this is not
        ## accessible - maybe we need to pass this in the metadata?
        self.offset = 0
        self.table=table
        self.dbh.execute("create table if not exists `LogicalIndex_%s` (`inode` VARCHAR( 20 ) NOT NULL ,`offset` BIGINT NOT NULL ,`id` INT NOT NULL AUTO_INCREMENT, primary key(id))",(table))
        self.filename = "%s/LogicalIndex_%s.idx" % (config.RESULTDIR,table)
        try:
            ## Is the file already there?
            self.index = index.Load(self.filename)
        except IOError:
            ## If not we create it
            self.index = index.index(self.filename)
            pydbh = DB.DBO(None)
            pydbh.execute("select word from dictionary")
            for row in pydbh:
                self.index.add(row['word'])
                
    def reset(self):
        """ This deletes the index file and drops the LogicalIndex table """
        ## First destroy the object and then try to remove the index file
        del self.index
        os.remove(self.filename)
        self.dbh.execute("drop table if exists `LogicalIndex_%s`",(self.table))
        ## Here we reset all reports that searched this disk
        FlagFramework.reset_all(case=self.dbh.case,report='SearchIndex', family='DiskForensics')
        self.dbh.execute("drop table if exists `LogicalKeyword_%s`",(self.table))

    def destroy(self):
        ## Destroy our index handle which will close the file and free memory
        del self.index

    class Scan:
        def __init__(self, inode,ddfs,outer,factories=None):
            self.index = outer.index
            self.dbh=outer.dbh
            self.offset=outer.offset
            self.outer=outer
            self.dbh.execute("insert into `LogicalIndex_%s` set inode=%r,offset=%r",(outer.table,inode,self.offset))

        def process(self,data,metadata=None):
            self.index.index_buffer(self.outer.offset,data)
            self.outer.offset+=len(data)

        def finish(self):
            pass
#            self.outer.offset=self.offset
