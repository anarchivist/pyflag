""" This Scanner handles windows registry files.

We use the files's magic to trigger this scanner off - so its imperative that the TypeScan scanner also be run or this will not work.
"""
import os.path
import pyflag.logging as logging
from Scanners import *

class RegistryScan(GenScanFactory):
    """ Load in Windows Registry files """
    def __init__(self,dbh, table):
        self.dbh=dbh
        self.table=table
        self.dbh.execute('create table if not exists reg_%s (`path` CHAR(250), `size` SMALLINT, `type` CHAR(12),`reg_key` VARCHAR(200),`value` text)',self.table)

    def reset(self):
        self.dbh.execute('drop table if exists reg_%s',self.table)
        self.dbh.execute('drop table if exists regi_%s',self.table)
        
    def destroy(self):
        ## Create the directory indexes to speed up tree navigation:
        self.dbh.execute("create table if not exists regi_%s (`dirname` TEXT NOT NULL ,`basename` TEXT NOT NULL,KEY `dirname` (`dirname`(100)))",self.table)
        dirtable = {}
        self.dbh.execute("select path from reg_%s",self.table)
        for row in self.dbh:
            array=row['path'].split("/")
            while len(array)>1:
                new_dirname="/".join(array[:-1])
                new_basename=array.pop()
                try:
                    ## See if the value is already in the dictionary
                    dirtable[new_dirname].index(new_basename)
                except ValueError:
                    dirtable[new_dirname].append(new_basename)
                except KeyError:
                    dirtable[new_dirname]=[new_basename]

        for k,v in dirtable.items():
            for name in v:
                self.dbh.execute("insert into regi_%s set dirname=%r,basename=%r",(self.table,k,name))

        ## Add indexes:
        self.dbh.execute("alter table reg_%s add index(path)",self.table)

    class Scan(StoreAndScan):
        def boring(self,metadata):
            return metadata['mime'] not in (
                'application/x-winnt-registry',
                'application/x-win9x-registry',
                )

        def external_process(self,filename):
            self.dbh.MySQLHarness("regtool -f %s -t reg_%s -p %r " % (filename,self.ddfs.table,self.ddfs.lookup(inode=self.inode)))
