""" This Scanner will automatically load in IE History files (index.dat) files.

We use the files's magic to trigger this scanner off - so its imperative that the TypeScan scanner also be run or this will not work.
"""
import pyflag.FlagFramework as FlagFramework
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.FileSystem as FileSystem
import pyflag.DB as DB
import os.path
import pyflag.logging as logging
from Scanners import *

raise Exception("This module not finished yet")

class IEIndex(GenScanFactory):
    """ Load in IE History files """
    def __init__(self,dbh, table):
        self.dbh=dbh
        self.table=table
        dbh.MySQLHarness("pasco -t %s -g create " % (table))

    def reset(self):
        self.dbh.MySQLHarness("pasco -t %s -g drop " % (self.table))
        
    def destroy(self):
        self.dbh.execute('ALTER TABLE history_%s ADD INDEX(url)', self.table)

    class Scan:
        def __init__(self, inode,ddfs,dbh,table,factories=None):
            self.size = 0
            self.dbh=dbh
            self.table=table
            self.ddfs=ddfs
            self.factories=factories
            self.filename=self.ddfs.lookup(inode=inode)
            self.inode = inode
            self.type_mime = None
            self.type_str = None
            self.fdata = None
            self.handlers = { 'application/x-zip':self.ZipHandler,
                              'application/x-winnt-registry' : self.RegistryHandler,
                              'application/x-win9x-registry' : self.RegistryHandler,
                              'application/x-ie-index' : self.IEIndexHandler,
                              }

        def process(self, data,metadata=None):
            if(self.size == 0):
                magic = FlagFramework.Magic(mode='mime')
                magic2 = FlagFramework.Magic()
                self.type_mime = magic.buffer(data)
                self.type_str = magic2.buffer(data)
                if metadata:
                    metadata['mime']=self.type_mime
                    metadata['magic']=self.type_str

                # is there a handler for this mime-type? If so we save the data for later
                if self.handlers.has_key(self.type_mime):
                    self.fdata = data
            else:
                if self.fdata:
                    self.fdata = self.fdata + data

            self.size = self.size + len(data)

        def finish(self):
            # insert type into DB
            self.dbh.execute('INSERT INTO type_%s VALUES(%r, %r, %r)', (self.table, self.inode, self.type_mime, self.type_str))
            # if we have a mime handler for this data, call it
            logging.log(logging.DEBUG, "Handling inode %s = %s, mime type: %s, magic: %s" % (self.inode,self.filename,self.type_mime, self.type_str))
            if self.fdata:
                self.handlers[self.type_mime]()


        def IEIndexHandler(self):
            """ This handler automatically loads in Internet Explorer index.dat files as they are scanned """
            filename="%s/%s" % (config.RESULTDIR,self.dbh.MakeSQLSafe(self.ddfs.lookup(inode=self.inode)))
            fd=open(filename,'w')
            fd.write(self.fdata)
            fd.close()
            #self.dbh.execute('create table if not exists reg_%s (`path` CHAR(250), `size` SMALLINT, `type` CHAR(12),`reg_key` VARCHAR(200),`value` text)',self.ddfs.table)
            self.dbh.MySQLHarness("pasco -t %s -g create " % (self.ddfs.table))
            self.dbh.MySQLHarness("pasco -t %s -p %r %s " % (self.ddfs.table,self.ddfs.lookup(inode=self.inode),filename))
            ## dbh.execute("alter table reg_%s add index(path(100))",tablename)
                
            ## Now create the directory indexes to speed up tree navigation:
            self.dbh.execute("create table if not exists regi_%s (`dirname` TEXT NOT NULL ,`basename` TEXT NOT NULL,KEY `dirname` (`dirname`(100)))",self.ddfs.table)
   #         dirtable = {}
   #         self.dbh.execute("select path from reg_%s",self.ddfs.table)
   #         for row in self.dbh:
   #             array=row['path'].split("/")
   #             while len(array)>1:
   #                 new_dirname="/".join(array[:-1])
    #                if not new_dirname: new_dirname='/'
   #                 new_basename=array.pop()
   #                 try:
   #                     ## See if the value is already in the dictionary
   #                     dirtable[new_dirname].index(new_basename)
   #                 except ValueError:
   #                     dirtable[new_dirname].append(new_basename)
   #                 except KeyError:
   #                     dirtable[new_dirname]=[new_basename]
#
#            for k,v in dirtable.items():
#                for name in v:
#                    self.dbh.execute("insert into regi_%s set dirname=%r,basename=%r",(self.ddfs.table,k,name))
