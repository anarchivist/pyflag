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
                metadata['mime']=self.type_mime
                metadata['magic']=self.type_str

##                # is there a handler for this mime-type? If so we save the data for later
##                if self.handlers.has_key(self.type_mime):
##                    self.fdata = data
            else:
                pass
##                if self.fdata:
##                    self.fdata = self.fdata + data

            self.size = self.size + len(data)

        def finish(self):
            # insert type into DB
            self.dbh.execute('INSERT INTO type_%s VALUES(%r, %r, %r)', (self.table, self.inode, self.type_mime, self.type_str))
            # if we have a mime handler for this data, call it
            logging.log(logging.DEBUG, "Handling inode %s = %s, mime type: %s, magic: %s" % (self.inode,self.filename,self.type_mime, self.type_str))
            if self.fdata:
                self.handlers[self.type_mime]()

        def ZipHandler(self):
            """ Process data as ZIP file """
            import zipfile,cStringIO
            data=cStringIO.StringIO(self.fdata)
            zip=zipfile.ZipFile(data)

            ## List all the files in the zip file:
            sub_inode=0
            for i in zip.filelist:
                dirs=i.filename.split('/')
                for d in range(0,len(dirs)):
                    path='%s/%s' % (self.filename,'/'.join(dirs[0:d]))
                    if not path.endswith('/'): path=path+'/'

                    self.ddfs.dbh.execute("select * from file_%s where path=%r and name=%r",(self.ddfs.table,path,dirs[d]))
                    if not self.ddfs.dbh.fetch():
                        sub_inode+=1
                        self.ddfs.dbh.execute("insert into file_%s set path=%r,name=%r,status='alloc',mode='d/d',inode='%s|Z|%s'",(self.ddfs.table,path,dirs[d],self.inode,sub_inode))

                ## Add the file itself to the file table:
                self.ddfs.dbh.execute("update file_%s set mode='r/r' where path=%r and name=%r",(self.ddfs.table,path,dirs[-1]))
                ## Add the file to the inode table:
                self.ddfs.dbh.execute("insert into inode_%s set inode='%s|Z|%s',size=%r,mtime=unix_timestamp('%s-%s-%s:%s:%s:%s')",(self.ddfs.table,self.inode,sub_inode,i.file_size)+i.date_time)

                ## Now call the scanners on this new file (FIXME limit the recursion level here)
                if self.factories:
                    try:
                        data=zip.read(i.filename)
                    except zipfile.zlib.error:
		        continue
                    objs = [c.Scan("%s|Z|%s" % (self.inode,sub_inode),self.ddfs,self.ddfs.dbh,self.ddfs.table,factories=self.factories) for c in self.factories]
                    for o in objs:
                        o.process(data)
                        o.finish()

            ## Set the zip file to be a d/d entry so it looks like its a virtual directory:
            self.ddfs.dbh.execute("update file_%s set mode='d/d' where inode=%r",(self.ddfs.table,self.inode))


        def RegistryHandler(self):
            """ This handler automatically loads in registry files as they are scanned """
            filename="%s/%s" % (config.RESULTDIR,os.path.basename(self.ddfs.lookup(inode=self.inode)))
            fd=open(filename,'w')
            fd.write(self.fdata)
            fd.close()
            self.dbh.execute('create table if not exists reg_%s (`path` CHAR(250), `size` SMALLINT, `type` CHAR(12),`reg_key` VARCHAR(200),`value` text)',self.ddfs.table)
            self.dbh.MySQLHarness("regtool -f %s -t reg_%s -p %r " % (filename,self.ddfs.table,self.ddfs.lookup(inode=self.inode)))
            ## dbh.execute("alter table reg_%s add index(path(100))",tablename)
                
            ## Now create the directory indexes to speed up tree navigation:
            self.dbh.execute("create table if not exists regi_%s (`dirname` TEXT NOT NULL ,`basename` TEXT NOT NULL,KEY `dirname` (`dirname`(100)))",self.ddfs.table)
            dirtable = {}
            self.dbh.execute("select path from reg_%s",self.ddfs.table)
            for row in self.dbh:
                array=row['path'].split("/")
                while len(array)>1:
                    new_dirname="/".join(array[:-1])
    #                if not new_dirname: new_dirname='/'
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
                    self.dbh.execute("insert into regi_%s set dirname=%r,basename=%r",(self.ddfs.table,k,name))
                    
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
