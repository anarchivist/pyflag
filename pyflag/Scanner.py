# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG  $Name:  $ $Date: 2004/09/05 15:19:05 $
# ******************************************************
#
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# *
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
# ******************************************************

""" This module implements a scanning mechanism for operating on all files within a given filesystem.

The GenScan abstract class documents a Generic scanner. This scanner is applied on every file in a filesystem during a run of the FileSystem's scan method.
"""
import pyflag.FlagFramework as FlagFramework
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.FileSystem as FileSystem
import pyflag.DB as DB
import os.path
import pyflag.logging as logging

class GenScanFactory:
    """ Abstract Base class for scanner Factories.
    
    The Scanner Factory is a specialised class for producing scanner objects. It will be instantiated once per filesystem at the begining of the run, and destroyed at the end of the run. It will be expected to produce a new Scanner object for each file in the filesystem.
    """
    class Scan:
        """ This is the actual scanner class that will be instanitated once for each file in the filesystem.

        factories is a list of factory scanner objects that should be used to scan new files that have been revealed due to this particular scanner. This is mostly used for iteratively scanning files found inside other files (e.g. zip archieves etc).
        Note that this is a nested class since it may only be instantiated by first instantiating a Factory object. """
        def __init__(self, inode,dbh,table,factories=None):
            self.inode = inode
            self.size = 0

        def process(self, data):
            """ process the chunk of data.

            This function is given a chunk of data from the file - this may not be the complete file. Sometimes it may be appropropriate to accumulate the data until the finish method is called. """
            pass

        def finish(self):
            """ all data has been provided to process, finish up """
            pass

    def __init__(self,dbh, table):
        """ do any initialisation tasks, such as creating tables 
            this is called like C.__dict__['init'] where C is the class name, 
            its an ugly way to have class methods in python """
        pass

    def destroy(self):
        """ Final destructor called on the factory to finish the scan operation. This is sometimes used to make indexes etc """
        pass

    def reset(self):
        """ This method drops the relevant tables in the database, restoring the db to the correct state for rescanning to take place """
        pass

import magic
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

        def process(self, data):
            if(self.size == 0):
                magic = FlagFramework.Magic(mode='mime')
                magic2 = FlagFramework.Magic()
                self.type_mime = magic.buffer(data)
                self.type_str = magic2.buffer(data)

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

        def process(self, data):
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

#this is in a try block to allow for flag running when clamav is not installed.
try:
    import clamav
    clamav_module_present=1
    
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
            def __init__(self, inode,ddfs,dbh,table,factories=None):
                self.inode = inode
                self.window = ''
                self.dbh=dbh
                self.table=table
                self.virus = None
                self.windowsize = 1000
                self.scanner = VScan()

            def process(self, data):
                if not self.virus:
                    buf = self.window + data
                    self.virus = self.scanner.scan(buf)
                    self.window = buf[-self.windowsize:]

            def finish(self):
                if self.virus:
                    self.dbh.execute("INSERT INTO virus_%s VALUES(%r,%r)", (self.table, self.inode, self.virus))

except ImportError:
    clamav_module_present=0

scanners=[]
for c in dir():
    try:
        if issubclass(globals()[c],GenScanFactory) and c != 'GenScanFactory':
            scanners.append(globals()[c])
    except TypeError:
        pass

