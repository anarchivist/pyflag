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
#  Version: FLAG $Version: 0.84RC1 Date: Fri Feb  9 08:22:13 EST 2007$
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

""" This module contains classes considered to be part of the core functionality of PyFlag.

These are needed by both the DiskForensics and NetworkForensics
"""
import pyflag.FileSystem as FileSystem
import pyflag.IO as IO
import pyflag.Reports as Reports
import pyflag.conf
config=pyflag.conf.ConfObject()
import os.path
import pyflag.DB as DB
import pyflag.Farm as Farm
import pyflag.Scanner as Scanner
import pyflag.pyflaglog as pyflaglog
import os
import pyflag.FlagFramework as FlagFramework
import pyflag.Registry as Registry

config.add_option("SCHEMA_VERSION", default=1, absolute=True,
                  help="Current schema version")

class IO_File(FileSystem.File):
    """ A VFS Driver to make the io source available.

    Basically we proxy the IO source driver in here.
    """
    specifier = "I"

    def __init__(self, case, fd, inode):
        FileSystem.File.__init__(self, case, fd, inode)

        ## The format of the inode is Iname .Where name is the name of
        ## the IO source.
        self.name = inode[1:]
        self.io = IO.open(case, self.name)
        self.size = self.io.size

        ## This source should not be scanned directly.
        self.ignore = True

    def read(self, length=None):
        if length==None:
            return self.io.read()
        
        return self.io.read(length)

    def seek(self, offset, rel=0):
        if rel==0:
            return self.io.seek(offset)
        elif rel==1:
            return self.io.seek(offset + self.tell())
        elif rel==2:
            return self.io.seek(offset + self.size)

    def tell(self):
        return self.io.tell()
        
    def explain(self, result):
        tmp = result.__class__(result)
        self.io.explain(tmp)
        dbh = DB.DBO(self.case)    
        result.row("IO Subsys %s:" % self.name, tmp, valign="top")
        result.row("Mount point",dbh.get_meta("mount_point_%s" % self.name))

import sys

class OffsetFile(FileSystem.File):
    """ A simple offset:length file driver.

    The inode name specifies an offset and a length into our parent Inode.
    The format is offset:length
    """
    specifier = 'o'
    def __init__(self, case, fd, inode):
        FileSystem.File.__init__(self, case, fd, inode)

        ## We parse out the offset and length from the inode string
        tmp = inode.split('|')[-1]
        tmp = tmp[1:].split(":")
        self.offset = int(tmp[0])
        self.readptr=0

        ## Seek our parent file to its initial position
        self.fd.seek(self.offset)

        try:
            self.size=int(tmp[1])
            if self.size == 0: self.size=sys.maxint
        except IndexError:
            self.size=sys.maxint

        # crop size if it overflows IOsource
        # some iosources report size as 0 though, we must check or size will
        # always be zero
        if fd.size != 0 and self.size + self.offset > fd.size:
            self.size = fd.size - self.offset

    def seek(self,offset,whence=0):
        if whence==2:
            self.readptr=self.size+offset
        elif whence==1:
            self.readptr+=offset
        else:
            self.readptr=offset

        self.fd.seek(self.offset + self.readptr)

    def tell(self):
        return self.readptr
    
    def read(self,length=None):
        available = self.size - self.readptr
        if length==None:
            length=available
        else:
            if length > available:
                length = available

        if(length<0): return ''

        result=self.fd.read(length)
        
        self.readptr+=len(result)
        return result

class Help(Reports.report):
    """ This facility displays helpful messages """
    hidden = True
    family = "Misc"
    name = "Help"
    parameters = {'topic':'any'}

    def form(self,query,result):
        result.textfield("Topic",'topic')
    
    def display(self,query,result):
        fd=open("%s/%s.html" % (config.DATADIR, os.path.normpath(query['topic'])))
        result.result+=fd.read()
        result.decoration='naked'

## IO subsystem unit tests:
import unittest
import md5,random,time
import pyflag.tests as tests
from pyflag.FileSystem import DBFS

class IOSubsysTests(tests.FDTest):
    """ Testing IO Subsystem handling """
    def setUp(self):
        self.fd = IO_File('PyFlagNTFSTestCase', None, 'Itest')

class OffsetFileTests(tests.FDTest):
    """ Testing OffsetFile handling """
    test_case = "PyFlagNTFSTestCase"
    test_inode = "Itest|o1000:1000"
    
    def testMisc(self):
        """ Test OffsetFile specific features """
        ## Make sure we are the right size
        self.assertEqual(self.fd.size, 1000)
        
        fd2 = IO_File('PyFlagNTFSTestCase', None, 'Itest')
        fd2.seek(1000)
        data=fd2.read(1000)

        self.fd.seek(0)
        data2 = self.fd.read()

        ## Make sure that we are reading the same data with and
        ## without the offset:
        self.assertEqual(data2, data)

class Scan(Farm.Task):
    """ A task to distribute scanning among all workers """
    def run(self,case, inode, scanners, *args):
        factories = Scanner.get_factories(case, scanners.split(","))

        if factories:
            ddfs = factories[0].fsfd
            fd = ddfs.open(inode = inode)
            Scanner.scanfile(ddfs, fd, factories)
            fd.close()

class DropCase(Farm.Task):
    """ This class is responsible for cleaning up cached data
    structures related to the case
    """
    def run(self, case, *args):
        ## Expire any caches we have relating to this case:
        pyflaglog.log(pyflaglog.INFO, "Resetting case %s in worker" % case)
        FlagFramework.post_event('reset', case)

class CaseDBInit(FlagFramework.EventHandler):
    """ A handler for creating common case tables """
    
    ## This should come before any other handlers if possible.
    order = 5
    
    def create(self,case_dbh,case):
        case_dbh.execute("""Create table if not exists meta(
        `time` timestamp NOT NULL,
        property varchar(50),
        value text,
        KEY property(property),
        KEY joint(property,value(20)))""")
        
        ## This is a transactional table for managing the cache
        case_dbh.execute("""CREATE TABLE if not exists `sql_cache` (
        `id` INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY ,
        `timestamp` TIMESTAMP ON UPDATE CURRENT_TIMESTAMP NOT NULL ,
        `tables` VARCHAR( 250 ) NOT NULL ,
        `query` MEDIUMTEXT NOT NULL,
        `limit` INT default 0,
        `length` INT default 100
        ) ENGINE=InnoDB""")
        
        case_dbh.execute("""CREATE TABLE if not exists `iosources` (
        `id` INT(11) not null auto_increment,
        `name` VARCHAR(250) NOT NULL,
        `type` VARCHAR(250) NOT NULL,
        `parameters` TEXT,
        PRIMARY KEY(`id`)
        )""")        

        case_dbh.execute("""CREATE TABLE if not exists `annotate` (
        `id` INT(11) not null auto_increment,
        `inode` VARCHAR(250) NOT NULL,
        `note` TEXT,
        `category` VARCHAR( 250 ) NOT NULL default 'Note',
        PRIMARY KEY(`id`)
        )""")        

        case_dbh.execute("""CREATE TABLE if not exists `timeline` (
        `id` INT(11) not null auto_increment,
        `time` timestamp,
        `notes` TEXT,
        `category` VARCHAR( 250 ) NOT NULL default 'Note',
        PRIMARY KEY(`id`)
        )""")        

        # The id field here feels kind of redundant, but it keeps DB.py happy for the
        # caching stuff...
        case_dbh.execute("""CREATE TABLE if not exists `interesting_ips` (
        `id` INT(11) not null auto_increment,
        `ip` INT(11) UNSIGNED UNIQUE,
        `notes` TEXT,
        `category` VARCHAR( 250 ) NOT NULL default 'Note',
        PRIMARY KEY(`id`)
        )""")

        # create the "groupware" tables
        case_dbh.execute("CREATE TABLE IF NOT EXISTS `email` (`inode` VARCHAR(250), `date` TIMESTAMP, `to` VARCHAR(250), `from` VARCHAR(250), `subject` VARCHAR(250));")
        case_dbh.execute("CREATE TABLE IF NOT EXISTS `contact` (`inode` VARCHAR(250), `name` VARCHAR(250), `email` VARCHAR(250), `address` VARCHAR(250), `phone` VARCHAR(250));")
        case_dbh.execute("CREATE TABLE IF NOT EXISTS `appointment` (`inode` VARCHAR(250), `startdate` TIMESTAMP, `enddate` TIMESTAMP, `location` VARCHAR(250), `comment` VARCHAR(250));")
        case_dbh.execute("CREATE TABLE IF NOT EXISTS `journal` (`inode` VARCHAR(250), `startdate` TIMESTAMP, `enddate` TIMESTAMP, `type` VARCHAR(250), `comment` VARCHAR(250));")

        ## Create a directory inside RESULTDIR for this case to store its temporary files:
        try:
            os.mkdir("%s/case_%s" % (config.RESULTDIR,case))
        except OSError:
            pass

        ## Create an enum for the scanners in the inode table
        scanners = [ "%r" % s.__name__ for s in Registry.SCANNERS.classes ]
        case_dbh.execute("""CREATE TABLE IF NOT EXISTS inode (
        `inode_id` int auto_increment,
        `inode` VARCHAR(250) NOT NULL,
        `status` set('unalloc','alloc'),
        `uid` INT,
        `gid` INT,
        `mtime` TIMESTAMP NULL,
        `atime` TIMESTAMP NULL,
        `ctime` TIMESTAMP NULL,
        `dtime` TIMESTAMP,
        `mode` INT,
        `links` INT,
        `link` TEXT,
        `size` BIGINT NOT NULL,
        `scanner_cache` set('',%s),
        primary key (inode_id)
        )""",",".join(scanners))

        case_dbh.execute("""CREATE TABLE IF NOT EXISTS file (
        `inode` VARCHAR(250) NOT NULL,
        `mode` VARCHAR(3) NOT NULL,
        `status` VARCHAR(8) NOT NULL,
        `path` TEXT,
        `name` TEXT)""")

        case_dbh.execute("""CREATE TABLE IF NOT EXISTS block (
        `inode` VARCHAR(250) NOT NULL,
        `index` INT NOT NULL,
        `block` BIGINT NOT NULL,
        `count` INT NOT NULL)""")

        case_dbh.execute("""CREATE TABLE IF NOT EXISTS resident (
        `inode` VARCHAR(250) NOT NULL,
        `data` TEXT)""")

        case_dbh.execute("""CREATE TABLE IF NOT EXISTS `filesystems` (
        `iosource` VARCHAR( 50 ) NOT NULL ,
        `property` VARCHAR( 50 ) NOT NULL ,
        `value` MEDIUMTEXT NOT NULL ,
        KEY ( `iosource` )
        )""")

        ## This is a nice idea, but its just not flexible enough... We
        ## use VARCHAR for now...
        
##        ## Create the xattr table by interrogating libextractor:
##        types = ['Magic']
##        try:
##            import extractor
##            e = extractor.Extractor()
##            types.extend(e.keywordTypes())
##        except ImportError:
##            pass

##        case_dbh.execute("""CREATE TABLE if not exists `xattr` (
##                            `inode_id` INT NOT NULL ,
##                            `property` ENUM( %s ) NOT NULL ,
##                            `value` VARCHAR( 250 ) NOT NULL
##                            ) """ % ','.join([ "%r" % x for x in types]))

        case_dbh.execute("""CREATE TABLE if not exists `xattr` (
                            `inode_id` INT NOT NULL ,
                            `property` VARCHAR(250) NOT NULL ,
                            `value` VARCHAR(250) NOT NULL
                            ) """)
        
        case_dbh.execute("""CREATE TABLE `GUI_filter_history` (
                            `id` int auto_increment,
                            `filter` VARCHAR(250),
                            `elements` VARCHAR(500),
                            PRIMARY KEY (`id`))""")

        case_dbh.execute("""ALTER TABLE `GUI_filter_history` ADD UNIQUE INDEX stopDupes (filter, elements)""")
    
    def init_default_db(self, dbh, case):
        ## Connect to the mysql database
        tdbh = DB.DBO('mysql')

        ## Make sure we start with a clean slate
        tdbh.execute("drop database if exists %s" % config.FLAGDB)
        tdbh.execute("create database %s" % config.FLAGDB)

        ## Source the initial database script.
        dbh.MySQLHarness("/bin/cat %s/db.setup" % config.DATADIR)

        ## Update the schema version.
        dbh.set_meta('schema_version',config.SCHEMA_VERSION)


    def exit(self, dbh, case):
        IO.IO_Cache.flush()
        DB.DBO.DBH.flush()
        DB.DBIndex_Cache.flush()
        Scanner.factories.flush()

    def reset(self, dbh, case):
        key_re = "%s.*" % case
        IO.IO_Cache.expire(key_re)
        DB.DBO.DBH.expire(key_re)
        DB.DBIndex_Cache.expire(key_re)
        Scanner.factories.expire(key_re)
