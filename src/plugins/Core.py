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
#  Version: FLAG $Version: 0.87-pre1 Date: Thu Jun 12 00:48:38 EST 2008$
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
from pyflag.ColumnTypes import StringType, TimestampType, InodeIDType, FilenameType, IntegerType, DeletedType, SetType, BigIntegerType

config.add_option("SCHEMA_VERSION", default=3, absolute=True,
                  help="Current schema version")

class CachedFile(FileSystem.File):
    """ A VFS Driver to open cached files """
    specifier = "x"

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
        
    def explain(self, query, result):
        tmp = result.__class__(result)
        try:
            self.io.explain(tmp)
        except AttributeError:
            dbh = DB.DBO(self.case)
            dbh.execute("select parameters from iosources where name=%r" , self.name)
            row = dbh.fetch()
            q = FlagFramework.query_type(string = row['parameters'])
            q.clear('report')
            q.clear('family')
            for k,v in q.items():
                if k == 'filename' and v.startswith(config.UPLOADDIR):
                    v = v[len(config.UPLOADDIR):]
                    
                tmp.row(k,v, **{'class': 'explain'})
            
        result.row("IO Subsys %s:" % self.name, tmp, **{'class': 'explainrow'})

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

    def explain(self, query, result):
        self.fd.explain(query,result)

        result.row("Offset","Extract %s bytes from %s starting at byte %s" % (self.size,
                                                                              self.fd.inode,
                                                                              self.offset))

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
            ddfs = DBFS(case)
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
        ## Create all CaseTables:
        for t in Registry.CASE_TABLES.classes:
            t().create(case_dbh)

        case_dbh.execute("""Create table if not exists meta(
        `time` timestamp NOT NULL,
        property varchar(50),
        value text,
        KEY property(property),
        KEY joint(property,value(20)))""")

        ## Defaults
        case_dbh.insert("meta",
                        property = "TZ",
                        value = "SYSTEM",
                        _fast = True)
        
        ## This is a transactional table for managing the cache
        case_dbh.execute("""CREATE TABLE if not exists `sql_cache` (
        `id` INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY ,
        `timestamp` TIMESTAMP ON UPDATE CURRENT_TIMESTAMP NOT NULL ,
        `query` MEDIUMTEXT NOT NULL,
        `limit` INT default 0,
        `length` INT default 100,
        `locked` INT default 1
        ) ENGINE=InnoDB""")

        case_dbh.execute("""CREATE TABLE sql_cache_tables (
        `sql_id` INT UNSIGNED,
        `table_name` VARCHAR(250))""")

        case_dbh.check_index("sql_cache_tables","sql_id")
        case_dbh.check_index("sql_cache_tables","table_name")
        
        case_dbh.execute("""CREATE TABLE if not exists `iosources` (
        `id` INT(11) not null auto_increment,
        `name` VARCHAR(250) NOT NULL,
        `type` VARCHAR(250) NOT NULL,
        `timezone` VARCHAR(250) NOT NULL,
        `parameters` TEXT,
        PRIMARY KEY(`id`)
        )""")        

        # create the "groupware" tables 
        # NOTE: davec: DISABLED contact/appointment/journal, not currently
        # used, should be moved into plugin if ever re-enabled anyway.  
        # FIXME: move email into RFC2822 scanner since thats what seems to use
        # it
        case_dbh.execute("CREATE TABLE IF NOT EXISTS `email` (`inode` VARCHAR(250), `date` TIMESTAMP, `to` VARCHAR(250), `from` VARCHAR(250), `subject` VARCHAR(250));")
        #case_dbh.execute("CREATE TABLE IF NOT EXISTS `contact` (`inode` VARCHAR(250), `name` VARCHAR(250), `email` VARCHAR(250), `address` VARCHAR(250), `phone` VARCHAR(250));")
        #case_dbh.execute("CREATE TABLE IF NOT EXISTS `appointment` (`inode` VARCHAR(250), `startdate` TIMESTAMP, `enddate` TIMESTAMP, `location` VARCHAR(250), `comment` VARCHAR(250));")
        #case_dbh.execute("CREATE TABLE IF NOT EXISTS `journal` (`inode` VARCHAR(250), `startdate` TIMESTAMP, `enddate` TIMESTAMP, `type` VARCHAR(250), `comment` VARCHAR(250));")

        ## Create a directory inside RESULTDIR for this case to store its temporary files:
        try:
            os.mkdir("%s/case_%s" % (config.RESULTDIR,case))
        except OSError:
            pass

##        ## Create an enum for the scanners in the inode table
##        scanners = [ "%r" % s.__name__ for s in Registry.SCANNERS.classes ]
##        case_dbh.execute("""CREATE TABLE IF NOT EXISTS inode (
##        `inode_id` int auto_increment,
##        `inode` VARCHAR(250) NOT NULL,
##        `status` set('unalloc','alloc'),
##        `uid` INT,
##        `gid` INT,
##        `mtime` TIMESTAMP NULL,
##        `atime` TIMESTAMP NULL,
##        `ctime` TIMESTAMP NULL,
##        `dtime` TIMESTAMP NULL,
##        `mode` INT,
##        `links` INT,
##        `link` TEXT,
##        `size` BIGINT NOT NULL,
##        `scanner_cache` set('',%s),
##        primary key (inode_id)
##        )""",",".join(scanners))

##        case_dbh.execute("""CREATE TABLE IF NOT EXISTS file (
##        `inode_id` INT NULL,
##        `inode` VARCHAR(250) NOT NULL,
##        `mode` VARCHAR(3) NOT NULL,
##        `status` VARCHAR(8) NOT NULL,
##        `path` TEXT,
##        `name` TEXT,
##        `link` TEXT NULL,
##        key `inode_id` (`inode_id`)
##        )""")

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
                            `value` TEXT NOT NULL
                            ) """)
        
        case_dbh.execute("""CREATE TABLE `GUI_filter_history` (
                            `id` int auto_increment,
                            `filter` VARCHAR(250),
                            `elements` VARCHAR(500),
                            PRIMARY KEY (`id`)) character set latin1""")

        case_dbh.execute("""ALTER TABLE `GUI_filter_history` ADD UNIQUE INDEX stopDupes (filter, elements)""")
    
    def init_default_db(self, dbh, case):
        ## Connect to the mysql database
        tdbh = DB.DBO('mysql')

        ## Make sure we start with a clean slate
        tdbh.execute("drop database if exists %s" % config.FLAGDB)
        tdbh.execute("create database `%s` default character set utf8" % config.FLAGDB)

        ## Source the initial database script. (We no longer use
        ## db.setup to initialise the database - everything is done by
        ## event handlers)

        dbh.execute("""CREATE TABLE meta (
        property varchar(50) default NULL,
        value text default NULL
        ) engine=MyISAM;""")

        ## This is required for the new distributed architecture
        dbh.execute("""create table jobs (
	`id` int unsigned auto_increment, 
	command varchar(250), 
	arg1 text,
	arg2 text,
	arg3 text,
	state enum('broadcast','pending','processing') default 'pending',
	`cookie` INT(11) not null,
	key `id`(id)
	)""")

        dbh.execute("""CREATE TABLE sql_cache_tables (
        `sql_id` INT UNSIGNED,
        `table_name` VARCHAR(250))""")

        dbh.check_index("sql_cache_tables","sql_id")
        dbh.check_index("sql_cache_tables","table_name")
        
        dbh.execute("""CREATE TABLE `sql_cache` (
        `id` INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY ,
        `timestamp` TIMESTAMP ON UPDATE CURRENT_TIMESTAMP NOT NULL ,
        `query` MEDIUMTEXT NOT NULL,
        `limit` INT default 0,
        `length` INT default 100,
        `locked` INT default 1
        ) ENGINE=InnoDB""")

        dbh.execute("""CREATE TABLE `logs` (
        `timestamp` TIMESTAMP NOT NULL ,
        `level` TINYINT NOT NULL ,
        `message` VARCHAR( 250 ) NOT NULL
        )""")

        ##dbh.MySQLHarness("/bin/cat %s/db.setup" % config.DATADIR)

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


class FileTable(FlagFramework.CaseTable):
    """ File table - Complements the VFS inodes with filenames """
    name = 'file'
    columns = [ [ InodeIDType, {} ],
                [ StringType, dict(name = 'Inode_deprecated', column = 'inode')],
                [ StringType, dict(name = 'Mode', column = 'mode', width=3)],
                [ StringType, dict(name = 'Status', column = 'status', width=8)],
                [ FilenameType, {}],
                ]
    index = [ 'inode_id']

class InodeTable(FlagFramework.CaseTable):
    """ Inode Table - stores information related to VFS Inodes """
    name = 'inode'
    primary = 'inode_id'
    columns = [ [ InodeIDType, {}, "auto_increment" ],
                [ StringType, dict(name = 'Inode_', column = 'inode')],
                [ DeletedType, {} ],
                [ IntegerType, dict(name = 'UID', column = 'uid')],
                [ IntegerType, dict(name = 'GID', column = 'gid')],
                [ TimestampType, dict(name = 'Modified', column='mtime')],
                [ TimestampType, dict(name = 'Accessed', column='atime')],
                [ TimestampType, dict(name = 'Changed', column='ctime')],
                [ TimestampType, dict(name = 'Deleted', column='dtime')],
                [ IntegerType, dict(name = 'Mode', column='mode')],
                [ IntegerType, dict(name = 'Links', column='links')],
                [ StringType, dict(name='Link', column='link', width=500)],
                [ BigIntegerType, dict(name = 'Size', column='size')],
                ## The dictionary version used on this inode:
                [ IntegerType, dict(name = "Index Version", column='version')],
                ]
    
    def __init__(self):
        scanners = [ "%s" % s.__name__ for s in Registry.SCANNERS.classes ]
        print scanners
        self.columns = self.columns + [ [ SetType,
                                          dict(name='Scanner Cache', column='scanner_cache',
                                               states = scanners)
                                          ],
                                        ]

class CaseConfiguration(Reports.report):
    """
    Case Configuration
    ==================

    This report allows case specific configuations.

    Timezone
    --------
    
    This is the timezone which will be used to view the data.  When
    data is loaded into PyFlag, the iosource itself has a distinct
    timezone associated with it. When users view this data, times are
    automatically presented in the case timezone.

    The case timezone may be specified as SYSTEM which simply
    specifies no special timezone adjustment. If the evidence is
    imported with a SYSTEM timezone, the dates the user views are in
    the same zone that is displayed.

    Note that if you do not see any timezones here, you should run the
    following command to load them into mysql:

    sh$ mysql_tzinfo_to_sql /usr/share/zoneinfo | mysql -u root -p mysql
    
    """
    parameters = { 'TZ': "string"}
    family = "Case Management"
    name = "Configure Case"
    
    def form(self, query, result):
        result.heading("Case configuration")
        result.tz_selector("Timezone", "TZ")

    def display(self, query, result):
        dbh = DB.DBO(query['case'])
        result.heading("Setting case parameters")
        for prop in ['TZ',]:
            dbh.execute("update meta set value = %r where property = %r",
                        query[prop],
                        prop)
            result.row(prop, query[prop])

        ## Expire the parameters:
        dbh.DBH.get(query['case']).parameter_flush()

class PyFlagStatistics(Reports.report):
    """ Display statistics on the currently running pyflag
    installation."""
    parameters = {}
    family = "Case Management"
    name = "PyFlag Stats"

    def display(self, query, result):
        result.heading("PyFlag Statistics")
        dbh = DB.DBO()
        dbh.execute("select count(*) as count from jobs where state='pending'")
        row = dbh.fetch()
        result.row("Version", config.VERSION)
        result.row("Outstanding jobs", row['count'])

        cdbh = DB.DBO(query['case'])
        cdbh.execute("select count(*) as count from inode")
        row = cdbh.fetch()
        result.row("Total Inodes in VFS", row['count'])
        result.end_table()

        
        pyflaglog.render_system_messages(result)

        def info_cb(query,result):
            result.heading("PyFlag Plugins")
            result.text(FlagFramework.print_info(), font='typewriter')
            
        result.toolbar(cb=info_cb, icon="question.png")
