# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.82 Date: Sat Jun 24 23:38:33 EST 2006$
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

""" Creates a new case database for flag """
import pyflag.Reports as Reports
import pyflag.FlagFramework as FlagFramework
import pyflag.FileSystem as FileSystem
import pyflag.DB as DB
import os
import pyflag.IO as IO
import pyflag.conf
config=pyflag.conf.ConfObject()
from pyflag.TableObj import StringType,TimestampType,InodeType,FilenameType
import pyflag.Registry as Registry

from os.path import join

description = "Case management"
order = 10

class NewCase(Reports.report):
    """ Creates a new flag case database."""
    parameters = {"create_case":"alphanum"}
    name = "Create new case"
    family = "Case Management"
    description = "Create database for new case to load data into"
    order = 10

    def form(self,query,result):
        result.defaults = query
        result.textfield("Please enter a new case name:","create_case")
        return result

    def display(self,query,result):
        #Get handle to flag db
        dbh = self.DBO(None)
        dbh.cursor.ignore_warnings = True
        dbh.execute("Create database if not exists %s",(query['create_case']))
        dbh.execute("select * from meta where property='flag_db' and value=%r",query['create_case'])
        if not dbh.fetch():
            dbh.insert('meta',
                       property='flag_db',
                       value=query['create_case'])

        #Get handle to the case db
        case_dbh = self.DBO(query['create_case'])
        case_dbh.cursor.ignore_warnings = True
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
        `length` INT default 100,
        PRIMARY KEY  (`id`)
        ) ENGINE=InnoDB DEFAULT""")

        case_dbh.execute("""CREATE TABLE if not exists `annotate` (
        `id` INT(11) not null auto_increment,
        `inode` VARCHAR(250) NOT NULL,
        `note` TEXT,
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
            os.mkdir("%s/case_%s" % (config.RESULTDIR,query['create_case']))
        except OSError:
            pass

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

        ## Create the xattr table by interrogating libextractor:
        types = ['Magic']
        try:
            import extractor
            e = extractor.Extractor()
            types.extend(e.keywordTypes())
        except ImportError:
            pass

        case_dbh.execute("""CREATE TABLE if not exists `xattr` (
                            `inode_id` INT NOT NULL ,
                            `property` ENUM( %s ) NOT NULL ,
                            `value` VARCHAR( 250 ) NOT NULL
                            ) """ % ','.join([ "%r" % x for x in types]))

        result.heading("Case Created")
        result.para("\n\nThe database for case %s has been created" %query['create_case'])
        result.link("Load a Disk Image", FlagFramework.query_type((), case=query['create_case'], family="Load Data", report="Load IO Data Source"))
	result.para('')
        result.link("Load a preset Log File", FlagFramework.query_type((), case=query['create_case'], family="Load Data", report="Load Preset Log File"))
        return result

class DelCase(Reports.report):
    """ Removes a flag case database """
    parameters = {"remove_case":"flag_db"}
    name = "Remove case"
    family = "Case Management"
    description="Remove database for specified case"
    order = 20

    def do_reset(self,query):
        pass

    def form(self,query,result):
        result.defaults = query
        result.para("Please select the case to delete. Note that all data in this case will be lost.")
        result.case_selector(case="remove_case")
        return result

    def display(self,query,result):
        dbh = self.DBO(None)

        case = query['remove_case']
        ## Remove any jobs that may be outstanding:
        dbh.delete('jobs',"command='Scan' and arg1=%r" % case)

        try:
          #Delete the case from the database
          dbh.delete('meta',"property='flag_db' and value=%r" % case)
          dbh.execute("drop database if exists %s" ,case)
        except DB.DBError:
            pass

        ## Delete the temporary directory corresponding to this case and all its content
        try:
            temporary_dir = "%s/case_%s" % (config.RESULTDIR,query['remove_case'])
            for root, dirs, files in os.walk(temporary_dir,topdown=False):
                for name in files:
                    os.remove(join(root, name))
                for name in dirs:
                    os.rmdir(join(root, name))

            os.rmdir(temporary_dir)
        except:
            pass

        ## Expire any caches we have relating to this case:
        key_re = "%s[/|]?.*" % query['remove_case']
        IO.IO_Cache.expire(key_re)
        DB.DBH.expire(key_re)
        DB.DBIndex_Cache.expire(key_re)

        result.heading("Deleted case")
        result.para("Case %s has been deleted" % query['remove_case'])
        return result

class ResetCase(Reports.report):
    """ Resets a flag case database """
    parameters = {"reset_case":"flag_db"}
    name = "Reset Case"
    family = "Case Management"
    description = "Reset a case database (delete data)"
    order = 30

    def form(self,query,result):
        result.defaults = query
        result.para("Please select the case to reset. Note that all data in this case will be lost.")
        result.case_selector(case="reset_case")
        return result

    def display(self,query,result):
        result.heading("Reset case")

        query['remove_case'] = query['reset_case']
        query['create_case'] = query['reset_case']
        tmp = result.__class__(result)
        
        report = DelCase(self.flag, self.ui)
        report.display(query,tmp)
        
        report = NewCase(self.flag, self.ui)
        report.display(query,tmp)

        result.para("Case %s has been reset" % query['reset_case'])

class ViewAnnotation(Reports.report):
    """ View the annotated Inodes """
    name = "View Annotations"
    family = "Case Management"

    def display(self, query,result):
        result.heading("Annotated Inodes for case %s" % query['case'])
        result.table(
            elements = [ InodeType('Inode', 'annotate.inode', case=query['case']),
                         FilenameType(case=query['case']),
                         StringType('Category','category'),
                         StringType('Note','note'),
                         ],
            table = 'annotate join file on file.inode=annotate.inode',
            case = query['case'],
            )
                                    
