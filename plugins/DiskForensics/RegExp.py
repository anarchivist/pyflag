""" This modules add support for a regular expression scanner to search all files in the filesystem.
#
# $Id: RegExp.py,v 1.3 2005/02/25 18:04:43 george Exp $
#
# $Log: RegExp.py,v $
# Revision 1.3  2005/02/25 18:04:43  george
# * Add regexp class to results database and display
#
# Revision 1.2  2005/02/25 14:41:41  george
# First working version. Finds all occurances in buffers.
# Does not find matches spanning buffers.
# Still to do:
#   - pass class name back up for display next to match
#   - provide context of matches
#
# Revision 1.1  2005/02/24 14:49:07  george
# Initial revision
#

We provide a scanner class and a report to query the results of this scanner.
"""
import pyflag.FlagFramework as FlagFramework
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.FileSystem as FileSystem
import pyflag.Reports as Reports
import pyflag.DB as DB
import os.path
import pyflag.logging as logging
from pyflag.Scanner import *

import re

class RScan:
    """ Singleton class to manage regexp scanner access """
    ## May need to do locking in future, if re is not reentrant.
    scanner = None
    default = True
    def __init__(self):
        logging.log(logging.DEBUG, "Debug: Init RScan")
	self.foo = 1

    def scan(self,buf,pattern):
        """ Scan the given buffer, and return a regexp name or 'None'"""

        logging.log(logging.DEBUG, "scaning for pattern /%s/" % pattern)

        c=re.findall(r"%s" % pattern, buf)
#        p=re.compile("%s" % pattern,re.I)  # gmj - move outside loop ?
#        c=p.findall(buf) 

        if c:
            logging.log(logging.DEBUG, "Debug: Scanning Found: %s" % c)
            return c
        else:
            return None

class RegScan(GenScanFactory):
    """ Scan file for regexps """
    def __init__(self,dbh, table,fsfd):
        logging.log(logging.DEBUG, "Debug: Creating regexp table")        
        dbh.execute(""" CREATE TABLE IF NOT EXISTS `regexp_%s` (
        `inode` varchar( 20 ) NOT NULL,
        `class` tinytext NOT NULL,
        `regexp` tinytext NOT NULL )""", table)
        self.dbh=dbh
        self.table=table
        pydbh = DB.DBO(None)
        pydbh.execute("select class,pattern from regexps")
        self.RegexpRows = [] 
        for row in pydbh:
            self.RegexpRows.append(row)

    def destroy(self):
        self.dbh.execute('ALTER TABLE regexp_%s ADD INDEX(inode)', self.table)

    def reset(self):
        GenScanFactory.reset(self)
        self.dbh.execute('drop table regexp_%s',self.table)

    class Scan(BaseScanner):
        def __init__(self, inode,ddfs,outer,factories=None):
            BaseScanner.__init__(self, inode,ddfs,outer,factories)
            self.inode = inode
            self.window = ''
            self.dbh=outer.dbh
            self.table=outer.table
            self.listfound = None
            self.windowsize = 1000
            self.RegexpRows = outer.RegexpRows;
            logging.log(logging.DEBUG, "Debug: Creating RScan")
            self.scanner = RScan()

        def process(self, data,metadata=None):
            """ This scans for the a regexp in buffer.  Should span buffers."""

            # gmj - old logic ... scan for one regexp, stop when found.
            #            if not self.regexp:
            #                buf = self.window + data
            #                self.regexp = self.scanner.scan(buf)
            #                self.window = buf[-self.windowsize:]

            # gmj - new logic.  Scan for all occurances of all regexps. 
            for row in self.RegexpRows:
                buf = self.window + data
                self.listfound = None
                self.listfound = self.scanner.scan(buf,row['pattern'])
                if self.listfound:

                    for found in self.listfound:
                        self.dbh.execute("INSERT INTO regexp_%s VALUES(%r,%r,%r)", (self.table, self.inode, row['class'],found))

                self.listfound = None
                self.window = buf[-self.windowsize:]

        def finish(self):
            return
		

class RegExpScan(Reports.report):
    """ Scan Filesystem for RegExpes using re"""
    parameters = {'fsimage':'fsimage'}
    name = "RegExp Scan"
    family = "Disk Forensics"
    description="This report will scan for regexps and display a table of regexpss found"
    def form(self,query,result):
        try:
            result.case_selector()
            if query['case']!=config.FLAGDB:
               result.meta_selector(case=query['case'],property='fsimage')
        except KeyError:
            return result

    def display(self,query,result):
        result.heading("RegExp Scan for %s" % query['fsimage'])
        dbh=self.DBO(query['case'])
        tablename = dbh.MakeSQLSafe(query['fsimage'])

        try:
            result.table(
                columns=('a.inode','concat(path,name)', 'a.regexp','a.class'),
                names=('Inode','Filename','RegExp Found','RegExp Type'),
                table='regexp_%s as a join file_%s as b on a.inode=b.inode ' % (tablename,tablename),
                case=query['case'],
                links=[ FlagFramework.query_type((),case=query['case'],family=query['family'],fsimage=query['fsimage'],report='ViewFile',__target__='inode')]
                )
        except DB.DBError,e:
            result.para("Unable to display RegExp table, maybe you did not run the regexp scanner over the filesystem?")
            result.para("The error I got was %s"%e)
            
