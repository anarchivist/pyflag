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
#  Version: FLAG $Name:  $ $Date: 2004/10/17 11:53:12 $
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

""" Flag plugin to load various forms of data into the case databases """
import re,os,os.path
import pyflag.Reports as Reports
import pyflag.FlagFramework as FlagFramework
import pyflag.FileSystem as FileSystem
import pyflag.Scanner as Scanner
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.DB as DB
import pyflag.LogFile as LogFile
import plugins.LogAnalysis as LogAnalysis

description = "Load Data"
order = 20

class LoadPresetLog(Reports.report):
    """ Loads a log file into the database using preset type """
    parameters = {"table":"any", "new_table":"any",
                  "datafile":"filename", "log_preset":"sqlsafe", "final":"alphanum"}
    name="Load Preset Log File"
    description="Load Data from log file into Database using Preset"
    order=30

    def display(self,query,result):
        result.heading("Uploaded log file into database")
        result.para("Successfully uploaded the following files into case %s, table %s:" % (query['case'],query['table']))
        for fn in query.getarray('datafile'):
            result.para(fn)
        result.link("Browse this log file", FlagFramework.query_type((), case=query['case'], family="LogAnalysis", report="ListLogFile", logtable="%s"%query['table']))
        return result
    
    def progress(self,query,result):
        result.heading("Currently uploading log file into database")
        try:
            tmp = query['new_table']
            del query['table']
            query['table'] = tmp
        except KeyError:
            pass
        
        dbh = self.DBO(query['case'])
        dbh.execute("select count(*) as count from %s_log", (query['table']))
        tmp = dbh.fetch()
        try:
            result.para("Uploaded %s rows. " % tmp['count'])
        except TypeError,e:
            print "exception %s tmp is %s" %(e,tmp)

    def form(self, query, result):
        try:
            result.case_selector()
            result.meta_selector(config.FLAGDB,'Select preset type','log_preset',onclick="this.form.submit();")
            # get existing tables
            dbh = self.DBO(query['case'])
            dbh.execute('select value from meta where property=%r group by value', 'logtable')
            tables = [row['value'][:-4] for row in dbh]
            tables.append('NEW')
            result.const_selector('Insert into Table', 'table', tables, tables)
            result.textfield("OR Enter New table name:","new_table")

            tmp = self.ui(result)
            tmp.filebox()
            result.row("Select file to load:",tmp)
            if query.getarray('datafile'):
                log = LogFile.get_loader(query['log_preset'],query.getarray('datafile'))
            else:
                return result

            # show preview
            dbh = self.DBO(query['case'])
            temp_table = dbh.get_temp()
            log.load(dbh,temp_table, rows=3)

            # retrieve and display the temp table
            dbh.execute("select * from %s limit 1",temp_table)
            LogAnalysis.display_test_log(dbh,log,result,query)
            
            result.checkbox('Click here when finished','final','ok')
            
        except KeyError:
            pass

    def analyse(self, query):
        """ Load the log file into the table """
        log = LogFile.get_loader(query['log_preset'],query.getarray('datafile'))

        # decide on table name
        if query.has_key('new_table'):
            del query['table']
            query['table'] = query['new_table']

        dbh = self.DBO(query['case'])
        log.load(dbh,'%s_log'%query['table'])
        dbh.execute("INSERT INTO meta set property='logtable', value='%s'" ,(query['table']))
        dbh.execute("INSERT INTO meta set property='log_preset_%s', value='%s'",(query['table'],query['log_preset']))

    def reset(self, query):
        dbh = self.DBO(query['case'])
        # decide on table name
        if query.has_key('new_table'):
            del query['table']
            query['table'] = query['new_table']

        dbh.execute("DROP TABLE if exists %s_log" % query['table'])
        dbh.execute("delete from meta where property='logtable' and value='%s'" , (query['table']))
        dbh.execute("delete from meta where property='log_preset_%s'" , (query['table']))

import pyflag.Ethereal as Ethereal

class LoadTcpDump(Reports.report):
    """ Loads a TCPDump using the modified ethereal. """
    parameters = {"datafile":"filename"}
    name = "Load Pcap file"
    description = "Load a network capture file into the case Database "
    order=30
    
    def form(self,query,result):
        result.start_table()
        result.ruler()
        tmp = self.ui()
        tmp.heading("Step 1:")
        result.row(tmp,"Select Case name to load Pcap file into")
        result.case_selector()
        result.ruler()
        tmp = self.ui()
        tmp.heading("Step 2:")
        result.row(tmp,"Select PCAP file to load")
        tmp = self.ui(default = result)
        tmp.filebox()
        result.row("Enter name of file to load:",tmp)
        result.ruler()
        tmp = self.ui()
        tmp.heading("Step 3:")
        result.row(tmp,"")

    def analyse(self,query):
        datafile=query['datafile']
        Ethereal.load_sql(query['case'],datafile)

        #Now load the indexes on the data:
        dbh = self.DBO(query['case'])
        index = (
            ('tcp','key_id'),
            ('tcp','tcp_srcport'),
            ('tcp','tcp_dstport'),
            ('ip','key_id'),
            ('ip','ip_dst'),
            ('ip','ip_src'),
            ('frame','key_id'),
            ('eth','key_id'),
            ('icmp','key_id'),
            ('dns','key_id'),
            ('http','key_id'),
            ('http','http_request_uri(20)'),
            ('pop','key_id'),
            ('pop','pop_req_command(20)'),
            ('smtp','key_id'),
            ('smtp','smtp_req_command(20)'),
            ('udp','key_id'),
            ('udp','udp_srcport'),
            ('udp','udp_dstport')
            )
        
        for x,y in index:
            dbh.execute("alter table %s add index(%s)",(x,y))

    def display(self,query,result):
        result.heading("Uploaded PCAP file %r to case %r" % (query['datafile'],query['case']))
                       
    def progress(self,query,result):
        result.heading("Currently uploading Pcap file to case %s" % query['case'])
        dbh = self.DBO(query['case'])
        dbh.execute('select count(*) from frame',())
        a = dbh.cursor.fetchone()
        result.para("Added %s packets already"%a[0])

    def reset(self,query):
        dbh = self.DBO(query['case'])
        dbh2 =  self.DBO(query['case'])
        dbh.execute('select value from meta where property = "tcpdump_table" group by value',())
        while 1:
            rs = dbh.fetch()
            if not rs: break
            dbh2.execute("drop table %s ",rs['value'])

        dbh.execute("delete from meta where property = 'tcpdump_table'",())

import pyflag.IO as IO

class LoadIOSource(Reports.report):
    """ Initialises and caches an IO Subsystem datasource into the database for
    subsequent use by other reports (eg. LoadFS and exgrep) """
    parameters = {"iosource":"sqlsafe","subsys":"iosubsystem"}
    name = "Load IO Data Source"
    description = "Load a data source into flag using IO subsystem"
    order = 10

    def form(self,query,result):
        result.start_table()
        try:
            result.case_selector()
            result.ruler()
            subsystems=IO.subsystems.keys()
            subsystems.sort()
            subsystems.reverse()
            result.const_selector("Select IO Subsystem",'subsys',subsystems,subsystems)
            #this will cause a form to be placed into result.
            fd=IO.IOFactory(query,result)
            result.textfield("Identifier","iosource")
        except KeyError:
            pass
        except IOError, e:
            result.row("Error: %s" % e, bgcolor=config.HILIGHT)

    def analyse(self,query):
        # cache serialised io options in the case mata table
        fd=IO.IOFactory(query)
        dbh = self.DBO(query['case'])
        dbh.execute("insert into meta set property=%r,value=%r", ('iosource',query['iosource']))
        dbh.execute("insert into meta set property=%r,value=%r",(query['iosource'],fd.get_options()))

    def display(self,query,result):
        result.heading("Data Source %s successfully added" % query['iosource'])
        result.link("Load Filesystem", FlagFramework.query_type((), case=query['case'], family="LoadData", report="LoadFS", iosource=query['iosource']))
        result.para('')
        result.link("Extract Files", FlagFramework.query_type((), case=query['case'], family="UnstructuredDisk", report="ExtractFiles", iosource=query['iosource']))


import pyflag.Sleuthkit as Sleuthkit

class LoadFS(Reports.report):
    """ Loads Filesystem Image using the modified sleuthkit. """
    parameters = {"iosource":"iosource","fstype":"sqlsafe"}
    name = "Load Filesystem image"
    description = "Load a filesystem image into the case Database"
    order = 20

    progress_str=None
    
    def form(self,query,result):
        result.start_table()
        try:
            result.case_selector()
            result.ruler()
            result.meta_selector(message='Select IO Data Source', case=query['case'], property='iosource')
            
            # initialise/open the subsystem
            dbh = self.DBO(query['case'])
            fd=IO.open(query['case'],query['iosource'])

            fs_types = Sleuthkit.filesystems(fd)
            
            ## If there is only one choice - we choose it for the user and run this already.
            if len(fs_types[0])==1:
                query['fstype']=fs_types[1][0]
                result.refresh(0,query)
                return
            
            magic = FlagFramework.Magic()
            result.ruler()
            result.row("Magic identifies this file as: %s" % magic.buffer(fd.read(10240)),colspan=50,bgcolor=config.HILIGHT)
            fd.close()

            result.const_selector("Enter Filesystem type",'fstype',fs_types[0],fs_types[1])
            result.ruler()

        except (KeyError,IOError,TypeError):
            pass

    def analyse(self,query):
        """ load the filesystem image data into the database """
        dbh = self.DBO(query['case'])
        self.progress_str=None
        tablename=dbh.MakeSQLSafe(query['iosource'])
        # call on sleuthkit module to shell out and load data
        Sleuthkit.load_sleuth(query['case'],query['fstype'],tablename,query['iosource'])
        dbh.execute("insert into meta set property='fsimage', value=%r", query['iosource'])

        self.progress_str="Creating file and inode indexes"
        
        #Add indexes:
        index = (
            ('file','inode'),
            ('file','path(100)'),
            ('file','name(100)'),
            ('inode','inode'),
            ('block','inode')
            )
        for x,y in index:
            dbh.execute("alter table %s_%s add index(%s)",(x,tablename,y))

        self.progress_str="Scanning"
        ## Scan the filesystem for hashes and viruses etc.
        iofd=IO.open(query['case'],query['iosource'])
        fsfd=FileSystem.FS_Factory( query["case"], query["iosource"], iofd)
        fsfd.scanfs(Scanner.scanners)
        
    def display(self,query,result):
        result.heading("Uploaded FS Image from IO Source %s to case %s" % (query['iosource'],query['case']))
        result.link("Analyse this data", FlagFramework.query_type((), case=query['case'], family="DiskForensics", fsimage=query['iosource']))
                       
    def progress(self,query,result):
        result.heading("Uploading filesystem image to case %s" % query['case'])
        dbh = self.DBO(query['case'])
        tablename=dbh.MakeSQLSafe(query['iosource'])
        if self.progress_str:
            if self.progress_str == "Scanning":
                result.start_table()
                dbh.execute("select count(*) from file_%s where mode='r/r'" % tablename)
                f = dbh.cursor.fetchone()
                dbh.execute("select count(*) from md5_%s" % tablename)
                g = dbh.cursor.fetchone()
                result.text("Currently scanning files (progress: %u files from %u)" % (g[0],f[0]))
                return
            else:
                result.text(self.progress_str)
                return
            
        try:
            result.start_table()
            dbh.execute("select count(*) from file_%s" % tablename)
            f = dbh.cursor.fetchone()
            result.row("Uploaded File Entries:", "%s"%f[0])
            dbh.execute("select count(*) as count,value as total from inode_%s, meta_%s as m where m.name='last_inode' group by total" % (tablename, tablename))
            row = dbh.fetch()
            result.row("Uploaded Inode Entries:", "%s of %s"%(row['count'],row['total']))
            result.end_table()
        except (TypeError, DB.DBError):
            pass

    def reset(self,query):
        dbh = self.DBO(query['case'])
        tablename = dbh.MakeSQLSafe(query['iosource'])
        Sleuthkit.del_sleuth(query['case'],tablename)
        iofd=IO.open(query['case'],query['iosource'])
        fsfd=FileSystem.FS_Factory( query["case"], query["iosource"], iofd)
        fsfd.scanfs([Scanner.TypeScan,Scanner.MD5Scan],action='reset')

class LoadKB(LoadTcpDump):
    """ Calculates a Knowledgebase based on a Pcap file and stores it in the case """
    parameters = {"datafile":"filename"}
    name = "Build Knowledge Base"
    description = "Builds a knowledge base from a Pcap file "
    order=50
    
    def form(self,query,result):
        result.start_table()
        result.ruler()
        tmp = self.ui()
        tmp.heading("Step 1:")
        result.row(tmp,"Select Case name to load Pcap file into")
        result.case_selector()
        result.ruler()
        tmp = self.ui()
        tmp.heading("Step 2:")
        result.row(tmp,"Select PCAP file to load")
        tmp = self.ui(default = result)
        tmp.filebox()
        result.row("Enter name of file to load:",tmp)
        
    def analyse(self,query):
        datafile=query['datafile']
        Ethereal.load_kb(query['case'],datafile)

    def display(self,query,result):
        result.heading("Calculated the Knowledge Base in case %s " % query['case'])
        link = self.ui(result)
        link.link('Analyse this data',FlagFramework.query_type((),family='KnowledgeBase'))
        result.para(link)

    def progress(self,query,result):
        result.heading("Currently Building Knowledge Base into case %s" % query['case'])
        dbh = self.DBO(query['case'])
        dbh.execute('select count(*) from knowledge_node',())
        a = dbh.cursor.fetchone()
        result.para("Added %s nodes already"%a[0])

    def reset(self,query):
        Ethereal.clear_kb(query['case'])

