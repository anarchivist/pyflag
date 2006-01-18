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
#  Version: FLAG $Version: 0.78 Date: Fri Aug 19 00:47:14 EST 2005$
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
import pyflag.Registry as Registry
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.DB as DB
import pyflag.LogFile as LogFile
import plugins.LogAnalysis.LogAnalysis as LogAnalysis
import pyflag.logging as logging
import pyflag.ScannerUtils as ScannerUtils

description = "Load Data"

class LoadPresetLog(Reports.report):
    """ Loads a log file into the database using preset type """
## See FIXME below
##    parameters = {"table":"any", "new_table":"any",
##                  "datafile":"filename", "log_preset":"sqlsafe", "final":"alphanum"}
    parameters = {"table":"sqlsafe", "datafile":"filename",
                  "log_preset":"sqlsafe", "final":"alphanum"}
    name="Load Preset Log File"
    family="Load Data"
    description="Load Data from log file into Database using Preset"
    order=40

    def display(self,query,result):
        result.heading("Uploaded log file into database")
        result.para("Successfully uploaded the following files into case %s, table %s:" % (query['case'],query['table']))
        for fn in query.getarray('datafile'):
            result.para(fn)
        result.link("Browse this log file", FlagFramework.query_type((), case=query['case'], family="Log Analysis", report="ListLogFile", logtable="%s"%query['table']))
        return result

    progress_str = None
    
    def progress(self,query,result):
        result.heading("Currently uploading log file into database")
        try:
            tmp = query['new_table']
            del query['table']
            query['table'] = tmp
        except KeyError:
            pass

        if not self.progress_str:
            dbh = self.DBO(query['case'])
            dbh.execute("select count(*) as count from %s_log", (query['table']))
            tmp = dbh.fetch()
            try:
                result.para("Uploaded %s rows. " % tmp['count'])
            except TypeError,e:
                pass
        else:
            result.para(self.progress_str)
            
    def form(self, query, result):
        try:
            result.start_table()
            result.case_selector()
            result.meta_selector(config.FLAGDB,'Select preset type','log_preset',onclick="this.form.submit();")
            ## FIXME: This is a nice idea but it stuffs up the framework's idea of whats cached and what isnt... this needs more work!!!
            # get existing tables
##            dbh = self.DBO(query['case'])
##            dbh.execute('select value from meta where property=%r group by value', 'logtable')
##            tables = [row['value'][:-4] for row in dbh]
##            tables.append('NEW')
##            result.const_selector('Insert into Table', 'table', tables, tables)
##            result.textfield("OR Enter New table name:","new_table")
            result.textfield("Table name:","table")

            tmp = self.ui(result)
            tmp.filebox()
            result.row("Select file to load:",tmp)
            if query.getarray('datafile'):
                log = LogFile.get_loader(query['log_preset'],query.getarray('datafile'))
            else:
                return result

            result.end_table()
            
            # show preview
            result.start_table()
            dbh = self.DBO(query['case'])
            temp_table = dbh.get_temp()
            try:
                for progress in log.load(dbh,temp_table, rows=3):
                    pass

                # retrieve and display the temp table
                dbh.execute("select * from %s limit 1",temp_table)
                LogAnalysis.display_test_log(dbh,log,result,query)
            except Exception,e:
                result.text("Error: Unable to load a test set - maybe this log file is incompatible with this log preset?",color='red',font='bold')
                logging.log(logging.DEBUG,"Unable to load test set - error returned was %s" % e)
                return
            
            result.end_table()
            
            result.checkbox('Click here when finished','final','ok')
            
        except KeyError:
            pass

    def analyse(self, query):
        """ Load the log file into the table """
        log = LogFile.get_loader(query['log_preset'],query.getarray('datafile'))
        dbh = self.DBO(query['case'])
        
        ## Check to make sure that this table is not used by some other preset:
        dbh.execute("select * from meta where property='log_preset_%s'" ,query['table'])
        row=dbh.fetch()
        if row:
            raise Reports.ReportError("Table %s already exists with a conflicting preset (%s) - you can only append to the same table with the same preset." % (query['table'],row['value']))
        
        for progress in log.load(dbh,'%s_log'%query['table']):
            self.progress_str = progress
            
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

import pyflag.IO as IO

class LoadIOSource(Reports.report):
    """ Initialises and caches an IO Subsystem datasource into the database for
    subsequent use by other reports (eg. LoadFS and exgrep) """
    parameters = {"iosource":"sqlsafe","subsys":"iosubsystem"}
    name = "Load IO Data Source"
    family="Load Data"
    description = "Load a data source into flag using IO subsystem"
    order = 10

    def form(self,query,result):
        result.start_table()

        try:
            result.case_selector()
            result.ruler()
            subsystems=IO.subsystems.keys()
            result.const_selector("Select IO Subsystem",'subsys',subsystems,subsystems)
            #this will cause a form to be placed into result.
            fd=IO.IOFactory(query,result)
            result.textfield("Unique Data Load ID","iosource")
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
        result.refresh(0, FlagFramework.query_type((), case=query['case'], family="Load Data", report="LoadFS", iosource=query['iosource']))

class ScanFS(Reports.report):
    """ A report used to scan the filesystem using the specified scanners.

    There can be many scanners in a typical PyFlag installation
    (Scanners are found in the plugin directory). It can be quite
    inefficient for the user to select all of the scanners. We prefer
    to group the scanners into groups which can be selected en-mass or
    tuned specifically.

    This report presents those groups which will apply to the current
    file system. Users may then fine tune each group by clicking on
    the configure button.

    The following rules apply to scanners:
    
    - The same file can not be scanned twice by the same scanner.
    - If an enabled scanner depends on another scanner to execute, that scanner will be enabled in order to satisfy the dependancy.

    """
    parameters = {'fsimage':'fsimage', 'path':'any', 'final':'string'}
    name = "Scan Filesystem"
    description = "Scan filesystem using spceified scanners"
    family = "Load Data"
    order = 30
    
    def __init__(self,flag,ui=None):
        Reports.report.__init__(self,flag,ui)
        self.parameters = self.parameters.copy()
        ## Work out what scan groups are available and require they be
        ## in the parameters:
        for cls in ScannerUtils.scan_groups_gen():
            drawer = cls.Drawer()
            scan_group_name = drawer.get_group_name()
            ## Add the scan group to our parameters - this will ensure
            ## that type checking is done on it:
            self.parameters[scan_group_name]='onoff'
            ## Adjust this reports parameters list. This is
            ## required to ensure that caching works correctly
            ## (caching must include all the individual scanners so
            ## they are sensitive to changes in sub group tuning)
            for k,t in drawer.get_parameters():
                self.parameters[k]=t

    def form(self,query,result):
        try:
            result.case_selector()
            if query['case']!=config.FLAGDB:
               result.meta_selector(case=query['case'],property='fsimage')
               result.textfield('Scan under directory','path',size=50)

               ## Draw the form for each scan group:
               for cls in ScannerUtils.scan_groups_gen():
                   drawer = cls.Drawer()
                   drawer.form(query,result)
               result.checkbox('Click here when finished','final','ok')

        except KeyError:
            return result

    def calculate_scanners(self,query):
        """ Calculates the scanners required, filling in dependancies
        and considering scanner groups.

        returns an array of scanner names.
        """
        ## The scanners that users asked for:
        q = FlagFramework.query_type(())
        for cls in ScannerUtils.scan_groups_gen():
            drawer=cls.Drawer()
            drawer.add_defaults(q,query)

        scanner_names = []
        l = len("scan_")
        for k,v in q:
            if k[:l]=="scan_" and v=='on':
                scanner_names.append(k[l:])

        ## Now pull in any scanners which are needed
        ScannerUtils.fill_in_dependancies(scanner_names)
        
        return scanner_names

    def analyse(self,query):
        dbh=DB.DBO(query['case'])
        iofd=IO.open(query['case'],query['fsimage'])
        fsfd = Registry.FILESYSTEMS.fs['DBFS'](query['case'],query['fsimage'],iofd)

        scanner_names = self.calculate_scanners(query)
        
        scanners = [ ]
        for i in scanner_names:
            try:
                tmp  = Registry.SCANNERS.dispatch(i)
                scanners.append(tmp(dbh,query['fsimage'],fsfd))
            except Exception,e:
                logging.log(logging.ERRORS,"Unable to initialise scanner %s (%s)" % (i,e))

        ## Now sort the scanners by their specified order:
        def cmpfunc(x,y):
            if x.order>y.order:
                return 1
            elif x.order<y.order:
                return -1

            return 0

        scanners.sort(cmpfunc)

        logging.log(logging.DEBUG,"Will invoke the following scanners: %s" % scanners)
        ## Prepare the scanner factories for scanning:
        for s in scanners:
            s.prepare()

        def process_directory(root):
            """ Recursive function for scanning directories """
            ## First scan all the files in the directory
            for stat in fsfd.longls(path=root,dirs=0):
                logging.log(logging.DEBUG,"Scanning file %s%s (inode %s)" % (stat['path'],stat['name'],stat['inode']))
                try:
                    fd=fsfd.open(inode=stat['inode'])
                    Scanner.scanfile(fsfd,fd,scanners)
                except IOError,e:
                    logging.log(logging.WARNINGS,"Unable to open file %s/%s: %s" % (stat['path'],stat['name'],e))
                except Exception,e:
                    logging.log(logging.ERRORS,"Error scanning inode %s: %s" % (stat['inode'],e))
                    
            ## Now recursively scan all the directories in this directory:
            for directory in fsfd.ls(path=root,dirs=1):
                new_path = "%s%s/" % (root,directory)
                process_directory(new_path)
                    
        process_directory(query['path'])

        ## Destroy the scanner factories:
        for s in scanners:
            s.destroy()

    def progress(self,query,result):
        result.heading("Scanning filesystem %s in path %s" % (query['fsimage'],query['path']))
        scanners = self.calculate_scanners(query)
        
        result.para("The following scanners are used: %s" % scanners)
        result.row("System messages:")
        tmp=result.__class__(result)
        tmp.text('\n'.join(logging.ring_buffer),font='typewriter',color="red")
        result.row(tmp)
        

    def display(self,query,result):
        ## Browse the filesystem instantly
        result.refresh(0, FlagFramework.query_type((),case=query['case'],
           family='Disk Forensics', report='BrowseFS', fsimage=query['fsimage'],
           open_tree = query['path'])
                       )

def get_default_fs_driver(query,sig):
    """ Try to guess a good default filesystem driver based on the magic """
    ## Only do this if one was not already supplied
    if not query.has_key('fstype'):
        if "tcpdump" in sig:
            query['fstype'] = "PCAP Filesystem"
        else:
            query['fstype'] = "Auto FS"

class LoadFS(Reports.report):
    """ Loads Filesystem Image into the database. """
    parameters = {"iosource":"iosource","fstype":"string"}
    name = "Load Filesystem image"
    family="Load Data"
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

            fs_types = Registry.FILESYSTEMS.filesystems.keys()
            fs_types.sort()
            
            ## Try to get a magic hint
            try:
                magic = FlagFramework.Magic()
                result.ruler()
                sig = magic.buffer(fd.read(10240))
                result.row("Magic identifies this file as: %s" % sig,colspan=50,bgcolor=config.HILIGHT)
                fd.close()

                get_default_fs_driver(result.defaults,sig)
                
                result.const_selector("Enter Filesystem type",'fstype',fs_types,fs_types)
                result.ruler()
            except FlagFramework.FlagException,e:
                result.hidden('fstype','Mounted')
        except IOError,e:
            result.text("IOError %s" % e,color='red')
        except (KeyError,TypeError),e:
#            FlagFramework.get_traceback(e,result)
            pass

    def analyse(self,query):
        """ load the filesystem image data into the database """
        dbh = self.DBO(query['case'])
        self.progress_str=None
        
        #Check to see if we have done this part previously
        if dbh.get_meta('fsimage')!=query['iosource']:
            tablename=dbh.MakeSQLSafe(query['iosource'])
            io = IO.open(query['case'],query['iosource'])
            # call on FileSystem to load data
            fsobj=Registry.FILESYSTEMS.filesystems[query['fstype']](query['case'],tablename,io)
            fsobj.load()

            self.progress_str="Creating file and inode indexes"        
            #Add indexes:
            index = (
                ('file','inode',None),
                ('file','path',100),
                ('file','name',100),
                ('inode','inode',None),
                ('block','inode',None)
                )
            for x,y,z in index:
                dbh.check_index("%s_%s" % (x,tablename),y,z)

            dbh.set_meta('fsimage',query['iosource'])
            dbh.set_meta('fstype_%s' % query['iosource'],query['fstype'])
        
    def display(self,query,result):
        result.heading("Uploaded FS Image from IO Source %s to case %s" % (query['iosource'],query['case']))
        result.link("Analyse this data", FlagFramework.query_type((), case=query['case'], family="Disk Forensics", fsimage=query['iosource'],report='BrowseFS'))
        result.refresh(0,FlagFramework.query_type((), case=query['case'], family="Disk Forensics", fsimage=query['iosource'],report='BrowseFS'))
                       
    def progress(self,query,result):
        result.heading("Uploading filesystem image to case %s" % query['case'])
        dbh = self.DBO(query['case'])
        tablename=dbh.MakeSQLSafe(query['iosource'])
        if self.progress_str:
            result.text(self.progress_str)
            return
            
        try:
            result.start_table()
            dbh.execute("select count(*) as Count from file_%s" % tablename)
            row=dbh.fetch()
            if row:
                result.row("Uploaded File Entries: %s"%row['Count'])

            result.row("System messages:")
            tmp=result.__class__(result)
            tmp.text('\n'.join(logging.ring_buffer),font='typewriter',color="red")
            result.row(tmp)
            ## FIXME: This is a horribly slow query...
  #          dbh.execute("select count(*) as count,value as total from inode_%s, meta_%s as m where m.name='last_inode' group by total" % (tablename, tablename))
  #          row = dbh.fetch()
  #          result.row("Uploaded Inode Entries:", "%s of %s"%(row['count'],row['total']))
            result.end_table()
        except (TypeError, DB.DBError):
            pass

    def reset(self,query):
        dbh = self.DBO(query['case'])
        tablename = dbh.MakeSQLSafe(query['iosource'])
        fsobj=Registry.FILESYSTEMS.filesystems[query['fstype']](query['case'],tablename,query['iosource'])
        fsobj.delete()
