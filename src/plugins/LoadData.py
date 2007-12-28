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
#  Version: FLAG $Version: 0.85 Date: Fri Dec 28 16:12:30 EST 2007$
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
from pyflag.FlagFramework import query_type
import pyflag.FileSystem as FileSystem
import pyflag.Scanner as Scanner
import pyflag.Registry as Registry
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.DB as DB
import pyflag.LogFile as LogFile
import plugins.LogAnalysis.LogAnalysis as LogAnalysis
import pyflag.pyflaglog as pyflaglog
import pyflag.ScannerUtils as ScannerUtils
import time
import plugins.LogAnalysis.Whois as Whois
from pyflag.TableObj import IPType
import pyflag.code_parser as code_parser

description = "Load Data"

class LoadPresetLog(Reports.report):
    """ Loads a log file into the database using preset type """
    parameters = {"table":"sqlsafe", "datafile":"any",
                  "preset":"any", "final":"any"}
    name="Load Preset Log File"
    family="Load Data"
    description="Load Data from log file into Database using Preset"
    order=40

    def display(self,query,result):
        result.heading("Uploaded log file into database")
        result.para("Successfully uploaded the following files into case %s, table %s:" % (query['case'],query['table']))
        for fn in query.getarray('datafile'):
            result.para(fn)

        try:
            if len(query['filter'])>1:
                result.text("Log was filtered with: %s\n" % query['filter'], style='red')
        except KeyError:
            pass
        
        result.link("Browse this log file",
                    query_type(case=query['case'],
                               family="Log Analysis",
                               report="ListLogFile",
                               logtable= query['table']))
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
            dbh = DB.DBO(query['case'])
            dbh.execute("select count(*) as count from `%s_log`", (query['table']))
            tmp = dbh.fetch()
            try:
                result.para("Uploaded %s rows. " % tmp['count'])
            except TypeError,e:
                pass
        else:
            result.para(self.progress_str)
            
    def form(self, query, result):
        try:
            result.case_selector()
            result.selector('Select Log Preset','preset',
                            "select name as `key`, name as `value` from log_presets",
                            autosubmit=True)

            result.textfield("Table name:","table")
            result.fileselector("log files to use", 'datafile')

            try:
                if query.getarray('datafile'):
                    log = LogFile.load_preset(query['case'], query['preset'], query.getarray('datafile'))
                else:
                    return result
            except Exception,e:
                result.end_table()
                result.text("\nError: %s\n\n" % e, style='red')
#                raise
                return result

            ## Draw the filter GUI:
            result.add_filter(query, query['case'], code_parser.parse_eval,
                           log.fields, search_text = "Pre-Filter Expression")

            result.ruler()
            result.end_table()
            result.para("Please check the test table before continuing. Note that the filter is not applied to the test table.")

            # show preview
            result.start_table()
            dbh = DB.DBO(query['case'])

            try:
                # retrieve and display the temp table
                log.display_test_log(result, filter=None)
            except Exception,e:
                result.text("Error: Unable to load a test set - maybe this log file is incompatible with this log preset?\nError was %s" % e,style='red',font='bold')
                pyflaglog.log(pyflaglog.DEBUG,"Unable to load test set - error returned was %s" % e)
                return
            
            result.checkbox('Click here to confirm','final','ok')

        except (KeyError, RuntimeError):
            pass

    def analyse(self, query):
        """ Load the log file into the table """
        log = LogFile.load_preset(query['case'], query['preset'], query.getarray('datafile'))
        
        for progress in log.load(query['table'], filter=query.get('filter')):
            self.progress_str = progress
            
    def reset(self, query):
        pass
        #LogFile.drop_table(query['case'], query['table'])

import pyflag.IO as IO

class LoadIOSource(Reports.report):
    """
    Load IO Source
    ==============
    This report loads a new IO source for use within PyFlag. All input
    to PyFlag is done through IO source. IO Sources group the
    different file types that PyFlag supports into a single abstract
    entity which can be later refered to by name.
    """
    parameters = {"iosource":"sqlsafe","subsys":"string"}
    name = "Load IO Data Source"
    family="Load Data"
    description = "Load a data source into flag using IO subsystem"
    order = 10

    def form(self, query, result):
        drivers = Registry.IMAGES.class_names
        try:
            result.const_selector("Select IO Subsystem", 'subsys', drivers, drivers)

            ## Instantiate the required factory:
            image = Registry.IMAGES.dispatch(query['subsys'])()

            image.form(query,result)

            ## Get the name of the source:
            result.textfield("Unique Data Load ID","iosource")
        except KeyError:
            pass

    def display(self, query,result):
        ## Try to instantiate the image:
        try:
            image = Registry.IMAGES.dispatch(query['subsys'])()
        except:
            result.heading("Error: Unable to create IO Source")
            result.para("Could not find a driver for requested IO"\
                        " subsystem (%s). Are you sure you spelt it "\
                        "correctly? It's case sensitive!" % query['subsys'])
            return
    
        try:
            ## Correct the filenames to stem at the UPLOADDIR:
            filenames = query.getarray('filename')
            query.clear('filename')

            ## Adjust all the filenames to be rooted at the UPLOADDIR:
            for f in filenames:
                query['filename'] = os.path.normpath(
                    "%s/%s" % (config.UPLOADDIR, f))

            io = image.open(query['iosource'], query['case'], query)
        except Exception,e:
            pyflaglog.log(pyflaglog.WARNING,"Error instantiating driver: %s" % e)
            raise Reports.ReportError(ui=result, exception=e)

        ## If we get here all went well - go to next step
        result.refresh(0, query_type(case=query['case'],
                                     family="Load Data",
                                     report="LoadFS",
                                     iosource=query['iosource']))
        
##    def form(self,query,result):
##        result.start_table()
##        try:
##            result.case_selector()
##            result.ruler()
##            subsystems=IO.subsystems.keys()
##            result.const_selector("Select IO Subsystem",'subsys',subsystems,subsystems)
##            #this will cause a form to be placed into result.
##            fd=IO.IOFactory(query,result)
##            result.textfield("Unique Data Load ID","iosource")
##        except (KeyError, RuntimeError):
##            pass
##        except IOError, e:
##            result.row("Error: %s" % e, **{'class':'highlight'})

##    def analyse(self,query):
##        # cache serialised io options in the case mata table
##        fd=IO.IOFactory(query)
##        dbh = DB.DBO(query['case'])
##        dbh.insert("meta", property='iosource', value=query['iosource'])
##        dbh.insert("meta", property=query['iosource'],value=fd.get_options())

##    def display(self,query,result):
##        result.refresh(0, FlagFramework.query_type((), case=query['case'], family="Load Data", report="LoadFS", iosource=query['iosource']))

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

    Note that 'path' is a filesystem glob specifying a set of directories to be scanned recursively.
    """
    parameters = {'path':'any', 'final':'string'}
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
               result.textfield('Scan files (glob or path)','path',size=50)

               ## Draw the form for each scan group:
               for cls in ScannerUtils.scan_groups_gen():
                   try:
                       drawer = cls.Drawer()
                       drawer.form(query,result)
                   except RuntimeError:
                       pass
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
        scanner_names = self.calculate_scanners(query)

        pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "Asking pyflash to scan the path: %s with scanners %s" % (query['path'], scanner_names))
            
        #Use pyflash to do all the work
        env = pyflagsh.environment(case=query['case'])
        pyflagsh.shell_execv(env=env, command="scan_path",
                             argv=[query['path'], scanner_names])


    def progress(self,query,result):
        result.heading("Scanning path %s" % (query['path']))
        scanners = self.calculate_scanners(query)
        
        result.para("The following scanners are used: %s" % scanners)
        result.row("System messages:")
        dbh = DB.DBO()
        dbh.execute("select count(*) as size from logs")
        size = dbh.fetch()['size']

        pagesize=20
        dbh.execute("select timestamp,level,message from logs limit %s, %s", (max(size-pagesize,0), pagesize))
        data = '\n'.join(["%(timestamp)s(%(level)s): %(message)s" % row for row in dbh])
        tmp=result.__class__(result)
        tmp.text(data,font='typewriter',style="red")
        result.row(tmp)
        

    def display(self,query,result):
        ## Browse the filesystem instantly
        result.refresh(0, FlagFramework.query_type((),case=query['case'],
           family='Disk Forensics', report='BrowseFS',
           open_tree = query['path'])
                       )
 
class ResetScanners(ScanFS):
    """ This report will reset the specified scanners.

    Normally when files are scanned by the PyFlag scanners, the fact they have been scanned is cached in the database. This will ensure that the same file will never be rescanned by the same scanner again.

    Sometimes it is desired to rescan files again. For example when adding new words to the dictionary. This report will reset the scanners ensuring it is safe to rescan the files again.
    """
    name = "Reset Scanners"
    description = "Reset Scanners run on the VFS"
    order = 40

    def analyse(self,query):
        # We just overwrite this so it doesn't get called in the base class
        pass

    def display(self,query, result):
        
        # We use to call all the scanners from here, but now
        # we just call pyflash to do all the work

        #dbh=DB.DBO(query['case'])
        #fsfd = Registry.FILESYSTEMS.fs['DBFS'](query['case'])
        #
        #
        #scanners = [ ]
        #for i in scanner_names:
        #    try:
        #        tmp  = Registry.SCANNERS.dispatch(i)
        #        scanners.append(tmp(fsfd))
        #    except Exception,e:
        #        pyflaglog.log(pyflaglog.ERRORS,"Unable to initialise scanner %s (%s)" % (i,e))
        #
        #pyflaglog.log(pyflaglog.DEBUG,"Will reset the following scanners: %s" % scanners)

        scanner_names = self.calculate_scanners(query)
        
        ## Use pyflash to do all the work
        env = pyflagsh.environment(case=query['case'])
        pyflagsh.shell_execv(env=env, command="scanner_reset_path",
                             argv=[query['path'], scanner_names])

        ## Reset the ScanFS reports from the database
        FlagFramework.reset_all(family = query['family'], report="Scan Filesystem", case=query['case'])

        ## Browse the filesystem instantly
        result.refresh(0, FlagFramework.query_type((),case=query['case'],
           family='Disk Forensics', report='BrowseFS',
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
    """ Loads Filesystem Image into the database.

    PyFlag Uses a Virtual File System (VFS) to present information about all filesystems within a case. When a filesystem is loaded, it is usually loaded inot a specified mount point. This is a path (directory) which will contain all the files in this filesystem within it.

    The mount point can be any valid path, but its probably most sensible to make it the same as the mount point of the original filesystem within the system drive. For example /freds_box/c/ or /fred/usr/.
    """
    parameters = {"iosource":"string","fstype":"string", "mount_point":"string"}
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
            result.selector('Select IO Data Source', 'iosource',
                            "select name as `key`,name as `value` from iosources",
                            case=query['case'])
            
            # initialise/open the subsystem
            fd=IO.open(query['case'],query['iosource'])

            ## We need to ask all our filesystems to have a go at
            ## this:
            metadata = {}
            order = []
            for c in Registry.FILESYSTEMS.classes:
                c = c(query['case'])
                guess = c.guess(fd, result, metadata)
                if guess>0:
                    order.append((guess , c.name))

            ## Sort according to the guess value
            order.sort(lambda x,y: y[0] - x[0])
                    
            ## We only show those whose guess is within 100 off
            ## the top - this allows a strong guess to bump out
            ## weaker guesses.
            maximum = order[0][0]
            fs_types = [ x[1] for x in order if x[0] > maximum - 100 ]

            ## If only one option is possible here, 
            if len(fs_types)==1:
                result.hidden('fstype',fs_types[0], exclusive = True)
            else:
                result.const_selector("Enter Filesystem type",'fstype',fs_types,fs_types)

            result.textfield("VFS Mount Point:","mount_point")
            result.ruler()
        except IOError,e:
            result.text("IOError %s" % e,style='red')
        except (KeyError,TypeError),e:
            #FlagFramework.get_traceback(e,result)
            pass

    def analyse(self,query):
        """ load the filesystem image data into the database """
        dbh = DB.DBO(query['case'])
        self.progress_str=None

        # call on FileSystem to load data
        fsobj=Registry.FILESYSTEMS.dispatch(query['fstype'])(query['case'])
        mount_point = FlagFramework.normpath("/"+query['mount_point'])
        fsobj.load(mount_point, query['iosource'])
        dbh.set_meta("mount_point_%s" % query['iosource'] , mount_point)

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
            dbh.check_index(x,y,z)

    def display(self,query,result):
        result.heading("Uploaded FS Image from IO Source %s to case %s" % (query['iosource'],query['case']))
        result.link("Analyse this data", FlagFramework.query_type((), case=query['case'], family="Disk Forensics",report='BrowseFS'))
        result.refresh(0,FlagFramework.query_type((), case=query['case'], family="Disk Forensics", report='BrowseFS'))
                       
    def progress(self,query,result):
        result.heading("Uploading filesystem image to case %s" % query['case'])
        dbh = DB.DBO(query['case'])
        tablename=dbh.MakeSQLSafe(query['iosource'])
        if self.progress_str:
            result.text(self.progress_str)
            return
            
        try:
            result.start_table()
            dbh.execute("select count(*) as Count from file")
            row=dbh.fetch()
            if row:
                result.row("Uploaded File Entries: %s"%row['Count'])

            result.row("System messages:")
            tmp=result.__class__(result)
            tmp.text('\n'.join(pyflaglog.ring_buffer),font='typewriter',style="red")
            result.row(tmp)
            result.end_table()
        except (TypeError, DB.DBError):
            pass

    def reset(self,query):
        dbh = DB.DBO(query['case'])
        tablename = dbh.MakeSQLSafe(query['iosource'])
        fsobj=Registry.FILESYSTEMS.dispatch(query['fstype'])(query['case'],tablename,query['iosource'])
        fsobj.delete()


## Unit Tests:
import unittest, md5
import pyflag.pyflagsh as pyflagsh
from pyflag.FileSystem import DBFS

## Is this even needed any more? Surely it should be enough with all
## the scanner tests?
class LoadDataTests(unittest.TestCase):
#class LoadDataTests:
    """ Forensic Image Loading Tests """
    order = 1
    test_case = "PyFlagTestCase"
    def test01CaseCreation(self):
        """ Test that basic tables have been added to new cases """
        pyflagsh.shell_execv(command="execute",
                             argv=["Case Management.Remove case",'remove_case=%s' % self.test_case])

        pyflagsh.shell_execv(command="execute",
                             argv=["Case Management.Create new case",'create_case=%s' % self.test_case])

        dbh = DB.DBO(self.test_case)
        dbh.execute("show tables")
        tables = [ row.values()[0] for row in dbh ]
        ## At a minimum these tables must exist:
        for required in ['annotate', 'block', 'file', 'filesystems',
                         'inode', 'meta', 'resident', 'sql_cache', 'xattr']:
            self.assert_(required in tables)

    def test02LoadFilesystem(self):
        """ Test that basic filesystems load """
        pyflagsh.shell_execv(command="execute",
                             argv=["Load Data.Load IO Data Source",'case=%s' % self.test_case,
                                   "iosource=first_image",
                                   "subsys=Advanced",
                                   "filename=pyflag_stdimage_0.4.dd" ,
                                   "offset=16128s",
                                   ])
        pyflagsh.shell_execv(command="execute",
                             argv=["Load Data.Load Filesystem image",'case=%s' % self.test_case,
                                   "iosource=first_image",
                                   "fstype=Sleuthkit",
                                   "mount_point=/stdimage/"])
        dbh = DB.DBO(self.test_case)
        dbh.execute("select count(*) as count from inode")
        self.assertEqual(dbh.fetch()['count'],82)

    def test03MultipleSources(self):
        """ Test that multiple images can be loaded on the same VFS """
        pyflagsh.shell_execv(command="execute",
                             argv=["Load Data.Load IO Data Source",'case=%s' % self.test_case,
                                   "iosource=second_image",
                                   "subsys=EWF",
                                   "filename=ntfs_image.e01" ,
                                   ])
        pyflagsh.shell_execv(command="execute",
                             argv=["Load Data.Load Filesystem image",'case=%s' % self.test_case,
                                   "iosource=second_image",
                                   "fstype=Sleuthkit",
                                   "mount_point=/ntfsimage/"])

        ## Try to read a file from the first source:
        fsfd = DBFS(self.test_case)
        fd = fsfd.open("/stdimage/dscf1081.jpg")
        m = md5.new()
        m.update(fd.read())
        self.assertEqual(m.hexdigest(),'11bec410aebe0c22c14f3eaaae306f46')

        ## Try to read a file from the second source:
        fd = fsfd.open("/ntfsimage/Books/80day11.txt")
        m = md5.new()
        m.update(fd.read())
        self.assertEqual(m.hexdigest(),'f5b394b5d0ca8c9ce206353e71d1d1f2')

