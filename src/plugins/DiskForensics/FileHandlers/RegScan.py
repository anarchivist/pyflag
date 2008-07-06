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
""" This Module handles windows registry files.

This module contains a scanner to trigger off on registry files and scan them seperately. A report is also included to allow tree viewing and table searching of registry files.
"""
import os.path
from pyflag.Scanner import *
import plugins.DiskForensics.DiskForensics as DiskForensics
import pyflag.DB as DB
from pyflag.FlagFramework import query_type,HexDump
import pyflag.FlagFramework as FlagFramework
import pyflag.Reports as Reports
from FileFormats.RegFile import ls_r, RegF
from format import Buffer
from pyflag.ColumnTypes import StringType, TimestampType, InodeType

class RegEventHandler(FlagFramework.EventHandler):
    def create(self, dbh, case):
        dbh.execute("""CREATE TABLE if not exists `reg` (
        `inode_id` INT NOT NULL,
        `path` text NOT NULL,
        `offset` INT(11),
        `type` enum('REG_NONE','REG_SZ','REG_EXPAND_SZ','REG_BINARY','REG_DWORD',\
          'REG_DWORD_BIG_ENDIAN','REG_LINK','REG_MULTI_SZ','REG_RESOURCE_LIST',\
          'REG_FULL_RESOURCE_DESCRIPTOR','REG_RESOURCE_REQUIREMENTS_LIST',\
          'Unknown') NOT NULL,
        `modified` TIMESTAMP NULL DEFAULT '0000-00-00 00:00:00',
        `reg_key` VARCHAR(200) NOT NULL,
        `value` text,
        key (`inode_id`))""")        

        ## The regi table is used for the key navigation
        dbh.execute("""create table if not exists regi (
        `dirname` TEXT NOT NULL ,`basename` TEXT NOT NULL)""")
            
class RegistryScan(GenScanFactory):
    """ Load in Windows Registry files """
    default = True
    depends = ['TypeScan']
    group = "FileScanners"
    
    def reset(self, inode):
        GenScanFactory.reset(self, inode)
        dbh=DB.DBO(self.case)
        dbh.execute('delete from reg')
        dbh.execute('delete from regi')
        
    def destroy(self):
        ## Add indexes:
        dbh=DB.DBO(self.case)

    class Scan(StoreAndScanType):
        types =  (
            'application/x-winnt-registry',
## FIXME: NOT Currently supported temporarily
#            'application/x-win9x-registry',
            )
        
        def external_process(self,fd):
            b=Buffer(fd)
            header = RegF(b)
            root_key = header['root_key_offset'].get_value()
            parent_path, inode, inode_id = self.ddfs.lookup(inode=self.inode)
            parent_path += '/'
            
            ## One handle does the reg table, the other handle the
            ## regi table:
            regi_handle=DB.DBO(self.case)
            reg_handle=DB.DBO(self.case)

            reg_handle.mass_insert_start('reg')
            regi_handle.mass_insert_start('regi')

            ## Make sure that parents are properly created in the regi
            ## table:
            dirs = parent_path.split("/")
            for d in range(len(dirs)-1,0,-1):
                path = "/".join(dirs[:d])+"/"
                print path
                regi_handle.execute("select * from regi where dirname=%r and basename=%r", (path, dirs[d]))
                if not regi_handle.fetch():
                    regi_handle.insert("regi", dirname=path, basename=dirs[d], _fast=True)
                else:
                    break
            
            def store_key(nk_key, path):
                if not nk_key: return
                regi_handle.mass_insert(dirname=path,
                                        basename=nk_key['key_name'])

                new_path="%s/%s/" % (path,nk_key['key_name'])
                new_path=FlagFramework.normpath(new_path)
                
                ## Store all the values:
                for v in nk_key.values():
                    reg_handle.mass_insert(inode_id = inode_id,
                                           path=new_path,
                                           offset=v['data']['offs_data'],
                                           _modified="from_unixtime(%d)" % nk_key['WriteTS'].get_value(),
                                           type=v['data']['val_type'],
                                           reg_key=v['keyname'],
                                           value=v['data']
                                           )
                    
                for k in nk_key.keys():
                    store_key(k,new_path)

            store_key(root_key,path=parent_path)
            reg_handle.mass_insert_commit()
            regi_handle.mass_insert_commit()
            
            regi_handle.check_index("reg" ,"path",250)
            regi_handle.check_index("regi" ,"dirname",100)
            regi_handle.check_index("reg" ,"reg_key")

            ## Recreate the interesting reg key table
            regi_handle.drop("interestingregkeys");
            
            ## These collect interesting keys. FIXME - Do we really
            ## need the like clause its very slow especially since it
            ## has a wildcard at the start.
            regi_handle.execute("""create table `interestingregkeys` select 
            a.path, a.modified, a.type,a.reg_key, a.value, b.category, 
            b.description from reg as a, %s.registrykeys as b where a.path 
            LIKE concat('%%',b.path,'%%') AND
            a.reg_key=b.reg_key""",(config.FLAGDB))

## Report to browse Loaded Registry Files:
class BrowseRegistry(DiskForensics.BrowseFS):
    """ Browse a Windows Registry file """
    description="Browse a windows registry hive file (found in c:\winnt\system32\config\) "
    name = "Browse Registry Hive"

    def display(self,query,result):
        result.heading("Registry Hive")
        dbh = self.DBO(query['case'])
        new_q=query.clone()
                            
        def table_notebook_cb(query,result):
            del new_q['mode']
            del new_q['mark']
            new_q['__target__']='open_tree'
            new_q['mode'] = 'Tree View'

            result.table(
                elements = [ StringType('Path','path',
                                link = new_q),
                             StringType('Type','type'),
                             StringType('Key','reg_key'),
                             TimestampType('Modified','modified'),
                             StringType('Value','value') ],
                table='reg',
                case=query['case'],
                filter = "filter1"
                )

        def tree_notebook_cb(query,result):

            #Make a tree call back:
            def treecb(path):
                """ This call back will render the branch within
                the registry file."""
                dbh = DB.DBO(query['case'])

                path = FlagFramework.normpath(path+"/")

                ##Show the directory entries:
                dbh.execute("select basename from regi where dirname=%r",(path))
                for row in dbh:
                    yield(([row['basename'],row['basename'],'branch']))

            def pane_cb(path,table):
                tmp=result.__class__(result)
                path = path+'/'
                dbh.execute("select modified as time from reg where path=%r limit 1",(path))
                row=dbh.fetch()

                try:
                    tmp.text("Last modified %s " % row['time'],style='red')
                    table.row(tmp)
                except TypeError:
                    pass

                def callback(value):
                    if len(value)>50:
                        value = value[:50] + " ..."

                    return value

                # now display keys in table
                new_q['mode'] = 'display'
                new_q['path']=path
                table.table(
                    elements = [ StringType('Key','reg_key',
                                   link = query_type(family=query['family'],
                                                     report='BrowseRegistryKey',
                                                     path=path,
                                                     __target__='key',
                                                     case=query['case'])),

                                 StringType('Type','type'),
                                 StringType('Value','value', callback = callback) ],
                    table='reg',
                    where="path=%r" % path,
                    case=query['case'],
                    filter = "filter2"
                    )

            # display paths in tree
            result.tree(tree_cb=treecb,pane_cb=pane_cb,branch=[''])

        result.notebook(
            names=['Tree View','Table View'],
            callbacks=[tree_notebook_cb,table_notebook_cb],
            context='mode',
            )
            
    def reset(self,query):
        dbh = self.DBO(query['case'])

        dbh.execute('drop table if exists reg')
        dbh.execute('drop table if exists regi')

class BrowseRegistryKey(BrowseRegistry):
    """ Display the content of a registry key """
    parameters= {'key':'string','path':'string'}
    hidden=True
    name="BrowseRegistryKey"
    family="Disk Forensics"
    description =    """ Display the content of a registry key """

    def display(self,query,result):
        path=query['path']
        key=query['key']
        result.heading("Registry Key Contents")
        result.text("Key %s/%s:" % (path,key),style='red',font='typewriter')
        dbh=DB.DBO(query['case'])

        def hexdump(query,out):
            """ Show the hexdump for the key """
            dbh.execute("select value from reg where path=%r and reg_key=%r limit 1",(path,key))
            row=dbh.fetch()
            if row:
                HexDump(row['value'],out).dump()
            return out

        def strings(query,out):
            """ Draw the strings in the key """
            out.para("not implimented yet")
            return out

        def stats(query,out):
            """ display stats on a key """
            out.para("not implemented yet")
            return out

        result.notebook(
            names=["HexDump","Strings","Statistics"],
            callbacks=[hexdump,strings,stats],
            context="display_mode"
            )

class InterestingRegKey(Reports.report):
    """ Displays values of interesting registry keys, grouped into categories """
    name = "Interesting Reg Keys"
    family = "Disk Forensics"
    description="This report shows the values of interesting registry keys on the disk"
    progress_dict = {}

    def form(self,query,result):
        result.case_selector()
        
    def progress(self,query,result):
        result.heading("Looking for registry key values");

    def reset(self,query):
        dbh = self.DBO(query['case'])
        dbh.execute('drop table interestingregkeys');

    def display(self,query,result):
        result.heading("Interesting Registry Keys")
        dbh=self.DBO(query['case'])

        result.table(
            elements = [ StringType('Path','path'),
                         StringType('Key','reg_key'),
                         StringType('Value','value'),
                         TimestampType('Last Modified','modified'),
                         StringType('Category','category'),
                         StringType('Description','description') ],
            table='interestingregkeys',
            case=query['case'],
            )

class InterestingRegKeyInit(FlagFramework.EventHandler):
    def init_default_db(self, dbh,case):
        dbh.execute("""CREATE TABLE `registrykeys` (
 	`id` int auto_increment,
        `path` VARCHAR( 250 ) ,
        `reg_key` VARCHAR( 200 ) ,
        `category` VARCHAR( 100 ),
        `description` TEXT ,
        PRIMARY KEY  (`id`)
        )""")

        ## FIXME: This should really be in an external file
        keys = [
            ( 'Software/Microsoft/CurrentVersion/Applets/Paint', 'Recent File List', 'User Activity', 'Maintains a list of image files accessed with Paint'),
            ( 'Software/Microsoft/CurrentVersion/Applets', 'RegEdit', 'User Activity', 'The LastKey value maintains the last key accessed using RegEdit'),
            ( 'Software/Microsoft/CurrentVersion/Applets/RegEdit', 'Favorites', 'User Activity', 'Maintains a list of favorites added through Favorites menu item in RegEdit'),
            ( 'Software/Microsoft/CurrentVersion/Applets/WordPad', 'Recent File List', 'User Activity', 'List of files accessed/saved in WordPad'),
            ( 'Software/Microsoft/Search Assistant', 'ACMru', 'User Activity', 'Maintains a list of items searched for via Start->Search; the subkeys (5001'),
            ( 'Software/Microsoft/Internet Explorer', 'TypedURLs', 'User Activity', 'Maintains a list of URLs typed into the IE Address bar'),
            ( 'Software/Microsoft/Windows/CurrentVersion/Explorer', 'RecentDocs', 'User Activity', 'RecentDocs'),
            ( 'Software/Microsoft/Windows/CurrentVersion/Explorer/ComDlg32', 'LastVisitedMRU', 'User Activity', 'Maintains a list of programs accessed'),
            ( 'Software/Microsoft/Windows/CurrentVersion/Explorer/ComDlg32', 'OpenSaveMRU', 'User Activity', 'Maintains a list of files that are opened or saved via Windows Explorer-style dialog boxes'),
            ( 'Software/Microsoft/Windows/CurrentVersion/Explorer', 'StreamMRU', 'User Activity', 'streamMRU'),
            ( 'Software/Microsoft/Windows/CurrentVersion/Explorer', 'RunMRU', 'User Activity', 'Maintains a list of entries typed into the Start->Run box'),
            ( 'Software/Microsoft/Windows/CurrentVersion/Explorer', 'Doc Find Spec MRU', 'User Activity', 'Do find'),
            ( 'Software/Microsoft/Windows/CurrentVersion/Explorer', 'FindComputerMRU', 'User Activity', 'Maintains a list of entries for computers searched for via Windows Explorer'),
            ( 'Software/Microsoft/Windows/CurrentVersion/Explorer', 'UserAssist', 'User Activity', 'There are two GUID subkeys beneath this key.  Beneath each of these keys is the Count subkey'),
            ( 'Software/Microsoft/Windows/CurrentVersion/Explorer', 'Map Network Drive MRU', 'User Activity', 'Maintains a list of drive mapped via the Map Network Drive Wizard.'),
            ( 'Software/Microsoft/Windows/CurrentVersion/Explorer', 'ComputerDescriptions', 'User Activity', 'Values beneath this key are names or IP addresses of machines connected to.'),
            ( 'Software/Microsoft/Windows/CurrentVersion/Explorer', 'MountPoints2', 'User Activity', 'Subkeys that start with # are paths to drives that have been mounted; includes the use of the net use command.  BaseClass value will usually be Drive.'),
            ( 'Software/Microsoft/Windows/CurrentVersion/Explorer/MountPoints2/CPC', 'Volume', 'User Activity', 'Each GUID subkey includes a Data value.  This value is a volume identifier.'),
            ( 'Software/Microsoft/MediaPlayer/Player', 'RecentFileList', 'User Activity', 'List of files (movies - .mpg'),
            ( 'Software/Microsoft/MediaPlayer/Player', 'RecentURLList', 'User Activity', 'recent url list'),
            ( 'Software/Microsoft/Office/{version}/Common/Open Find/{product}/Settings/Open', 'File Name MRU', 'User Activity', 'Value is Reg_Multi_SZ containing a list of file names'),
            ( 'Software/Microsoft/Office/{version}/Common/Open Find/{product}/Settings/Save As', 'File Name MRU', 'User Activity', 'Value is Reg_Multi_SZ containing a list of file names'),
            ( 'Software/Nico Mak Computing/WinZip', 'filemenu', 'User Activity', 'List of recently used WinZip archives'),
            ( 'Control Panel/Desktop', 'SCRNSAVE.EXE', 'Launch Point', 'LaunchPoint'),
            ( 'Software/Microsoft/Command Processor', 'AutoRun', 'Launch Point', 'Launch Point'),
            ( 'Software/Microsoft/Internet Explorer', 'Explorer Bars', 'Launch Point', 'Launch Point'),
            ( 'Software/Microsoft/Internet Explorer', 'Extensions', 'Launch Point', 'Launch Point'),
            ( 'Software/Microsoft/Internet Explorer/Toolbar', 'ShellBrowser', 'Launch Point', 'All'),
            ( 'Software/Microsoft/Internet Explorer/Toolbar', 'WebBrowser', 'Launch Point', 'Launch Point'),
            ( 'Software/Microsoft/Windows/CurrentVersion/Policies/Explorer', 'Run', 'Launch Point', 'Launch Point W2K/WXP'),
            ( 'Software/Microsoft/Windows/CurrentVersion/Policies/System', 'Shell', 'Launch Point', 'Launch Point W2K/WXP'),
            ( 'Software/Microsoft/Windows/CurrentVersion', 'Run', 'Launch Point', 'Lists programs to be run when system starts.  On 2K and XP these entries are ignored when booted to Safe Mode; Andy Aronoff owner of SilentRunners.org says that the contents of any subkey will be launched.  At this point I haven''t tested it.'),
            ( 'Software/Microsoft/Windows/CurrentVersion', 'Run', 'Launch Point', 'Auto Start'),
            ( 'Software/Microsoft/Windows/CurrentVersion', 'RunOnce', 'Launch Point', 'Lists programs to be run once when the system starts and deleted.  The commands listed here are deleted before the actual commands are run.  If the command is preceded by ! the command is deleted after the command is run.'),
            ( 'Software/Microsoft/Windows/CurrentVersion', 'ShellServiceObjectDelayLoad', 'Launch Point', 'Launch Point All'),
            ( 'Software/Microsoft/Windows NT/CurrentVersion/Windows', 'load', 'Launch Point', 'Launch Point'),
            ( 'Software/Microsoft/Windows NT/CurrentVersion/Windows', 'run', 'Launch Point', 'Launch Point NT4+'),
            ( 'Software/Microsoft/Windows NT/CurrentVersion/Winlogon', 'Shell', 'Launch Point', 'Launch Point NT4+'),
            ( 'Software/Policies/Microsoft/Windows/System', 'Scripts', 'Launch Point', 'Launch Point W2K/WXP'),
            ( 'Software/Classes/ CLASSID Stopped by REAPOFF/{ CLASSID Stopped by REAPOFF}/Implemented Categories', '{00021493-0000-0000-C000-000000000046}', 'Launch Point', 'Launch Point'),
            ( 'Software/Classes/ CLASSID Stopped by REAPOFF/{ CLASSID Stopped by REAPOFF}/Implemented Categories/{00021494-0000-0000-C000-000000000046}', ' 	All (1)', 'Launch Point', 'Launch Point'),
            ( 'Software/Classes/.bat/shell/open', 'command', 'Launch Point', 'Launch Point All'),
            ( 'Software/Classes/.cmd/shell/open', 'command', 'Launch Point', 'Launch Point NT4+'),
            ( 'Software/Classes/.com/shell/open', 'command', 'Launch Point', 'Launch Point All'),
            ( 'Software/Classes/.exe/shell/open', 'command', 'Launch Point', 'Launch Point All'),
            ( 'Software/Classes/.hta/shell/open', 'command', 'Launch Point', 'Launch Point All'),
            ( 'Software/Classes/.pif/shell/open', 'command', 'Launch Point', 'Launch Point All'),
            ( 'Software/Classes/.scr/shell/open', 'command', 'Launch Point', 'Launch Point'),
            ( 'Software/Classes/batfile/shell/open', 'command', 'Launch Point', 'Launch Point All'),
            ( 'Software/Classes/cmdfile/shell/open', 'command', 'Launch Point', 'Launch Point NT4+'),
            ( 'Software/Classes/comfile/shell/open', 'command', 'Launch Point', 'Launch Point All'),
            ( 'Software/Classes/exefile/shell/open', 'command', 'Launch Point', 'Launch Point All'),
            ( 'Software/Classes/htafile/shell/open', 'command', 'Launch Point', 'Launch Point All'),
            ( 'Software/Classes/piffile/shell/open', 'command', 'Launch Point', 'Launch Point All'),
            ( 'Software/Classes/scrfile/shell/open', 'command', 'Launch Point', 'Launch Point All'),
            ( 'Software/Classes/*/shellex', 'ContextMenuHandlers', 'Launch Point', 'Launch Point'),
            ( 'Software/Classes/Directory/shellex', 'ContextMenuHandlers', 'Launch Point', 'Launch Point'),
            ( 'Software/Classes/Folder/shellex', 'ContextMenuHandlers', 'Launch Point', 'Launch Point All'),
            ( 'Software/Classes/Protocols', 'Filter', 'Launch Point', 'Launch Point All'),
            ( 'Software/Microsoft/Active Setup', 'Installed Components', 'Launch Point', 'Launch Point All'),
            ( 'Software/Microsoft/Command Processor', 'AutoRun', 'Launch Point', 'Launch Point NT4+'),
            ( 'Software/Microsoft/Internet Explorer', 'Explorer Bars', 'Launch Point', 'Launch Point  All'),
            ( 'Software/Microsoft/Internet Explorer', 'Extensions', 'Launch Point', 'Launch Point All'),
            ( 'Software/Microsoft/Internet Explorer', 'Toolbar', 'Launch Point', 'Launch Point All'),
            ( 'Software/Microsoft/Windows/CurrentVersion/Explorer', 'Browser Helper Objects', 'Launch Point', 'Launch Point All'),
            ( 'Software/Microsoft/Windows/CurrentVersion/Explorer', 'SharedTaskScheduler', 'Launch Point', 'Launch Point All'),
            ( 'Software/Microsoft/Windows/CurrentVersion/Explorer', 'ShellExecuteHooks', 'Launch Point', 'Launch Point All'),
            ( 'Software/Microsoft/Windows/CurrentVersion/Policies/Explorer', 'Run', 'Launch Point', 'Launch Point W2K/WXP'),
            ( 'Software/Microsoft/Windows/CurrentVersion', 'Run', 'Launch Point', 'Launch Point All'),
            ( 'Software/Microsoft/Windows/CurrentVersion', 'RunOnce', 'Launch Point', 'Launch Point All'),
            ( 'Software/Microsoft/Windows/CurrentVersion/RunOnce', 'Setup', 'Launch Point', 'Launch Point All'),
            ( 'Software/Microsoft/Windows/CurrentVersion', 'RunOnceEx', 'Launch Point', 'Launch Point All'),
            ( 'Software/Microsoft/Windows/CurrentVersion', 'RunServices', 'Launch Point', 'Launch Point W9x'),
            ( 'Software/Microsoft/Windows/CurrentVersion', 'RunServicesOnce', 'Launch Point', 'Launch Point W9x'),
            ( 'Software/Microsoft/Windows/CurrentVersion/Shell Extensions', 'Approved', 'Launch Point', 'Launch Point All'),
            ( 'Software/Microsoft/Windows/CurrentVersion', 'ShellServiceObjectDelayLoad', 'Launch Point', 'Launch Point All'),
            ( 'Software/Microsoft/Windows NT/CurrentVersion', 'Image File Execution Options', 'Launch Point', 'Launch Point NT4+'),
 ( 'Software/Microsoft/Windows NT/CurrentVersion/Windows', 'AppInit_DLLs', 'Launch Point', 'Launch Point NT4+'),
            ( 'Software/Microsoft/Windows NT/CurrentVersion/Winlogon', 'GinaDLL', 'Launch Point', 'Launch Point'),
            ( 'Software/Microsoft/Windows NT/CurrentVersion/Winlogon', 'Shell', 'Launch Point', 'Launch Point'),
            ( 'Software/Microsoft/Windows NT/CurrentVersion/Winlogon', 'System', 'Launch Point', 'Launch Point'),
            ( 'Software/Microsoft/Windows NT/CurrentVersion/Winlogon', 'Taskman', 'Launch Point', 'Launch Point'),
            ( 'Software/Microsoft/Windows NT/CurrentVersion/Winlogon', 'Userinit', 'Launch Point', 'Launch PointNT4+'),
            ( 'Software/Microsoft/Windows NT/CurrentVersion/Winlogon', 'Notify', 'Launch Point', 'Launch PointW2K/WXP'),
            ( 'Software/Policies/Microsoft/Windows/System', 'Scripts', 'Launch Point', 'Launch PointW2K/WXP'),
            ( 'System/CurrentControlSet/Control/Class/{4D36E96B-E325-11CE-BFC1-08002BE10318}', 'UpperFilters', 'Launch Point', 'Launch Point W2K/WXP'),
            ( 'System/CurrentControlSet/Control/Session Manager', 'BootExecute', 'Launch Point', 'Launch Point NT4+'),
            ( 'System/CurrentControlSet', 'Services', 'Launch Point', 'Launch Point NT4+'),
 ( 'System/CurrentControlSet/Services/Winsock2/Parameters/NameSpace_Catalog5', 'Catalog_Entries', 'Launch Point', 'Launch Point'),
            ( 'System/CurrentControlSet/Services/Winsock2/Parameters/Protocol_Catalog9', 'Catalog_Entries', 'Launch Point', 'Launch Point All'),
            ( 'Software/Microsoft/Internet Explorer/Desktop', 'Components', 'Hijack Points', 'Hijack Points All'),
            ( 'Software/Microsoft/Internet Explorer', 'Main', 'Hijack Points', 'Hijack Points All (4)'),
            ( 'Software/Microsoft/Internet Explorer', 'SearchURL', 'Hijack Points', 'Hijack Points All (4)'),
            ( 'Software/Microsoft/Internet Explorer', 'URLSearchHooks', 'Hijack Points', 'Hijack Points All'),
            ( 'Software/Microsoft/Windows/CurrentVersion/Explorer', 'ShellState', 'Hijack Points', 'Hijack Points All'),
            ( 'Software/Microsoft/Windows/CurrentVersion/Policies', 'ActiveDesktop', 'Hijack Points', 'Hijack Points'),
            ( 'Software/Microsoft/Windows/CurrentVersion/Policies', 'Explorer', 'Hijack Points', 'Hijack Points'),
            ( 'Software/Microsoft/Windows/CurrentVersion/Policies', 'System', 'Hijack Points', 'Hijack Points'),
            ( 'Software/Microsoft/Windows/CurrentVersion/Policies', 'WindowsUpdate', 'Hijack Points', 'Hijack PointsAll'),
            ( 'Software/Policies/Microsoft/Internet Explorer', 'Control Panel', 'Hijack Points', 'Hijack Points'),
            ( 'Software/Policies/Microsoft/Internet Explorer', 'Restrictions', 'Hijack Points', 'Hijack Points All'),
            ( 'Software/Microsoft/Internet Explorer', 'Main', 'Hijack Points', 'Hijack Points All (4)'),
            ( 'Software/Microsoft/Internet Explorer', 'Search', 'Hijack Points', 'Hijack Points All (4)'),
            ( 'Software/Microsoft/Internet Explorer', 'AboutURLs', 'Hijack Points', 'Hijack Points All'),
            ( 'Software/Microsoft/Windows/CurrentVersion/URL', 'DefaultPrefix', 'Hijack Points', 'Hijack Points All'),
            ( 'Software/Microsoft/Windows/CurrentVersion/URL', 'Prefixes', 'Hijack Points', 'Hijack Points All'),
            ( 'Software/Policies/Microsoft/Windows NT', 'SystemRestore', 'Hijack Points', 'Hijack Points WXP'),
            ( 'System/CurrentControlSet/Services/Tcpip/Parameters', 'DataBasePath', 'Hijack Points', 'Hijack Points NT4+'),
            ( 'Software/Microsoft/Windows/CurrentVersion/Policies/Explorer', 'Run', 'Auto Start', 'Lists programs to be run when system starts.'),
            ( 'Software/Microsoft/Windows/CurrentVersion/Policies/Explorer', 'Run', 'Auto Start', 'Auto Start'),
            ( 'Software/Microsoft/Windows/CurrentVersion/Explorer', 'Browser Helper Objects', 'Auto Start', 'Browser Helper Objects (BHOs) are in-process COM components loaded each time Internet Explorer starts up.  These components run in the same memory context as the browser.  with Active Desktop Windows Explorer will also support BHOs.'),
            ( 'Software/Microsoft/Windows/CurrentVersion/Explorer', 'SharedTaskScheduler', 'Auto Start', 'Entries in this key are automatically loaded by Explorer.exe when Windows starts.'),
            ( 'Software/Classes/exefile/shell/open', 'command', 'Auto Start', 'The Default setting for these entries is ''%1 %*''.  Some malware will add entries to have other things run.  Also may need to examine other file types under the Classes key as well (ie any file classes that point to an app with a .exe extension).  These entires map to HKCR\\{ext}file\\shell\\open\\command.  Other entries under the HKLM\\Software\\Classes (and HKCR) key are succeptible to this same sort of subversion.  For example navigate via RegEdit to the HKCR\\Drive\\shell\\cmd\\command key right-click on the Default value and choose Modify.  In the textfield add && notepad.exe and click OK.  Open My Computer select a drive right-click and choose Open Command Prompt here......both cmd.exe and notepad.exe will run.'),
            ( 'Software/Microsoft/Command Processor', 'AutoRun', 'Auto Start', 'Commands listed here are executed before all other options listed at the command line; disabled by /d switch; REG_SZ data type.'),
            ( 'Software/Microsoft/Command Processor', 'AutoRun', 'Auto Start', 'Commands listed here are executed before all other options listed at the command line; disabled by /d switch; REG_SZ data type.'),
            ( 'Control Panel/Desktop', 'SCRNSAVE.EXE', 'Auto Start', 'Designates the user''s screen saver which is launched based on parameters set through the Control Panel.'),
            ( 'Software/Microsoft/Windows/CurrentVersion/ShellServiceObjectDelayLoad', '', 'Auto Start', 'Points to the InProcServer for a CLSID; The values found in this key can be mapped to HKLM\\Software\\Classes\\CLSID\\{GUID}\\InProcServer; Items listed here are loaded by Explorer when Windows starts; Used by malware'),
            ( 'Software/Microsoft/Windows/CurrentVersion', 'ShellServiceObjectDelayLoad', 'Auto Start', 'Auto Start'),
            ( 'Software/Microsoft/Windows NT/CurrentVersion/Windows', 'load', 'Auto Start', 'Replaces the use of the load= line in Win.ini'),
            ( 'Software/Microsoft/Windows NT/CurrentVersion/Windows', 'run', 'Auto Start', 'Replaces the use of the run= line in Win.ini'),
            ( 'Software/Policies/Microsoft/Windows/System', 'Scripts', 'Auto Start', 'Points to scripts for various events (ie logon logoff shutdown etc.), Usually handled via GPOs but can also be configured via local security policies'),
            ( 'Software/Policies/Microsoft/Windows/System', 'Scripts', 'Auto Start', 'Auto Start'),
            ( 'Software/Microsoft/Windows/CurrentVersion/Policies/System', 'Shell', 'Auto Start', 'Can specify an alternate user shell'),
            ( 'Software/Microsoft/Windows/CurrentVersion/Shell Extensions', 'Approved', 'Auto Start', 'Contains a list of approved shell extensions.'),
            ( 'Software/Microsoft/Windows NT/CurrentVersion/Windows', 'AppInit_DLLs', 'Auto Start', 'DLLs specified within this key are loaded whenever a Windows-based (GUI) application is launched.'),
            ( 'Software/Microsoft/Windows NT/CurrentVersion/Winlogon', 'GinaDLL', 'Auto Start', 'This entry can be subverted to load an alternate GINA capable of capturing the user''s login information in plain text (ie FakeGINA.DLL from NTSecurity.nu).  This is loaded and used by WinLogon.exe.'),
            ( 'Software/Microsoft/Windows NT/CurrentVersion/Winlogon', 'Shell', 'Auto Start', 'Indicates executable files launched by Userinit.exe and expected at user shell startup. '),
            ( 'Software/Microsoft/Windows NT/CurrentVersion/Winlogon', 'Shell', 'Auto Start', 'Auto Start'),
            ( 'Software/Microsoft/Windows NT/CurrentVersion/Winlogon', 'System', 'Auto Start', 'Indicates programs to be executed in System mode.'),
            ( 'Software/Microsoft/Windows NT/CurrentVersion/Winlogon', 'TaskMan', 'Auto Start', 'Specifies the Task Manager to be used by Windows.  The default is TaskMan.exe but the SysInternals.com tool Process Explorer can replace this value.'),
            ( 'Software/Microsoft/Windows NT/CurrentVersion/Winlogon', 'UserInit', 'Auto Start', 'Lists programs to be automatically run when the user logs in.  Userinit.exe is responsible for shell execution.  Nddeagnt.exe is responsible for NetDDE.  Multiple programs may be listed.'),
            ( 'Software/Microsoft/Windows NT/CurrentVersion/Winlogon', 'Notify', 'Auto Start', 'Specifies programs to be run when certain system events (ie logon logoff startup shutdown startscreensaver stopscreensaver) occur.  The event is generated by Winlogon.exe at which point the system will look for a DLL within this key to handle the event.'),
            ( 'System/CurrentControlSet/Control/Session Manager', 'BootExecute', 'Auto Start', 'Specifies the applications services and commands executed during startup.'),
            ( 'System/CurrentControlSet', 'Services', 'Auto Start', 'Subkeys list services to be executed most of which are run as LocalSystem.  The Hacker Defender rootkit installs as a service.'),
            ( 'Software/Microsoft/Active Setup', 'Installed Components', 'Auto Start', 'Auto Start'),
            ( 'Software/Microsoft/Windows/CurrentVersion/Explorer/Shell Folders', 'Common Startup', 'Auto Start', 'Designates location of Startup folders; ie Autostart directory'),
            ( 'Software/Microsoft/Windows/CurrentVersion/Explorer/Shell Folders', 'Startup', 'Auto Start', 'Auto Start'),
            ( 'Software/Microsoft/Windows/CurrentVersion/explorer/User Shell Folders', 'Common Startup', 'Auto Start', 'Auto Start'),
            ( 'Software/Microsoft/Windows/CurrentVersion/Explorer/User Shell Folders', 'Startup', 'Auto Start', 'Auto Start'),
            ( 'Software/Microsoft/Windows/CurrentVersion', 'App Paths', 'Auto Start', 'Each subkey contains the path to the specific application; paths and the actual executables should be verified as legitimate apps may be set in other autostart locations and the linked-to application subverted or trojaned.'),
            ( 'SOFTWARE/Microsoft/Windows NT/CurrentVersion', 'Image File Execution Options', 'Auto Start', 'This Registry location is used to designate a debugger for an application.  Testing shows that it''s an excellent redirection facility.  For example adding notepad.exe as a key and then adding a Debugger value of cmd.exe will cause the command prompt to be opened whenever Notepad is launched.  File binding utilities will allow an attacker to bind a backdoor to a legitimate program and then redirect that legit program to the Trojaned one.'),
            ( 'SOFTWARE/Microsoft/Windows/CurrentVersion/Policies/Explorer', 'NoDriveAutoRun', 'Misc', 'Misc'),
            ( 'SOFTWARE/Microsoft/Windows/CurrentVersion/Policies/Explorer', 'NoDriveAutoRun', 'Misc', 'Misc'),
            ( 'SYSTEM/CurrentControlSet/Control/FileSystem', 'NtfsDisableLastAccessUpdate', 'Misc', 'Misc'),
            ( 'System/CurrentControlSet/Control/Session Manager', 'KnownDLLs', 'Misc', 'Misc'),
            ( 'Software/Microsoft/Windows NT/CurrentVersion/Winlogon', 'ParseAuotExec', 'Misc', 'Misc'),
            ]

        for path, reg_key, category, description in keys:
            dbh.insert("registrykeys",
                       path=path, reg_key=reg_key,
                       category=category, description=description,
                       _fast=True)

import pyflag.tests
import pyflag.pyflagsh as pyflagsh

class RegScanTest(pyflag.tests.ScannerTest):
    """ Test Registry scanner """
    test_case = "PyFlagTestCase"
    test_file = "pyflag_stdimage_0.4.e01"
    subsystem = 'EWF'
    offset = "16128s"

    def test01RunScanner(self):
        """ Test Reg scanner """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env, command="scan",
                             argv=["*",'RegistryScan'])

