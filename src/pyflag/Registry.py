#!/usr/bin/env python
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
# *****************************************************
""" This module implements a class registry.

We scan the plugins directory for all python files and add those
classes which should be registered into their own lookup tables. These
are then ordered as required. The rest of Flag will then call onto the
registered classes when needed.

This mechanism allows us to reorgenise the code according to
functionality. For example we may include a Scanner, Report and File
classes in the same plugin and have them all automatically loaded.
"""
import pyflag.conf
config=pyflag.conf.ConfObject()

import os,sys,imp
import pyflag.pyflaglog as pyflaglog

## Define the parameters we need. The default plugins directory is
## taken from the path of the current module because the installer
## will put the plugins directory within this directory.
config.add_option("PLUGINS", default=os.path.dirname(__file__) + "/plugins",
                  help="Plugin directories to use")

class Registry:
    """ Main class to register classes derived from a given parent class. """
    modules = []
    module_desc = []
    module_paths = []
    classes = []
    class_names = []
    order = []
    filenames = {}
    ## These are the modules which have been disabled
    loaded_modules = []
    
    def __init__(self,ParentClass):
        """ Search the plugins directory for all classes extending ParentClass.
        
        These will be considered as implementations and added to our internal registry.
        """
        ## Create instance variables
        self.classes = []
        self.class_names = []
        self.order = []
        
        ## Recurse over all the plugin directories recursively
        for path in config.PLUGINS.split(':'):
            for dirpath, dirnames, filenames in os.walk(path):
                sys.path.append(dirpath)
                
                for filename in filenames:
                    #Lose the extension for the module name
                    module_name = filename[:-3]
                    if filename.endswith(".py"):
                        path = dirpath+'/'+filename
                        try:
                            if path not in self.loaded_modules:
                                self.loaded_modules.append(path)
                                
                                pyflaglog.log(pyflaglog.VERBOSE_DEBUG,"Will attempt to load plugin '%s/%s'"
                                            % (dirpath,filename))
                                try:
                                    #open the plugin file
                                    fd = open(path ,"r")
                                except Exception,e:
                                    pyflaglog.log(pyflaglog.DEBUG, "Unable to open plugin file '%s': %s"
                                                % (filename,e))
                                    continue

                                #load the module into our namespace
                                try:
                                    module = imp.load_source(module_name,dirpath+'/'+filename,fd)
                                except Exception,e:
                                    pyflaglog.log(pyflaglog.ERRORS, "*** Unable to load module %s: %s"
                                                % (module_name,e))
                                    continue

                                fd.close()

                                #Is this module active?
                                try:
                                    if module.hidden:
                                        pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "*** Will not load Module %s: Module Hidden"% (module_name))
                                        continue
                                except AttributeError:
                                    pass
                                
                                try:
                                    if not module.active:
                                        pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "*** Will not load Module %s: Module not active" % (module_name))
                                        continue
                                except AttributeError:
                                    pass
                                
                                #find the module description
                                try:
                                    module_desc = module.description
                                except AttributeError:
                                    module_desc = module_name

                                ## Store information about this module here.
                                self.modules.append(module)
                                self.module_desc.append(module_desc)
                                self.module_paths.append(path)
                                
                            else:
                                try:
                                    ## We already have the module in the cache:
                                    module = self.modules[self.module_paths.index(path)]
                                    module_desc = self.module_desc[self.module_paths.index(path)]
                                except (ValueError, IndexError),e:
                                    ## If not the module has been loaded, but disabled
                                    continue

                            #Now we enumerate all the classes in the
                            #module to see which one is a ParentClass:
                            for cls in dir(module):
                                try:
                                    Class = module.__dict__[cls]
                                    if issubclass(Class,ParentClass) and Class!=ParentClass:
                                        ## Check the class for consitancy
                                        try:
                                            self.check_class(Class)
                                        except AttributeError,e:
                                            err = "Failed to load %s '%s': %s" % (ParentClass,cls,e)
                                            pyflaglog.log(pyflaglog.WARNINGS, err)
                                            continue

                                        ## Add the class to ourselves:
                                        self.add_class(ParentClass, module_desc, cls, Class, filename)
                                            
                                # Oops: it isnt a class...
                                except (TypeError, NameError) , e:
                                    continue

                        except TypeError, e:
                            pyflaglog.log(pyflaglog.ERRORS, "Could not compile module %s: %s"
                                        % (module_name,e))
                            continue

    def add_class(self, ParentClass, module_desc, cls, Class, filename):
        """ Adds the class provided to our self. This is here to be
        possibly over ridden by derived classes.
        """
        if Class not in self.classes:
            self.classes.append(Class)
            self.filenames[self.get_name(Class)] = filename
            try:
                self.order.append(Class.order)
            except:
                self.order.append(10)

            pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "Added %s '%s:%s'"
                          % (ParentClass,module_desc,cls))

    def check_class(self,Class):
        """ Run a set of tests on the class to ensure its ok to use.

        If there is any problem, we chuck an exception.
        """

    def import_module(self,name=None,load_as=None):
        """ Loads the named module into the system module name space.
        After calling this it is possible to do:

        import load_as

        in all other modules. Note that to avoid race conditions its best to only attempt to use the module after the registry is initialised (i.e. at run time not load time).

        @arg load_as: name to use in the systems namespace.
        @arg name: module name to import
        @note: If there are several modules of the same name (which should be avoided)  the last one encountered during registring should persist. This may lead to indereminate behaviour.
        """
        if not load_as: load_as=name
        
        for module in self.modules:
            if name==module.__name__:
                sys.modules[load_as] = module
                return

        raise ImportError("No module by name %s" % name)

    def get_name(self, cls):
        try:
            return cls.name
        except AttributeError:
            return ("%s" % cls).split(".")[-1]

    def filename(self, cls_name):
        return self.filenames.get(cls_name, "Unknown")

class ReportRegistry(Registry):
    """ A class to register reports.

    We have the extra task of resolving reports into families (Or
    report groups). This is done by examining the family property of
    the report.
    """
    family = {}
    
    def __init__(self,ParentClass):
        Registry.__init__(self,ParentClass)
        for cls in self.classes:
            try:
                self.family[cls.family].append(cls)
            except KeyError:
                self.family[cls.family]=[cls]

        ## Sort all reports in all families:
        def sort_function(x,y):
            a=x.order
            b=y.order
            if a<b:
                return -1
            elif a==b: return 0
            return 1
        
        for family in self.family.keys():
            self.family[family].sort(sort_function)

    def get_families(self):
        """ Returns a list of families we have detected """
        return self.family.keys()

    def dispatch(self,family,report):
        """ Returns the report object referenced by family and report

        For backward compatibility we allow report to be the classes name or the report.name attatibute.
        """
        ## Find the requested report in the registry:
        f = self.family[family]
        result= [ i for i in f if i.name==report]
        if not result:
            result= [ i for i in f if report == ("%s" % i).split('.')[-1]]

        if not result:
            raise ValueError("Can not find report %s/%s" % (family,report))
        
        return result[0]
    
    def check_class(self,Class):
        ## If the report is missing any of those an exception will be raised...
        Class.display
        Class.analyse
        Class.progress
        Class.form
        Class.name
        Class.parameters

class ScannerRegistry(Registry):
    """ A class to register Scanners. """
    def __init__(self,ParentClass):
        Registry.__init__(self,ParentClass)
        ## Sort all reports in all families:
        def sort_function(x,y):
            try:
                a=x.order
            except: a=10

            try:
                b=y.order
            except: b=10
            
            if a<b:
                return -1
            elif a==b: return 0
            return 1

        self.classes.sort(sort_function)
        self.class_names = [ self.get_name(i) for i in self.classes ]
        self.scanners = self.class_names

    def dispatch(self,scanner_name):
        if scanner_name in self.class_names:
            return self.classes[self.class_names.index(scanner_name)]
        else:
            raise ValueError("Object %s does not exist in the registry. Is the relevant plugin loaded?" % scanner_name)

class FileHandlerRegistry(ScannerRegistry):
    def __init__(self, ParentClass):
        Registry.__init__(self, ParentClass)
        self.class_names = [ i.method for i in self.classes ]

class VFSFileRegistry(Registry):
    """ A class to register VFS (Virtual File System) File classes """
    vfslist = {}
    def __init__(self,ParentClass):
        Registry.__init__(self,ParentClass)
        for cls in self.classes:
            ## We ignore VFS drivers without specifiers
            if not cls.specifier: continue
            
            if self.vfslist.has_key(cls.specifier):
                raise Exception("Class %s has the same specifier as %s. (%s)" % (cls,self.vfslist[cls.specifier],cls.specifier))
            self.vfslist[cls.specifier] = cls

class ShellRegistry(Registry):
    """ A class to manage Flash shell commands """
    commands = {}
    def __getitem__(self,command_name):
        """ Return the command objects by name """
        return self.commands[command_name]
    
    def __init__(self,ParentClass):
        Registry.__init__(self,ParentClass)
        for cls in self.classes:
            ## The name of the class is the command name
            command = ("%s" % cls).split('.')[-1]
            try:
                raise Exception("Command %s has already been defined by %s" % (command,self.commands[command]))
            except KeyError:
                self.commands[command]=cls

class LogDriverRegistry(ScannerRegistry):
    """ A class taking care of Log file drivers """
    drivers = {}
    def __init__(self,ParentClass):
        Registry.__init__(self,ParentClass)
        for cls in self.classes:
            self.drivers[cls.name]=cls

class ThemeRegistry(Registry):
    """ A class registering all the themes """
    themes = {}
    def __init__(self,ParentClass):
        Registry.__init__(self,ParentClass)
        for cls in self.classes:
            self.themes[("%s" % cls).split('.')[-1]]=cls

class FileFormatRegistry(Registry):
    """ A class for registering all file formats """
    formats = {}

    def __getitem__(self,format_name):
        """ Return the command objects by name """
        return self.formats[format_name]

    def __init__(self,ParentClass):
        Registry.__init__(self,ParentClass)   
        for cls in self.classes:
            ## The name of the class is the command name
            self.formats[("%s" % cls).split('.')[-1]] = cls

import unittest
class TestsRegistry(ScannerRegistry):
    pass

class ColumnTypeRegistry(ScannerRegistry):
    pass

class TaskRegistry(ScannerRegistry):
    pass

class CarverRegistry(ScannerRegistry):
    pass

## These are some base classes which will be used by plugins to be
## registered:
class Action: pass

LOCK = 0
REPORTS = None
SCANNERS = None
VFS_FILES = None
LOG_DRIVERS = None
SHELL_COMMANDS = None
FILESYSTEMS = None
THEMES = None
FILEFORMATS = None
TASKS = None
CARVERS = None
EVENT_HANDLERS = None
IMAGES = None
FILE_HANDLERS = None
STATS_HANDLERS = None
CASE_TABLES = None
TABLE_RENDERERS = None
ACTIONS = None

## This is required for late initialisation to avoid dependency nightmare.
def Init():
    ## We may only register things once. LOCK will ensure that we only initialise once
    global LOCK
    if LOCK:
        return
    LOCK=1
    ## Do the reports here
    import pyflag.Reports as Reports
    global REPORTS
    
    REPORTS=ReportRegistry(Reports.report)

    ## Collect all themes
    import pyflag.Theme as Theme
    global THEMES
    THEMES = ThemeRegistry(Theme.BasicTheme)

    ## Now do the scanners
    import pyflag.Scanner as Scanner
    global SCANNERS
    SCANNERS = ScannerRegistry(Scanner.GenScanFactory)

    ## Pick up all VFS drivers:
    import pyflag.FileSystem as FileSystem
    global VFS_FILES
    VFS_FILES = VFSFileRegistry(FileSystem.File)
    
    ## Pick all Log File drivers:
    import pyflag.LogFile as LogFile
    global LOG_DRIVERS
    LOG_DRIVERS = ScannerRegistry(LogFile.Log)
    
    ## Register all shell commands:
    import pyflag.pyflagsh as pyflagsh
    global SHELL_COMMANDS
    SHELL_COMMANDS = ShellRegistry(pyflagsh.command)

    ## Register Filesystem drivers
    import pyflag.FileSystem as FileSystem
    global FILESYSTEMS
    FILESYSTEMS = ScannerRegistry(FileSystem.DBFS)

    ## Register FileFormat drivers
    import pyflag.format as format
    global FILEFORMATS
    FILEFORMATS = FileFormatRegistry(format.DataType)

    ## Register Column Types:
    import pyflag.ColumnTypes as ColumnTypes
    global COLUMN_TYPES
    COLUMN_TYPES = ColumnTypeRegistry(ColumnTypes.ColumnType)

    ## Register worker tasks
    import pyflag.Farm as Farm
    global TASKS
    TASKS = ScannerRegistry(Farm.Task)

    ## Register carvers:
    global CARVERS
    CARVERS = ScannerRegistry(Scanner.Carver)

    ## Register SQL handlers
    import pyflag.FlagFramework as FlagFramework
    global EVENT_HANDLERS
    EVENT_HANDLERS = ScannerRegistry(FlagFramework.EventHandler)

    ## Register IO Images:
    import pyflag.IO as IO
    global IMAGES
    IMAGES = ScannerRegistry(IO.Image)

    global FILE_HANDLERS
    FILE_HANDLERS = FileHandlerRegistry(IO.FileHandler)

    ## Register packet handlers:
    import pyflag.Packets as Packets
    global PACKET_HANDLERS
    PACKET_HANDLERS = ScannerRegistry(Packets.PacketHandler)

    ## Register stats viewers:
    import pyflag.Stats as Stats
    global STATS_HANDLERS
    STATS_HANDLERS = ScannerRegistry(Stats.Handler)

    ## Register Case Tables for dynamic schema
    global CASE_TABLES
    CASE_TABLES = ScannerRegistry(FlagFramework.CaseTable)

    global MAGIC_HANDLERS
    import pyflag.Magic as Magic

    MAGIC_HANDLERS = ScannerRegistry(Magic.Magic)

    global TABLE_RENDERERS
    import pyflag.UI as UI

    TABLE_RENDERERS = ScannerRegistry(UI.TableRendererBaseClass)

    global ACTIONS
    ACTIONS = ScannerRegistry(Action)

def InitTests():
    return TestsRegistry(unittest.TestCase)

def import_module(name,load_as=None):
    Init()
    REPORTS.import_module(name,load_as)

