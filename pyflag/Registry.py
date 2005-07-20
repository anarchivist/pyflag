# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.76 Date: Sun Apr 17 21:48:37 EST 2005$
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
import pyflag.logging as logging

class Registry:
    """ Main class to register classes derived from a given parent class. """
    modules = []
    module_desc = []
    module_paths = []
    classes = []
    class_names = []
    order = []
    
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
                            if path not in self.module_paths:
                                logging.log(logging.DEBUG,"Will attempt to load plugin '%s/%s'"
                                            % (dirpath,filename))
                                ## If we do not have the module in the cache, we load it now
                                try:
                                    #open the plugin file
                                    fd = open(path ,"r")
                                except Exception,e:
                                    logging.log(logging.DEBUG, "Unable to open plugin file '%s': %s"
                                                % (filename,e))
                                    continue

                                #load the module into our namespace
                                try:
                                    module = imp.load_source(module_name,dirpath+'/'+filename,fd)
                                except Exception,e:
                                    logging.log(logging.ERRORS, "*** Unable to load module %s: %s"
                                                % (module_name,e))
                                    continue

                                fd.close()

                                #Is this module active?
                                try:
                                    if module.hidden:
                                        logging.log(logging.DEBUG, "*** Will not load Module %s: Module Hidden"% (module_name))
                                        continue
                                except AttributeError:
                                    pass
                                
                                try:
                                    if not module.active:
                                        logging.log(logging.WARNINGS, "*** Will not load Module %s: Module not active" % (module_name))
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
                                ## We already have the module in the cache:
                                module = self.modules[self.module_paths.index(path)]
                                module_desc = self.module_desc[self.module_paths.index(path)]

                            #Now we enumerate all the classes in the
                            #module to see which one is a ParentClass:
                            for cls in dir(module):
                                try:
                                    Class = module.__dict__[cls]
                                    if issubclass(Class,ParentClass) and Class!=ParentClass:
                                        ## Check the class for consitency
                                        try:
                                            self.check_class(Class)
                                        except AttributeError,e:
                                            err = "Failed to load %s '%s': %s" % (ParentClass,cls,e)
                                            logging.log(logging.WARNINGS, err)
                                            continue

                                        self.classes.append(Class)
                                        logging.log(logging.DEBUG, "Added %s '%s:%s'"
                                                    % (ParentClass,module_desc,cls))

                                        try:
                                            self.order.append(Class.order)
                                        except:
                                            self.order.append(10)
                                            
                                # Oops: it isnt a class...
                                except (TypeError, NameError) , e:
                                    continue

                        except TypeError, e:
                            logging.log(logging.ERRORS, "Could not compile module %s: %s"
                                        % (module_name,e))
                            continue

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
            raise Exception("Can not find report %s/%s" % (family,report))
        
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
            a=x.order
            b=y.order
            if a<b:
                return -1
            elif a==b: return 0
            return 1

        self.classes.sort(sort_function)
        self.scanners = [ ("%s" % i).split(".")[-1] for i in self.classes ]

    def dispatch(self,scanner_name):
        return self.classes[self.scanners.index(scanner_name)]

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

class FileSystemRegistry(Registry):
    """ A class to register FileSystems.

    FileSystems control the internal representation of the filesystem structure, the loading of this from an image and the browsing of the filesystem. Note that this is different than VFS which deal with how to read individual files from the FileSystem, but both are confined to use the same DBFS schema at present.
    """
    filesystems = {}
    fs = {}
    def __init__(self,ParentClass):
        Registry.__init__(self,ParentClass)
        for cls in self.classes:
            if self.filesystems.has_key(cls.name):
                raise Exception("Class %s has the same specifier as %s. (%s)" % (cls,self.filesystems[cls.name],cls.name))
            ## A name of None will prevent from loading into Registry
            if cls.name:
                self.filesystems[cls.name] = cls
            self.fs[("%s" % cls).split(".")[-1]]=cls

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

class LogDriverRegistry(Registry):
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
    
LOCK = 0
REPORTS = None
SCANNERS = None
VFS_FILES = None
LOG_DRIVERS = None
SHELL_COMMANDS = None
FILESYSTEMS = None
THEMES = None

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
    LOG_DRIVERS = LogDriverRegistry(LogFile.Log)
    
    ## Register all shell commands:
    import pyflag.pyflagsh as pyflagsh
    global SHELL_COMMANDS
    SHELL_COMMANDS = ShellRegistry(pyflagsh.command)

    ## Register Filesystem drivers
    import pyflag.FileSystem as FileSystem
    global FILESYSTEMS
    FILESYSTEMS = FileSystemRegistry(FileSystem.FileSystem)


def import_module(name,load_as=None):
    Init()
    REPORTS.import_module(name,load_as)
