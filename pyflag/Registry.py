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
                                    if module.hidden: continue
                                    if not module.active: continue
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
            if self.vfslist.has_key(cls.specifier):
                raise Exception("Class %s has the same specifier as %s. (%s)" % (cls,self.vfslist[cls.specifier],cls.specifier))
            self.vfslist[cls.specifier] = cls

class LogDriverRegistry(Registry):
    """ A class taking care of Log file drivers """
    drivers = {}
    def __init__(self,ParentClass):
        Registry.__init__(self,ParentClass)
        for cls in self.classes:
            self.drivers[cls.name]=cls

REPORTS = None
SCANNERS = None
VFS_FILES = None
LOG_DRIVERS = None

## This is required for late initialisation to avoid dependency nightmare.
def Init():
    ## Do the reports here
    import pyflag.Reports as Reports
    global REPORTS
    
    REPORTS=ReportRegistry(Reports.report)
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
