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
import pyflag.Reports as Reports
import pyflag.logging as logging

class Registry:
    """ Main class to register classes derived from a given parent class. """

    modules = []
    module_desc = []
    classes = []
    class_names = []
    order = []
    
    def __init__(self,ParentClass):
        """ Search the plugins directory for all classes extending ParentClass.
        
        These will be considered as implementations and added to our internal registry.
        """
        ## Recurse over all the plugin directories recursively
        for path in config.PLUGINS.split(':'):
            for dirpath, dirnames, filenames in os.walk(path):
                for filename in filenames:
                    #Lose the extension for the module name
                    module_name = filename[:-3]
                    if filename.endswith(".py"):
                        logging.log(logging.DEBUG,"Will attempt to load plugin '%s/%s'"
                                    % (dirpath,filename))
                        try:
                            try:
                                #open the plugin file
                                fd = open(dirpath+'/'+filename ,"r")
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

                            ## Do we already have this module?
                            if module_desc in self.modules:
                                logging.log(logging.WARNINGS, "Module %s is already loaded, skipping...." % module_desc)
                                continue
                            else:
                                self.modules.append(module)
                                self.module_desc.append(module_desc)

                            #Now we enumerate all the classes in the
                            #module to see which one is a ParentClass:
                            for cls in dir(module):
                                try:
                                    if issubclass(module.__dict__[cls],ParentClass):
                                        Class = module.__dict__[cls]

                                        ## Check the class for consitency
                                        try:
                                            self.check_class(Class)
                                        except AttributeError,e:
                                            err = "Failed to load %s '%s': %s" % (ParentClass,cls,e)
                                            logging.log(logging.WARNINGS, err)
                                            continue

                                        self.classes.append(Class)
                                        self.class_names.append(cls)
                                        try:
                                            self.order.append(Class.order)
                                        except:
                                            self.order.append(0)
                                            
                                        logging.log(logging.DEBUG, "Added %s '%s:%s'"
                                                    % (ParentClass,module_desc,cls))

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
        
    def check_class(self,Class):
        Class.display
        Class.analyse
        Class.progress
        Class.form
        Class.name
        Class.parameters

REPORTS = ReportRegistry(Reports.report)

print REPORTS.family
