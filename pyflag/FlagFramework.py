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
#  Version: FLAG $Name:  $ $Date: 2004/10/14 12:41:01 $
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

""" Main flag framework modules contains many core classes

@var flag_version: Current version of the flag program
""" 
flag_version = "0.64"
import sys,os
import pyflag.conf
config=pyflag.conf.ConfObject()
import magic
import pyflag.logging as logging
import index

class FlagException(Exception):
    """ Generic Flag Exception """
    pass

class DispatchError(FlagException):
    """ Errors invoked from the Dispatcher. This is only used for fatal errors stopping the dispatcher """
    pass


class query_type:
    """ A generic wrapper for holding CGI parameters.

    This is almost like a dictionary, except that there are methods provided to give access to CGI arrays obtained by repeated use of the same key mutiple times.
    @note: This property necessitate the sometime unituitive way of resetting a paramter by initially deliting it. For example, to change the 'report' parameter in query you must do:
    
    >>> del query['report']
    >>> query['report'] = 'newvalue'

    since if the paramter is not deleted first, it will simply be appended to produce a report array.
    """
    def __init__(self,query_list,**params):
        """ Constructor initialises from a CGI list of (key,value) pairs or named keywords. These may repeat as needed """
        self.q=[]
        if isinstance(query_list,list):
            self.q = query_list
        elif isinstance(query_list,dict):
            for k,v in query_list.items():
                self.__setitem__(k,v)

        if params:
            for k,v in params.items():
                self.__setitem__(k,v)

        #All query strings should have a case to operate on:
        try:
            self.__getitem__('case')
        except KeyError:
            self.__setitem__('case',config.FLAGDB)

    def __str__(self):
        """ Prints the query object as a url string """
        mark=''
        if self.has_key('__mark__'):
            mark='#'+self.__getitem__('__mark__')
            self.__delitem__('__mark__')
            
        result = []
        for i in self.q:
            result.append("%s=%s" %(urlencode(i[0]),urlencode(i[1])))

        return 'f?'+'&'.join(result)+mark

    def __delitem__(self,item):
        """ Removes all instance of item from the CGI object """
        to_remove=[ d for d in self.q if d[0] == item ]
        for i in to_remove:
            try:
                while 1:
                    self.q.remove(i)
            except ValueError:
                pass

    def remove(self,key,value):
        """ Removes the specific instance of key,value from the query.
        @note: Normally you can just do del query['key'], but this will delete all keys,value pairs with the same keys. This is a more finer level method allowing to delete just a single element from the array.
        @except: This will raise a Value Error if the key,value pair do not exist in the query
        """
        index=self.q.index((key,value))
        del self.q[index]

    def keys(self,**options):
        """ Returns a list of all the keys in the query.

        @note: The default behaviour is to return only unique keys, however if the option multiple=True is given, all keys are provided
        """
        if options.has_key('multiple'):
            tmp =[ i[0] for i in self.q ]
        else:
            tmp=[]
            for i in self.q:
                if i[0] not in tmp:
                    tmp.append(i[0])

        return tmp

    def clone(self):
        """ Clones the current object into a new object. Faster than copy.deepcopy """
        tmp = self.__class__(())
        tmp.q = self.q[:]
        return tmp

    def getarray(self,key):
        """ Returns an array of all values of key.

        @arg key: CGI key to search for.
        @return: A list of all values (in no particular order). """
        tmp = []
        for i in self.q:
            if i[0] == key:
                tmp.append(i[1])

        return tuple(tmp)
    
    def has_key(self,key):
        for i in self.q:
            if i[0] == key:
                return True
            
        return False

    def __setitem__(self,i,x):
        ## case may only be specified once:
        if i=='case' and self.has_key('case'):
            self.__delitem__('case')
        
        self.q.append((i,x))
        
    def __getitem__(self,item):
        """ Implements the dictionary access method """
        for i in self.q:
            if i[0]== item:
                return i[1]

        raise KeyError, ("Key '%s' not found in CGI query" % item)

    def __iter__(self):
        self.iter_count = 0
        return self

    def next(self):
        """ This is used to implement an iterator over the query type. You can now do for x,y in a: """
        try:
            result = self.q[self.iter_count]
        except IndexError:
            raise StopIteration

        self.iter_count+=1
        return result

    def FillQueryTarget(self,dest):
        """ Given a target, this function returns a updates the query object with a filled in target

        @except KeyError: if the query is not formatted properly (i.e. no _target_ key)
        """
        for target in self.getarray('__target__'):
            try:
            ## Replace the target arg with the new one (note we cant just add one because that will append it to the end of a cgi array)
                tmp = str(self.__getitem__(target)) % dest
                self.__delitem__(target)
                self.__setitem__(target,tmp)
            
            ## No q[target]
            except (KeyError,TypeError):
                self.__delitem__(target)
                self.__setitem__(target,dest)

        try:
            ## If we were asked to mark this target, we do so here. (Note that __mark__ could still be set to a constant, in which case we ignore it, and its query_type.__str__ will fill it in)
            if self.__getitem__('__mark__')=='target':
                self.__delitem__('__mark__')
                self.__setitem__('__mark__',dest)
        except KeyError:
            pass
            
        self.__delitem__('__target__')

import pyflag.DB as DB
import threading
import re
import conf

def urlencode(string):
    """ Utility function used for encoding strings inside URLs.

    Replaces non-alphnumeric chars with their % representation """
    result = ''
    for c in str(string):
        if not c.isalnum():
            h = hex(ord(c))
            result +="%%%s" % h[2:]
        else:
            result += c

    return result

class Flag:
    """ Main Flag object.

    This object is responsible with maintaining configuration data, dispatching reports and processing queries.
    
    """
    dispatch = ''
    def __init__(self,ui=None):
        import pyflag.HTMLUI as UI

        if not ui:
            ui=UI.HTMLUI
        ## Figure out where the plugins are. We first take from the current dir
        plugins=["plugins"]
        try:
            ## If any dirs are specified in the conf file we take those
            plugins.append(config.PLUGINS)
        except AttributeError:
            pass

        ## Now try the system default. If pyflag was installed into the system
        try:
            import pyflag.plugins
            plugins.extend(sys.modules['pyflag.plugins'].__path__)
        except ImportError:
            pass
                
        self.dispatch = module_dispatcher(plugins,self,ui=ui)

    def canonicalise(self,query):
        """ Converts the query into the canonical form.

        The canonical form is defined as the sorted urlified key=value pairs of the parameters defined in the reports.parameters dict. This is used to uniquely identify the request in order to manage the caching."""
        if not query['report'] or not query['family']:
            raise FlagException,"No report or family in canonicalise query"

        report = self.dispatch.get(query['family'],query['report'])

        tmp = []
        for x,y in query:
            if report.parameters.has_key(x) or x=='family' or x=='report':
                tmp.append("%s=%s" %(urlencode(x),urlencode(y)))

        tmp.sort()
        return '&'.join(tmp)
    
    def is_cached(self,query):
        """ Checks the database to see if the report has been cached """
        dbh = DB.DBO(query['case'])
        dbh.execute("select * from meta where property=%r and value=%r",("report_executed",self.canonicalise(query)))
        if dbh.fetch():
            return True
        else:
            return False

    def run_analysis(self,report,query):
        canonical_query = self.canonicalise(query)
        #Find our thread name
        thread_name = threading.currentThread().getName()
        print "Current thread is %s" % thread_name
        import pyflag.Reports as Reports

        #note that we are executing this report (place a lock in the report object - only works because everyone is using the same instance of the report!!!)
        report.executing[thread_name]={'query': canonical_query, 'error': None}
        try:
            result = report.analyse(query)
        ## These are deliberate errors that reports raise with their own custom UI message:
        except Reports.ReportError,e:
            report.executing[thread_name]['error'] = e
            print report.executing, e.__str__()
            return
        except Exception,e:
            #If anything goes wrong in the analysis phase, we have to set the error in report.executing
            import sys
            import traceback
            import cStringIO

            a = cStringIO.StringIO()
            traceback.print_tb(sys.exc_info()[2], file=a)
            result = self.ui()
            a.seek(0)
            result.para("%s: %s" % (sys.exc_info()[0],sys.exc_info()[1]))
            result.pre(a.read())
            a.close()
            report.executing[thread_name]['error'] = result
            print report.executing, result.__str__()
            return

        #Lets remember the fact that we analysed this report - in the database
        dbh = DB.DBO(query['case'])
        dbh.execute("insert into meta set property=%r,value=%r",('report_executed',canonical_query))
        
        #Remove the lock
        del report.executing[thread_name]


    def check_progress(self,report,query):
        """ Checks the progress of a report. If the report is not running this method returns None. If the report is still running or has died due to an error, this method returns a UI object containing either the error message or a progress report called from the report's own progress method """
        canonical_query = self.canonicalise(query)
        if report.is_executing(canonical_query):
            #Did the analysis thread die with an error?
            thread_name = report.is_executing(canonical_query)
            #if an error exists, we get the error traceback produced by the analysis thread
            result = report.executing[thread_name]['error']
            #If the analysis thread set an error UI object we just return it else evaluate the progress
            if result:
                tmp = self.ui()
                tmp.heading("Error occured during analysis stage")
                tmp.join(result)
                result=tmp
                result.defaults = query
                del report.executing[thread_name]
                return result
            else:
                result = self.ui()
                result.defaults = query
                report.progress(query,result)
                #Refresh page
                result.refresh(config.REFRESH,query)
                return result
        #we are not executing
        else: return None

    ui = None    
    def process_request(self,query):
        """ Function responsible for processing the request presented by query, which is of query_type. Results returned are a UI object which may be used to display the results
        @arg query: A query_type object.
        @return: A UI object which must be displayed.
        """
        result = self.ui()
        result.defaults = query
        
        #Check to see if the report is valid:
        try:
            report = self.dispatch.get(query['family'],query['report'])
        except DispatchError,e:
            result.heading("Report Or family not recognized")
            result.para("It is possible that the appropriate module is not installed.")
            return result

        #Since flag must always operate on a case, if there is no case, we use the default flagdb as a case
        try:
            query['case']
        except KeyError:
            query['case'] = config.FLAGDB

        import pyflag.TypeCheck as TypeCheck

        #Check to see if the query string has enough parameters in it:
        try:
            if report.check_parameters(query):
                canonical_query = self.canonicalise(query)
                #Parameters ok, lets go

                #Check to see if the user wants to reset this report?
                if query.has_key('reset'):
                    report.do_reset(query)
                    result.heading("Report reset")
                    del query['reset']
                    result.refresh(1,query)
                    return result

                #Check to see if the report is cached in the database
                if self.is_cached(query):                   
                    report.display(query,result)
                    result.defaults = query
                    return result
                
                #Are we currently executing the report?
                result = self.check_progress(report,query)
                
                #OK - we run the analysis method in a seperate thread
                if not result:
                   #Start a new thread and run the analysis in it.
                   t = threading.Thread(target=self.run_analysis,args=(report,query))
                   t.start()
                   import time

                   #wait a little for the analysis to work
                   time.sleep(0.5)
                   #Are we still running the analysis?
                   result = self.check_progress(report,query)

                   #Nope - we should run the display method now...
                   if not result:
                       result = self.ui()
                       result.defaults = query
                       report.display(query,result)

                   return result
               
            #Form does not have enough parameters...
            else:
                #Set the default form behaviour
                result.defaults = query
                result.heading(report.name)
                result.start_form(query)
                report.form(query,result)
                result.end_table()
                result.end_form('Submit')
                
        #If one of the parameters is wrong - we present the user with an error page!!!
        except TypeCheck.ReportInvalidParamter, e:
            result.heading("Invalid parameters given:")
            result.para("%s" % e)
            return result

        return result

    checked=0
    def check_config(self,result,query):
        """ Checks the configuration for empty entries.

        Queries the user for those entries and creates a new configuration file in the users home directory
        @return: 1 if some of the configuration parameters are missing, 0 if all is well.
        """
        ## Short circuit to ensure we do not need to do this over and over.
        if self.checked: return 0
        global config
        ## Check to see if any of the configuration parameters are empty:
        params=[]
        import ConfigParser
        save_params=ConfigParser.RawConfigParser()
        result.heading("Missing configuration parameters")
        result.start_form(query)
        result.start_table()
        for section in config.config.sections():
            for opt in config.config.options(section):
                if config.config.get(section,opt)=='':
                    ## Check to see if these parameters are outstanding:
                    if query.has_key(opt):
                        try:
                            save_params.add_section(section)
                        except:
                            pass
                        
                        save_params.set(section,opt,query[opt])
                    else:
                        params.append(opt)
                        result.textfield("%s: %s" %(section,opt),opt)

        ## Now save the parameters that have been given:
        if save_params.sections():
            fd=open(os.path.expanduser('~/.pyflagrc'),'w')
            save_params.write(fd)
            fd.close()
            ## Force a reload of configuration files:
            ##pyflag.conf.ConfObject.config=None
            ##config=pyflag.conf.ConfObject()
            ##This does not work since everywhere else config was already loaded to be the old one. We really do need to exit and restart here.
            print "You must restart the server for the changes to take effect"
            sys.exit(0)

        if params:
            result.end_table()
            result.end_form()
            return 1
            
        ## Now check that we can create a database connection: FIXME
        self.checked=1
        return 0
        

class module_dispatcher:
    """ Generic class to manage access to report objects obtained from plugins. """
    family = {}
    modules = {}

    def get(self,family,name):
        """ Resolves the report named by family/name pair """
        try:
            return self.family[family][name]
        except KeyError,e:
            print self.family
            raise DispatchError, e

    def __init__(self,plugins,flag,ui=None):
        """ Searchs plugin directory and loads the modules into the program.

        Classes which are derived from report are loaded into the dispatcher and sorted into family/name combination in the self.family data structure. If we get error in certain modules we ignore those modules or reports and keep going after printing a warning to stdout.
        """
        import os,imp
        for plugin in plugins:
            for dirpath, dirnames, filenames in os.walk(plugin):
                for filename in filenames:
                    #Lose the extension for the module name
                    module_name = filename[:-3]
                    if filename.endswith(".py"):
                        logging.log(logging.DEBUG,"Will attempt to load plugin '%s/%s'" % (dirpath,filename))
                        try:
                            try:
                                #open the plugin file
                                fd = open(dirpath+'/'+filename ,"r")
                            except Exception,e:
                                logging.log(logging.DEBUG, "Unable to open plugin file '%s': %s" % (filename,e))
                                continue

                            import imp

                            #load the module into our namespace
                            try:
                                module = imp.load_source(module_name,dirpath+'/'+filename,fd)
                            except Exception,e:
                                logging.log(logging.ERRORS, "*** Unable to load module: %s" % e)
                                continue

                            fd.close()

                            #Is this module active?
                            try:
                                if module.hidden: continue
                            except AttributeError:
                                pass

                            #find the module description
                            try:
                                module_desc = module.description
                            except AttributeError:
                                module_desc = module_name

                            module_desc=module_name
                            ## Do we already have this module?
                            if self.modules.has_key(module_desc):
                                logging.log(logging.WARNINGS, "Module %s is already loaded, skipping...." % module_desc)
                                continue

                            #Now we enumerate all the classes in the module to see which one is a report class
                            for cls in dir(module):
                                #We check to see if each class is derived from the report class
                                try:
                                    import pyflag.Reports as Reports

                                    if issubclass(module.__dict__[cls],Reports.report):
                                        #If it is we instantiate it and store it in the dispatcher
                                        new_report = module.__dict__[cls](flag,ui=ui)
                                        new_report.conf = conf

                                        #here we check to see if the new report has all the methods we need. TBYL :
                                        try:
                                            new_report.display, new_report.analyse, new_report.progress, new_report.form, new_report.name, new_report.parameters
                                        except AttributeError,e:
                                            err = "Failed to load report '%s': %s" % (cls,e)
                                            logging.log(logging.WARNINGS, err)
                                            continue

                                        if not self.family.has_key(module_desc):
                                            self.family[module_desc] = {}
                                            logging.log(logging.DEBUG, "Added new family '%s' in module '%s.py'" % (module_desc,module_name))

                                        self.family[module_desc][cls] = new_report

                                        try:
                                            self.modules[module_desc] = module.order
                                        except AttributeError:
                                            self.modules[module_desc] = 0

                                        logging.log(logging.DEBUG, "Added report '%s:%s'" % (module_desc,cls))

                                # Oops: it isnt a class...
                                except (TypeError, NameError) , e:
                                    continue

                        except TypeError, e:
                            logging.log(logging.ERRORS, "Could not compile module %s: %s" % (module_name,e))
                            continue
        
class HexDump:
    """ Class manages displaying arbitrary data as hex dump.

    @ivar width: The width of the dump, in number of bytes. (default 16)
    """
    width = 16
    
    def __init__(self,data,ui):
        """ Constructor:
        @arg data: The binary data to dump
        @arg ui: A suitable UI object to use for the dump. This dumper uses ui.text to display the data. If ui is None, no UI will be used."""
        self.data = data
        self.ui = ui

    def dump(self,offset=0,limit=10240,base_offset=0):
        """ Dumps out the data.

        If a UI was specified in the constructor, we use it to display the data.

        @arg offset: The initial offset to use as the start of the data. Note that this is used to seek within the data given.
        @arg base_offset: An offset that will be added to the offset labels, but otherwise has no effect. Useful when data represents a chunk from a larger data set.
        @return: A string having the hex dump in it.
        """
        result = ''
        ui = self.ui
        offset_format =  "%06x   "
        char_format = "%02x "
        text_format = "   %s\n"
        initial_offset=offset

        #Do the headers:
        result += ' ' * len(offset_format % 0)
        ui.text( ' ' * len(offset_format % 0),font='typewriter')
        for i in range(self.width):
            result += char_format % i
            ui.text(char_format % i,color = 'blue',font='typewriter')

        ui.text("\n",font='typewriter')
        result+="\n"
        finished=0
        
        while not finished and initial_offset+limit>offset:
            ui.text(offset_format % (offset+base_offset), color='blue',font='typewriter')
            result += offset_format % offset
            text = ''

            for i in range(self.width):
                try:
                    ui.text(char_format % ord(self.data[offset]),color='black',font='typewriter')  
                    result += char_format % ord(self.data[offset])
                except IndexError:
                    ui.text("   ")
                    result += "   "
                    finished = 1

                try:
                    if 32 < ord(self.data[offset]) < 127:
                        text += self.data[offset]
                    else:
                        text += '.'
                except IndexError:
                    text += ' '
                    finished = 1
                    
                offset += 1

            ## Add the text at the end of each line
            ui.text(text_format % text,color='red',font='typewriter',sanitise='full')
            result+=text_format % text

            ui.text(finish=1)

class Magic:
    """ Singleton class to manage magic library access """
    ## May need to do locking in future, if libmagic is not reentrant.
    magic = None
    mimemagic = None
    
    def __init__(self,mode=None):
        if not Magic.magic:
            Magic.magic=magic.magic_open(magic.MAGIC_NONE)
            if magic.magic_load(Magic.magic,config.MAGICFILE) < 0:
                raise IOError("Could not open magic file %s" % config.MAGICFILE)
            
        if not Magic.mimemagic:
            Magic.mimemagic=magic.magic_open(magic.MAGIC_MIME)
            if magic.magic_load(Magic.mimemagic,config.MAGICFILE) < 0:
                raise IOError("Could not open magic file %s" % config.MAGICFILE)
        self.mode=mode

    def buffer(self,buf):
        """ Return the string representation of the buffer """
        if self.mode:
            result=magic.magic_buffer(Magic.mimemagic,buf)
        else:
            result=magic.magic_buffer(Magic.magic,buf)

        if not result:
            return "text/plain"
        else: return result

class Curry:
    """ This class makes a curried object available for simple inlined functions.

    A curried object represents a function which has some of its arguements pre-determined. For example imagine there is a function:

    def foo(a=a,b=b):
        pass

    curry=Curry(foo,a=1)   returns a function pointer.

    curry(3) is the same as calling foo(a=1,b=3).
    For more information see the Python Cookbook.
    """
    def __init__(function,*args,**kwargs):
        """ Initialised the curry object with the correct function."""
        self.fun=function
        self.pending = args[:]
        self.kargs = kwargs.copy()

    def __call__(self,*args,**kwargs):
        if kwargs and self.kwargs:
            kw=self.kwargs.copy()
            kw.update(kwargs)
        else:
            kw = kwargs or self.kwargs

        return self.fun(*(self.pending+args), **kw)
