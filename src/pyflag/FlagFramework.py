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

""" Main flag framework modules contains many core classes

@var flag_version: Current version of the flag program
""" 
flag_version = "$Version: 0.78 Date: Fri Aug 19 00:47:14 EST 2005$"
flag_version=flag_version.replace('$','')
import sys,os
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.logging as logging
import pyflag.Registry as Registry

class DontDraw(Exception):
    """ Exception raised by a UI to let the server know not to draw it.

    This is mainly used by the form method to allow a UI to manage its own window
    """

def canonicalise(query):
    """ Converts the query into the canonical form.

    The canonical form is defined as the sorted urlified key=value pairs of the parameters defined in the reports.parameters dict. This is used to uniquely identify the request in order to manage the caching."""
    if not query['report'] or not query['family']:
        raise FlagException,"No report or family in canonicalise query"

    report = Registry.REPORTS.dispatch(query['family'],query['report'])
    ## We instantiate the report before we determine its parameters
    ## list. This allows reports to have dynamic parameters list which
    ## gets built in the __init__
    report = report(None,None)

    tmp = []
    for x,y in query:
        if report.parameters.has_key(x) or x=='family' or x=='report':
            tmp.append("%s=%s" %(urlencode(x),urlencode(y)))

    tmp.sort()
    return '&'.join(tmp)
    
class AuthError(Exception):
    """ Exception raised when Authentication fails """
    def __init__(self,result):
        self.result=result

def get_bt_string(e):
    import sys
    import traceback
    import cStringIO
    
    a = cStringIO.StringIO()
    traceback.print_tb(sys.exc_info()[2], file=a)
    a.seek(0)
    result = a.read()
    a.close()
    return result
    
def get_traceback(e,result):
    result.heading("%s: %s" % (sys.exc_info()[0],sys.exc_info()[1]))
    result.text(get_bt_string(e))            

class FlagException(Exception):
    """ Generic Flag Exception """
    pass

class query_type:
    """ A generic wrapper for holding CGI parameters.

    This is almost like a dictionary, except that there are methods provided to give access to CGI arrays obtained by repeated use of the same key mutiple times.
    @note: This property necessitate the sometime unituitive way of resetting a paramter by initially deleting it. For example, to change the 'report' parameter in query you must do:
    
    >>> del query['report']
    >>> query['report'] = 'newvalue'

    since if the paramter is not deleted first, it will simply be appended to produce a report array.
    """
    def __init__(self,query_list=(),user=None,passwd=None,base='',**params):
        """ Constructor initialises from a CGI list of (key,value) pairs or named keywords. These may repeat as needed.

        @arg query_list: A list of lists as obtained from cgi.parse_qsl. This way of initialising query_type is obsolete - do not use.
        @arg user: The username or None if unauthenticated.
        @arg passwd: The password used or None if unauthenticated.
        @arg base: The base of the query. This is the part of the URL before the ?.
        """
        # Authentication Stuff
        self.user = user
        self.passwd = passwd
        self.base= base
        
        self.q=[]
        if isinstance(query_list,list):
            self.q = query_list
        elif isinstance(query_list,tuple):
            self.q = list(query_list)
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

        return cgi.urllib.urlencode(self.q)+mark
    
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

    def poparray(self,key):
        """ Remove last member of array from query """
        tmp = [ i for i in self.q if i[0]==key ]
        try:
            self.remove(tmp[-1][0],tmp[-1][1])
        except IndexError:
            raise KeyError

        return tmp[-1][1]
    
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

    def get(self,item,default=None):
        for i in self.q:
            if i[0]== item:
                return i[1]

        return default
        
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
import re,cgi
import conf

def urlencode(string):
    """ Utility function used for encoding strings inside URLs.

    Replaces non-alphnumeric chars with their % representation """
    result = ''
    for c in str(string):
        if not c.isalnum():
            result +="%%%02X" % ord(c)
        else:
            result += c

    return result

class Flag:
    """ Main Flag object.

    This object is responsible with maintaining configuration data, dispatching reports and processing queries.
    
    """
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

        ## Initialise the registry:
        Registry.Init()
                
    def is_cached(self,query):
        """ Checks the database to see if the report has been cached """
        try:
            dbh = DB.DBO(query['case'])
            dbh.execute("select * from meta where property=%r and value=%r",("report_executed",canonicalise(query)))
            if dbh.fetch():
                return True
        except:
            pass
        
        return False

    def run_analysis(self,report,query):
        canonical_query = canonicalise(query)
        #Find our thread name
        thread_name = threading.currentThread().getName()
        print "Current thread is %s" % thread_name
        import pyflag.Reports as Reports

        #note that we are executing this report (place a lock in the
        #report class - The lock is shared amongst all objects)
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
            result = self.ui()
            get_traceback(e,result)
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
        canonical_query = canonicalise(query)
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
            report = Registry.REPORTS.dispatch(query['family'],query['report'])
            ## Instantiate the report:
            report = report(self,ui=self.ui)
            
        except (IndexError):
            result.heading("Report Or family not recognized")
            result.para("It is possible that the appropriate module is not installed.")
            return result

        def show_help(query,result):
            result.heading("Help for %s" % report.name)
            result.text(report.__doc__)
            result.decoration='naked'

        #Since flag must always operate on a case, if there is no case, we use the default flagdb as a case
        try:
            query['case']
        except KeyError:
            query['case'] = config.FLAGDB

        import pyflag.TypeCheck as TypeCheck

        # First check authentication, do this always
        if not report.authenticate(query, result):
            raise AuthError(result)
                
        #Check to see if the query string has enough parameters in it:
        try:
            if report.check_parameters(query):
                canonical_query = canonicalise(query)
                #Parameters ok, lets go
                result.toolbar(show_help,text="Help",icon="help.png")

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
                    return result
                
                #Are we currently executing the report?
                progress_result = self.check_progress(report,query)
                
                #OK - we run the analysis method in a seperate thread
                if not progress_result:
                   #Start a new thread and run the analysis in it.
                   t = threading.Thread(target=self.run_analysis,args=(report,query))
                   t.start()
                   import time

                   #wait a little for the analysis to work
                   time.sleep(0.5)
                   #Are we still running the analysis?
                   progress_result = self.check_progress(report,query)

                   #Nope - we should run the display method now...
                   if not progress_result:
                       progress_result=result
                       report.display(query,progress_result)

                   return progress_result
                ## Report analysis returned an error
                else:
                     return progress_result
               
            #Form does not have enough parameters...
            else:
                #Set the default form behaviour
                result.defaults = query
                result.toolbar(show_help,text="Help",icon="help.png")
                result.heading(report.name)
                try:
                    result.start_form(query)
                    report.form(query,result)
                    result.end_table()
                    result.end_form('Submit')
                except DontDraw:
                    pass
                
        #If one of the parameters is wrong - we present the user with an error page!!!
        except TypeCheck.ReportInvalidParamter, e:
            result.heading("Invalid parameters given:")
            result.para("%s" % e)
            return result

        return result

    def check_config(self,result,query):
        """ Checks the configuration for empty entries.

        Queries the user for those entries and creates a new configuration file in the users home directory
        @return: 1 if some of the configuration parameters are missing, 0 if all is well.
        """
        report = None

        ## First check for missing parameters:
        for k,v in config.__class__.__dict__.items():
            if v=='':
                if query.has_key('PYFLAG_'+k):
                    config.__class__.__dict__[k]=query['PYFLAG_' + k]
                else:
                    report = Registry.REPORTS.dispatch("Configuration",
                                                       "Configure")

        ## If we were going to the config page we keep going there:
        if not report:
            if query.get('family',None)=='Configuration':
                report = Registry.REPORTS.dispatch(query['family'],
                                                   query['report'])

        ## Now check that the DB is properly initialised:
        if not report:
            try:
                dbh=DB.DBO(None)
                dbh.execute("desc meta");
            except Exception,e:
                print "DB Error was %s" % e
                if "Access denied" in str(e):
                    report = Registry.REPORTS.dispatch("Configuration",
                                                       "Configure")
                else:
                    report = Registry.REPORTS.dispatch("Configuration",
                                                       "Initialise Database")

        if report:
            ## Instantiate report:
            report = report(self, ui=self.ui)
            query['family']=report.family
            query['report']=report.name

            if report.check_parameters(query):
                report.display(query,result)
            else:
                result.start_form(query)
                result.heading(report.name)
                report.form(query,result)
                result.end_table()
                result.end_form('Submit')

            return True
            
        return False
                
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

    def dump(self,offset=0,limit=10240,base_offset=0,highlight=0,length=0):
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
        text_format = "   %s"
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
            tmp_offset=offset
            ui.text(offset_format % (offset+base_offset), color='blue',font='typewriter')
            result += offset_format % offset
            text = ''

            for offset in range(tmp_offset,tmp_offset+self.width):
                try:
                    if offset>=highlight and offset<highlight+length:
                        ui.text(char_format % ord(self.data[offset]),color='black',font='typewriter',highlight=1)  
                    else:
                        ui.text(char_format % ord(self.data[offset]),color='black',font='typewriter')  
                    result += char_format % ord(self.data[offset])
                except IndexError:
                    ui.text("   ")
                    result += "   "
                    finished = 1

            for offset in range(tmp_offset,tmp_offset+self.width):
                if offset>=highlight and offset<highlight+length:
                    highlight_flag=1
                else:
                    highlight_flag=0
                    
                try:
                    if 32 < ord(self.data[offset]) < 127:
                        ui.text(self.data[offset],color='red',font='typewriter',sanitise='full',highlight=highlight_flag)
                        result+=self.data[offset]
                    else:
                        ui.text('.',color='red',font='typewriter',sanitise='full',highlight=highlight_flag)
                        result+='.'
                except IndexError:
                    finished = 1

            ui.text("\n",font='typewriter',sanitise='full')
#            ui.text(finish=1)
            offset+=1

try:
    import magic

    class Magic:
        """ Singleton class to manage magic library access """
        ## May need to do locking in future, if libmagic is not reentrant.
        magic = None
        mimemagic = None

        def __init__(self,mode=None):
            if not Magic.magic:
                Magic.magic=magic.open(magic.MAGIC_NONE)
                if Magic.magic.load(config.MAGICFILE) < 0:
                    raise IOError("Could not open magic file %s" % config.MAGICFILE)

            if not Magic.mimemagic:
                Magic.mimemagic=magic.open(magic.MAGIC_MIME)
                if Magic.mimemagic.load(config.MAGICFILE) < 0:
                    raise IOError("Could not open magic file %s" % config.MAGICFILE)
            self.mode=mode

        def buffer(self,buf):
            """ Return the string representation of the buffer """
            if self.mode:
                result=Magic.mimemagic.buffer(buf)
            else:
                result=Magic.magic.buffer(buf)

            if not result:
                return "text/plain"
            else: return result

except ImportError:
    pass

class Curry:
    """ This class makes a curried object available for simple inlined functions.

    A curried object represents a function which has some of its arguements pre-determined. For example imagine there is a function:

    def foo(a=a,b=b):
        pass

    curry=Curry(foo,a=1)   returns a function pointer.

    curry(3) is the same as calling foo(a=1,b=3).
    For more information see the Python Cookbook.
    """
    def __init__(self,function,*args,**kwargs):
        """ Initialised the curry object with the correct function."""
        self.fun=function
        self.pending = args[:]
        self.kwargs = kwargs.copy()

    def __call__(self,*args,**kwargs):
        if kwargs and self.kwargs:
            kw=self.kwargs.copy()
            kw.update(kwargs)
        else:
            kw = kwargs or self.kwargs

        return self.fun(*(self.pending+args), **kw)

GLOBAL_FLAG_OBJ=None

def reset_all(**query):
    """ This searchs for all executed reports with the provided parameters in them and resets them all.

    Callers need to provide at least a report name, case and a family or an exception is raised.
    """
    flag = GLOBAL_FLAG_OBJ
    report =Registry.REPORTS.dispatch(query['family'],query['report'])
    dbh=DB.DBO(query['case'])
    family=query['family'].replace(" ","%20")
    dbh.execute("select value from meta where property='report_executed' and value like '%%family=%s%%'" % family)
    for row in dbh:
        import cgi
        
        q = query_type(cgi.parse_qsl(row['value']),case=query['case'])
        try:
            for k in query.keys():
                if k=='case': continue
                if q[k]!=query[k]:
                    raise KeyError()

            ## This report should now be reset:
            logging.log(logging.DEBUG, "Will now reset %s" % row['value'])

            try:
                report=report(flag)
            except:
                pass
            report.reset(q)
            dbh2 = DB.DBO(query['case'])
            dbh2.execute("delete from meta where property='report_executed' and value=%r",row['value'])
        except KeyError:
            pass

def normpath(string):
    """A sane implementation of normpath.

    The Python normpath has a bug whereby it swallaws the last / in a path name - this makes it difficult to distinguish between a directory and a filename.
    This is a workaround this braindead implementation.
    """
    tmp = os.path.normpath('////'+string)
    if string.endswith('/') and not tmp.endswith('/'):
        tmp=tmp+'/'
    return tmp


def make_sql_from_filter(filter_str,having,column,name):
    """ This function creates the SQL depending on the filter_str that was provided and its prefixes.

    @arg filter_str: The filter string to process.
    @arg having: this array will get the SQL appended to it.
    @arg column: The array of all the column names.
    @return: A condition text describing this condition.
    """
    if filter_str.startswith('=') or filter_str.startswith('<') or filter_str.startswith('>'):
        ## If the input starts with !, we do an exact match
        having.append("%s %s %r " % (column,filter_str[0],filter_str[1:]))
        condition_text="%s %s %s" % (name,filter_str[0],filter_str[1:])
    elif filter_str.find('%')>=0:
        #If the user already supplied the %, we dont add our own:
        having.append("%s like %r " % (column,filter_str.replace('%','%%')))
        condition_text="%s like %s" % (name,filter_str)
    elif filter_str[0] == '!':
        #If the user already supplied the %, we dont add our own:
        having.append("%s not like %r " % (column,"%%%%%s%%%%"% filter_str[1:]))
        condition_text="%s not like %s" % (name,"%%%s%%" % filter_str[1:])
    else:
        ## Otherwise we do a fuzzy match. 
        having.append("%s like %r " % (column,"%%%%%s%%%%"% filter_str))
        condition_text="%s like %s" % (name,"%%%s%%" % filter_str)

    return condition_text

def get_temp_path(case,filename):
    """ Returns the full path to a temporary file based on filename.
    """
    filename = filename.replace('/','-')
    return "%s/case_%s/%s" % (config.RESULTDIR,case,filename)
