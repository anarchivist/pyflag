#!/usr/bin/env python
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

""" Main flag framework modules contains many core classes
""" 
import sys,os
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.pyflaglog as pyflaglog
import pyflag.Registry as Registry
import pyflag.Store as Store
import textwrap

## This is required to shut up some stupid python warnings
import warnings
warnings.filterwarnings('ignore',
                        message=r'Module .*? was already imported', append=True)

## This global tells us if we checked the configuration already - we
## only check configuration the first time we are run.
config_checked = False

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

def get_bt_string(e=None):
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


STORE = Store.Store(1000)

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
    def __init__(self,query_list=(),string=None, user=None, passwd=None, base='',**params):
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
    
        ## The window we came from (This is used by HTML to work our
        ## where we need to be drawn to.
        self.window = "window"
        self.callback =''

        if string:
            query_list = cgi.parse_qsl(string)
        
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

        ## Make sure our query is parsed into unicode if needed:
        for i in range(len(self.q)):
            self.q[i] = (smart_unicode(self.q[i][0]), smart_unicode(self.q[i][1]))

    def __str__(self):
        """ Prints the query object as a url string. We encode ourself
        into utf8 to cater for any unicode present.

        NOTE: A URI is build by joining all keys and values with
        &. Both keys and values are properly escaped.
        """
        mark=''
        tmp = self.clone()
        result = []
        
        for k in tmp.keys():
            if k.startswith("__"):
                del tmp[k]

        for k,v in tmp.q:
            result.append("%s=%s" % (escape_unicode_string(k), escape_unicode_string(v)))

        return "&".join(result)

    def __repr__(self):
        result = ''
        for k,v in self.q:
            result += "%r: %r\n" % (k,v)

        return result
    
    def __delitem__(self,item):
        """ Removes all instance of item from the CGI object """
        to_remove=[ d for d in self.q if d[0] == item ]
        for i in to_remove:
            try:
                while 1:
                    self.q.remove(i)
            except ValueError:
                pass

    def clear(self, key):
        try:
            del self[key]
        except KeyError:
            pass

    def set(self, key, value):
        del self[key]
        self[key]=smart_unicode(value)

    def default(self, key, value):
        """ Set key to value only if key is not yet defined """
        if not self.has_key(key):
            self[key] = value

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
        tmp.window = self.window
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
            return None
            #raise KeyError

        return tmp[-1][1]
    
    def has_key(self,key):
        for i in self.q:
            if i[0] == key:
                return True
            
        return False

    def items(self):
        return self.q.__iter__()

    def __setitem__(self,i,x):
        ## case may only be specified once:
        if i=='case' and self.has_key('case'):
            self.__delitem__('case')
        
        self.q.append((i,smart_unicode(x)))
        
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

    def extend(self,dict):
        for k in dict.keys():
            self[k]=dict[k]

    def FillQueryTarget(self,dest):
        """ Given a target, this function returns a updates the query object with a filled in target

        @except KeyError: if the query is not formatted properly (i.e. no _target_ key)
        """
        for target in self.getarray('__target__'):
            ## Calculate the destination value:
            dest = self.get('__target_format__','%s') % dest
            
            ## Do we need to append it:
            if self.has_key('__target_type__') and self['__target_type__'] == 'append':
                self[target] = dest
            else:
                self.set(target,dest)

import pyflag.DB as DB
import threading
import re,cgi
import conf

def urlencode(string):
    """ Utility function used for encoding strings inside URLs.

    Replaces non-alphnumeric chars with their % representation

    Note: this could be replaced by urlllib.quote(string)

    """
    result = ''
    for c in "%s" % string:
        if not c.isalnum() and c not in "/.":
            result +="%%%02X" % ord(c)
        else:
            result += c

    return result

def show_help(query, result, cls=None):
    """ This is a popup callback which displays the doc string of a
    class nicely formatted.
    """
    result.decoration='naked'

    ## Try to use rst2html to produce nice looking html:
    try:
        import docutils.core

        result.result += docutils.core.publish_string(textwrap.dedent(cls.__doc__),
                                                      writer_name='html')
    except Exception,e:
        pyflaglog.log(pyflaglog.ERROR,"Error running docutils: %s", e)
        result.heading("Help for %s" % cls.__name__)
        result.text(textwrap.dedent(cls.__doc__), font='typewriter')

class Flag:
    """ Main Flag object.

    This object is used to process requests and run analysis, manage
    caching etc. You need to extend it to create a Flag Server.
    """
    def is_cached(self,query):
        """ Checks the database to see if the report has been cached """
        try:
            dbh = DB.DBO(query['case'])
            dbh.execute("select * from meta where property=%r and value=%r limit 1",("report_executed",canonicalise(query)))
            if dbh.fetch():
                return True
        except Exception,e:
            pass
        
        return False

    def run_analysis(self,report,query, result):
        canonical_query = canonicalise(query)
        #Find our thread name
        thread_name = threading.currentThread().getName()
        print "Current thread is %s" % thread_name
        import pyflag.Reports as Reports

        #note that we are executing this report (place a lock in the
        #report class - The lock is shared amongst all objects)
        report.executing[thread_name]={'query': canonical_query, 'error': None}
        try:
            analysis_result = report.analyse(query)
        ## These are deliberate errors that reports raise with their own custom UI message:
        except Reports.ReportError,e:
            report.executing[thread_name]['error'] = e
            pyflaglog.log(pyflaglog.ERROR, "Error executing analysis: %s", e)
            return

        except Exception,e:
            #If anything goes wrong in the analysis phase, we have to set the error in report.executing
            result.clear()
            get_traceback(e,result)
            report.executing[thread_name]['error'] = result
            print report.executing, result.__str__()
            return

        #Lets remember the fact that we analysed this report - in the database
        try:
            dbh = DB.DBO(query.get('case'))
            dbh.execute("insert into meta set property=%r,value=%r",('report_executed',canonical_query))
        except DB.DBError:
            pass

        #Remove the lock
        del report.executing[thread_name]


    def check_progress(self,report,query, result):
        """ Checks the progress of a report. If the report is not running this method returns None. If the report is still running or has died due to an error, this method returns a UI object containing either the error message or a progress report called from the report's own progress method """
        canonical_query = canonicalise(query)
        if report.is_executing(canonical_query):
            #Did the analysis thread die with an error?
            thread_name = report.is_executing(canonical_query)
            #if an error exists, we get the error traceback produced by the analysis thread
            new_result = report.executing[thread_name]['error']
            #If the analysis thread set an error UI object we just return it else evaluate the progress
            if new_result:
                result.heading("Error occured during analysis stage")
                del report.executing[thread_name]
                return result
            else:
                result.clear()
                report.progress(query,result)
                #Refresh page
                result.refresh(config.REFRESH,query)
                return result
        #we are not executing
        else: return None

    ### FIXME- This needs to move to FlagHTTPServer
    def process_request(self,query, result):
        """ Function responsible for processing the request presented by query, which is of query_type. Results returned are a UI object which may be used to display the results
        @arg query: A query_type object.
        @return: A UI object which must be displayed.
        """
        #Check to see if the report is valid:
        try:
            report_cls = Registry.REPORTS.dispatch(query['family'],query['report'])
            ## Instantiate the report:
            report = report_cls(self,ui=result)
            
        except (IndexError):
            result.heading("Report Or family not recognized")
            result.para("It is possible that the appropriate module is not installed.")
            return 

        ## We must make copies here to allow the report to be destroyed!!!
        report_name = report.name
        import pyflag.TypeCheck as TypeCheck

        # First check authentication, do this always
        if not report.authenticate(query, result):
            raise AuthError(result)
                
        #Check to see if the query string has enough parameters in it:
        try:
            if report.check_parameters(query):
                canonical_query = canonicalise(query)
                #Parameters ok, lets go
#                result.toolbar(cb = my_show_help,
#                               text="Help on %s" % report.name,icon="help.png")

                #Check to see if the user wants to reset this report?
                if query.has_key('reset'):
                    report.do_reset(query)
                    result.heading("Report reset")
                    del query['reset']
                    result.refresh(1,query)
                    return 

                #Check to see if the report is cached in the database
                if self.is_cached(query):
                    report.display(query,result)
                    return 
                
                #Are we currently executing the report?
                progress_result = self.check_progress(report,query, result)
                
                #OK - we run the analysis method in a seperate thread
                if not progress_result:
                   #Start a new thread and run the analysis in it.
                   t = threading.Thread(target=self.run_analysis,args=(report,query, result))
                   t.start()
                   import time

                   #wait a little for the analysis to work
                   time.sleep(0.5)
                   #Are we still running the analysis?
                   progress_result = self.check_progress(report,query, result)

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
                result.toolbar(Curry(show_help,cls=report),
                               text="Help on %s" % report.name,
                               icon="help.png")
                result.heading(report.name)
                try:
                    result.start_form(query)
                    report.form(query,result)
                    result.end_table()
                    result.end_form(result.submit_string)
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
        ## This stores if the config has already been checked - we
        ## dont want to do this for every request.
        global config_checked
        
        if config_checked: return
        report = None

        ## If we were going to the config page we keep going there:
        if not report:
            if query.get('family',None)=='Configuration':
                report = Registry.REPORTS.dispatch(query['family'],
                                                   query['report'])

        ## Now check that the DB is properly initialised:
        if not report:
            try:
                dbh=DB.DBO(None)
                version = dbh.get_meta("schema_version")
                ## The version is an integer
                try: version = int(version)
                except: version = 0
                
                if not version or version < config.SCHEMA_VERSION:
                    report = Registry.REPORTS.dispatch("Configuration",
                                                       "Initialise Database")
                    report.version = version
                elif version > config.SCHEMA_VERSION:
                    report = Registry.REPORTS.dispatch("Configuration",
                                                       "HigherVersion")
                    report.version = version
                else:
                    config_checked = True
                    
            except Exception,e:
                error = str(e)
                if "Unknown database" in error:
                    query['error'] = str(e)
                    print e
                    report = Registry.REPORTS.dispatch("Configuration",
                                                       "Initialise Database")

                elif "Access denied" in error or "Unable to connect" in error:
                    report = Registry.REPORTS.dispatch("Configuration",
                                                       "Pyflag Configuration")
                    query['highlight'] = 'dbpasswd'

                ## Set some helpful hints:
                if "socket" in error:
                    query['highlight'] = 'dbunixsocket'
                    query['highlight'] = 'dbhost'
                    query['highlight'] = 'dbport'

                result.para(error, color='red')

        if report:
            ## Instantiate report:
            report = report(self, ui=result)
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

        config_checked = True
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

    def dump(self,offset=0,limit=10240,base_offset=0,highlight=[]):
        """ Dumps out the data.

        If a UI was specified in the constructor, we use it to display the data.

        @arg offset: The initial offset to use as the start of the data. Note that this is used to seek within the data given.
        @arg base_offset: An offset that will be added to the offset labels, but otherwise has no effect. Useful when data represents a chunk from a larger data set.

        @arg highlight: This is a list of lists denoting highlighting regions. Each region is a list consisting of [offset, length, color]. 
        
        @return: A string having the hex dump in it.
        """
        result = ''
        ui = self.ui
        offset_format =  "%06x   "
        char_format = "%02x "
        text_format = "   %s"
        initial_offset=offset

        def find_highlights(off):
            """ Searches the highlight list and returns the color
            which offset should be rendered in. Returns None if no
            color is needed.
            """
            result = None
            for offset, length, color in highlight:
                if off >= offset and offset + length > off:
                    result = color
                    
            return result

        #Do the headers:
        result += ' ' * len(offset_format % 0)
        ui.text( ' ' * len(offset_format % 0),font='typewriter')
        for i in range(self.width):
            result += char_format % i
            ui.text(char_format % i,style = 'blue',font='typewriter')

        ui.text("\n",font='typewriter')
        result+="\n"
        finished=0
        
        while not finished and initial_offset+limit>offset:
            tmp_offset=offset
            ui.text(offset_format % (offset+base_offset), style='blue',font='typewriter')
            result += offset_format % offset
            text = ''

            for offset in range(tmp_offset,tmp_offset+self.width):
                try:
                    color = find_highlights(offset)
                    if color:
                        ui.text(char_format % ord(self.data[offset]),
                                font='typewriter',style=color)  
                    else:
                        ui.text(char_format % ord(self.data[offset]),style='black',
                                font='typewriter')
                        
                    result += char_format % ord(self.data[offset])
                except IndexError:
                    ui.text("   ")
                    result += "   "
                    finished = 1

            for offset in range(tmp_offset,tmp_offset+self.width):
                args = dict(font='typewriter',sanitise='full',style='red')
                color = find_highlights(offset)
                if color:
                    args['style'] = color
                    
                try:
                    if 32 < ord(self.data[offset]) < 127:
                        ui.text(self.data[offset],**args)
                        result+=self.data[offset]
                    else:
                        ui.text('.',**args)
                        result+='.'
                except IndexError:
                    finished = 1

            ui.text("\n",font='typewriter',sanitise='full')
#            ui.text(finish=1)
            offset+=1

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
        
        q = query_type(string=row['value'],case=query['case'])
        try:
            for k in query.keys():
                if k=='case': continue
                if q[k]!=query[k]:
                    raise KeyError()

            ## This report should now be reset:
            pyflaglog.log(pyflaglog.DEBUG, "Will now reset %s" % row['value'])

            print "Resetting %s" % query

            try:
                report=report(flag)
            except:
                pass
            report.reset(q)
            dbh2 = DB.DBO(query['case'])
            dbh2.execute("delete from meta where property='report_executed' and value=%r",row['value'])
        except KeyError:
            pass

import posixpath

def normpath(string):
    """A sane implementation of normpath.

    The Python normpath has a bug whereby it swallaws the last / in a path name - this makes it difficult to distinguish between a directory and a filename.
    This is a workaround this braindead implementation.
    """
    tmp = posixpath.normpath('////'+string)
    if string.endswith('/') and not tmp.endswith('/'):
        tmp=tmp+'/'
    return tmp

def splitpath(path):
    """ Returns all the elements in path as a list """
    path=normpath(path)
    return [ x for x in path.split('/') if x ]

def joinpath(branch):
    return '/'+'/'.join(branch)

def sane_join(*branch):
    return os.path.normpath(os.path.sep.join(branch))

from posixpath import join
import time

def glob_to_sql(glob):
    glob=glob.replace("*","%")
    return glob

def delete_case(case):
    """ A helper function which deletes the case """
    dbh = DB.DBO(None)    
    ## Broadcast that the case is about to be dropped (This broadcasts
    ## to the workers)

    dbh.insert('jobs',command = "DropCase", state='broadcast', arg1=case, cookie=0, _fast = True)

    ## This sends an event to our process:
    post_event('reset', case)

    ## Remove any jobs that may be outstanding (dont touch the
    ## currently processing jobs)
    dbh.delete('jobs',DB.expand("arg1=%r and state='pending' " , case),
               _fast= True)

    ## Now wait until there are no more processing jobs:
    total_time = 0
    while 1:
        dbh.execute("select * from jobs where arg1=%r and state='processing' limit 1", case)
        row = dbh.fetch()
        if row:
            time.sleep(2)
            total_time += 2
            if total_time > 20:
                pyflaglog.log(pyflaglog.WARNING,"Outstanding jobs remain in %s. Removing the case anyway." % case)
                dbh.execute("delete from jobs where arg1=%r and state='processing'",case)
                break
            pyflaglog.log(pyflaglog.INFO, "Waiting for outstanding jobs in case %r to be completed" % case)
        else:
            break

    try:
      #Delete the case from the database
      dbh.delete('meta',DB.expand("property='flag_db' and value=%r" , case),
                 _fast=True)
      dbh.execute("drop database if exists `%s`" ,case)
    except DB.DBError,e:
        pass

    ## Delete the temporary directory corresponding to this case and all its content
    try:
        temporary_dir = "%s/case_%s" % (config.RESULTDIR,case)
        for root, dirs, files in os.walk(temporary_dir,topdown=False):
            for name in files:
                os.remove(join(root, name))
            for name in dirs:
                os.rmdir(join(root, name))

        os.rmdir(temporary_dir)
    except Exception,e:
        print e

    ## Expire any caches we have relating to this case:
    key_re = "%s[/|]?.*" % case

    import pyflag.IO as IO
    import pyflag.Scanner as Scanner

    IO.IO_Cache.expire(key_re)
    DB.DBO.DBH.expire(key_re)
    DB.DBIndex_Cache.expire(key_re)
    try: Scanner.factories.expire(key_re)
    except: pass

class EventHandler:
    """ This is the base class for SQL which needs to be run on various events.

    This base class should be extended when plugins needs to respond to some events.
    """
    def startup(self):
        """ This will be called when pyflag starts up """
        
    def create(self,dbh,case):
        """ This method will be called when a new case is created """

    def init_default_db(self, dbh, case):
        """ This is called on the default database upon first
        installation of pyflag or upgrade of schema.
        """

    def exit(self, dbh, case):
        """ This is called when we are about to exit on the default db
        """

    def reset(self, dbh, case):
        """ This is called when the case is deleted. Its used by
        modules to delete local caches etc.
        """

def post_event(event, case):
    """ A function to post the specifed event to all event handlers """
    try:
        dbh = DB.DBO(case)
    except DB.DBError:
        return
    
    for cls in Registry.EVENT_HANDLERS.classes:
        event_handler = cls()
        
        ## Post the event:
        getattr(event_handler, event)(dbh,case)

import socket,struct

def inet_aton(address):
    return struct.unpack("I", socket.inet_aton(address))[0]

def print_info():
    result = "PyFlag installation information:"
    for heading, registry in (("Scanners", "SCANNERS"),
                              ("VFS File drivers", "VFS_FILES"),
                              ("Shell commands", "SHELL_COMMANDS"),
                              ("File systems", "FILESYSTEMS"),
                              ("Image format handlers", "IMAGES"),
                              ("Column Types", "COLUMN_TYPES"),
                              ("Case Tables", "CASE_TABLES"),
                              ("Magic Handlers", "MAGIC_HANDLERS"),
                              ("Carvers", "CARVERS"),
                              ):
        result += "\n%s:\n%s\n" % (heading, '-' * len(heading))
        registry = getattr(Registry, registry)
        for cls in registry.classes:
            try:
                message =  cls.__doc__.splitlines()[0]
            except: message = cls.__doc__
            result+= "%s: %s\n" % (cls, message)

    return result

class CaseTable:
    name = None
    ## This is an array of: ColumnType Class or instance, argv dict,
    ## Hidden If ColumnType is a class, argv will be used to
    ## instantiate it, otherwise argv are ignored.  If column is
    ## hidden it can not be selected for table construction.
    columns = []
    index = ['inode_id']
    primary = None

    ## These are extra entries in the style of self.columns which will
    ## be available for table construction, but will not be used in
    ## creating the table. This is useful when you want to make the
    ## same column available via a number of different ColumnTypes.
    extras = []

    def bind_columns(self, case):
        """ Returns a list of columns bound to the specified case """
        import pyflag.ColumnTypes as ColumnTypes

        possibles = self.columns + self.extras

        for x in possibles:
            column_cls = x[0]
            args = x[1]
            args['case'] = case
            args['table'] = self.name
            if isinstance(column_cls, ColumnTypes.ColumnType):
                yield column_cls
            else:
                yield column_cls(**args)

    def bind_column(self, case, column_name):
        """ Tries to find column_name in our columns and returns a
        bound (instantiated) column object
        """
        possibles = self.columns + self.extras

        for x in possibles:
            column_cls = x[0]
            args = x[1]
            args['case'] = case
            args['table'] = args.get('table', self.name)
            ## This is a little expensive because we instantiate each
            ## column just in order to check its name. This is
            ## necessary because some columns have a hard coded name
            ## which they set in the constructor (for example
            ## InodeIDType hard codes the name to Inode - so we dont
            ## have to supply it in args all the time).
            e = column_cls(**args)
            if e.name != column_name: continue
            return e

        raise RuntimeError("Column %s not found in table %s" % (
            column_name, self.__class__.__name__))

    def check(self, dbh):
        """ Checks the table in dbh to ensure that all the columns defined are present
        """
        columns = [ c for c in self.instantiate_columns() ]

        try:
            dbh.execute("desc %s", self.name)
        except DB.DBError,e:
            pyflaglog.log(pyflaglog.INFO, "Table %s does not exist in case %s - Creating" % (self.name, dbh.case))
            self.create(dbh)
            return

        existing = [ row['Field'] for row in dbh ]
        
        for c in columns:
            if c.column not in existing:
                pyflaglog.log(pyflaglog.INFO, "In table %s.%s, Column `%s` missing. Adding." % (dbh.case, self.name, c.column))
                try:
                    dbh.execute("alter table %s add %s", self.name, c.create())
                    if c.name in self.index or c.column in self.index:
                        dbh.check_index(c.name)
                except: pass
                
    def instantiate_columns(self):
        import pyflag.ColumnTypes as ColumnTypes
        
        for x in self.columns:
            column_cls = x[0]
            args = x[1]
            if isinstance(column_cls, ColumnTypes.ColumnType):
                c = column_cls
            else:
                c = column_cls(**args)

            c.table = c.table or self.name
            try:
                c.misc = x[2]
            except IndexError:
                c.misc = ''
                
            yield c

    def create(self, dbh):
        """ Returns an SQL CREATE statement from our schema description """
        tmp = []
        indexes = []

        for c in self.instantiate_columns():
            ## is there any extra specified?
            string = c.create()
            try:
                string += " " + c.misc
            except IndexError:
                pass
            
            tmp.append(string)
            if c.name in self.index or c.column in self.index:
                indexes.append(c)

        columns = ',\n'.join(tmp)
        if self.primary:
            columns += ", primary key(`%s`)" % self.primary

        sql = "CREATE TABLE `%s` (%s)" % (self.name, columns)
        dbh.execute("## Creating CaseTable %s" % self)
        dbh.execute(sql)

        ## Check indexes:
        for i in indexes:
            i.make_index(dbh, self.name)

## The following functions are for unicode support and are mostly
## borrowed from django:
def smart_unicode(s, encoding='utf-8', errors='ignore'):
    """
    Returns a unicode object representing 's'. Treats bytestrings using the
    'encoding' codec.
    """
    if not isinstance(s, basestring,):
        if hasattr(s, '__unicode__'):
            s = unicode(s)
        else:
            s = unicode(str(s), encoding, errors)
    elif not isinstance(s, unicode):
        try:
            s = s.decode(encoding, errors)
        except:
            s = s.decode('utf8', errors)
            
    return s

def smart_str(s, encoding='utf-8', errors='strict'):
    """
    Returns a bytestring version of 's', encoded as specified in 'encoding'.
    """
    if not isinstance(s, basestring):
        try:
            return str(s)
        except UnicodeEncodeError:
            return unicode(s).encode(encoding, errors)
    elif isinstance(s, unicode):
        return s.encode(encoding, errors)
    elif s and encoding != 'utf-8':
        return s.decode('utf-8', errors).encode(encoding, errors)
    else:
        return s

import urllib
def iri_to_inline_js(iri):
    """ This converts an IRI to a form which can be included within
    inline javascript. For example:

    <a href='

    """
    result = iri_to_uri(iri).replace("%","%25")
    return result

def escape_unicode_string(string):
    """ Returns a quoted unicode string """
    return urllib.quote(smart_str(string), safe='')

def iri_to_uri(iri):
    """
    Convert an Internationalized Resource Identifier (IRI) portion to a URI
    portion that is suitable for inclusion in a URL.

    This is the algorithm from section 3.1 of RFC 3987.  However, since we are
    assuming input is either UTF-8 or unicode already, we can simplify things a
    little from the full method.

    Returns an ASCII string containing the encoded result.
    """
    # The list of safe characters here is constructed from the printable ASCII
    # characters that are not explicitly excluded by the list at the end of
    # section 3.1 of RFC 3987.
    if iri is None:
        return iri

    return urllib.quote(smart_str(iri), safe='/%[]=:;$&()+,!?*')

def pyflag_escape_string(string):
    result = []
    for x in string:
        if x.isalnum():
            result.append(x)
        else:
            result.append("$%02X" % ord(x))

    return ''.join(result)

def calculate_offset_suffix(offset):
    base = 10
    if offset.startswith("0x"):
        base = 16
        offset = offset[2:]
    elif offset.startswith("\0"):
        base = 8
        offset = offset[2:]
        
    m=re.match("([0-9A-Fa-f]+)([sSkKgGmM]?)", offset)
    if not m:
        raise IOError("I cant understand offset should be an int followed by s,k,m,g")

    suffix=m.group(2).lower()
    multiplier = 1

    if not suffix: multiplier=1
    elif suffix=='k':
        multiplier = 1024
    elif suffix=='m':
        multiplier = 1024**2
    elif suffix=='g':
        multiplier = 1024**3
    elif suffix=='s':
        multiplier = 512

    return int(m.group(1), base)* multiplier

def check_schema():
    """ Checks the schema of all current cases for compliance """
    case_tables = [ c() for c in Registry.CASE_TABLES.classes ]
    pdbh = DB.DBO()
    pdbh.execute("select value from meta where property='flag_db'")
    for row in pdbh:
        try:
            case = row['value']
            dbh = DB.DBO(case)
            
            for c in case_tables:
                c.check(dbh)
                
        except Exception,e:
            pyflaglog.log(pyflaglog.ERROR, "Error: %s" % e)
    
