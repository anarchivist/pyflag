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

""" This module manages access to tables.

It provides simple reports for adding, deleting, and editing records
within tables.
"""
import pyflag.Reports as Reports
import pyflag.FlagFramework as FlagFramework
from pyflag.FlagFramework import Curry, query_type
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.DB as DB
import pyflag.TypeCheck as TypeCheck
import pyflag.FileSystem as FileSystem
import socket,re
import pyflag.Time as Time
import time, textwrap
import pyflag.Registry as Registry

## Some options for various ColumnTypes
config.add_option("PRECACHE_IPMETADATA", default=True,
                  help="Precache whois data for all IP addresses automatically")

class ConstraintError(Exception):
    """ This exception is thrown when a contraint failed when adding or updating a row in the db.
    """
    def __init__(self,result):
        self.result=result

    def __str__(self):
        return self.result.__str__()

class OmitValue(ConstraintError):
    """ This exception can be thrown by constraints to indicate the
    value should be totally ignored.
    """

class date_obj:
    format = "%Y-%m-%d %H:%M:%S"
    def __init__(self, date):
        self.date = date

    def __str__(self):
        try:
            return time.strftime(self.format,self.date)
        except TypeError:
            return self.date.strftime(self.format)

    def __eq__(self, x):
        return x == self.date

    def __le__(self, x):
        return x < self.date

    def __gt__(self, x):
        return x > self.date

try:
    ## This is for parsing ambigous dates:
    import dateutil.parser

    def guess_date(arg):
        try:
            return date_obj(dateutil.parser.parse(arg))
        except ValueError:
            ## Try a fuzzy match
            return date_obj(dateutil.parser.parse(arg, fuzzy=True))

except ImportError:
    import time

    FORMATS = [ "%Y%m%d %H:%M:%S",
                "%Y%m%d %H:%M",
                "%Y%m%d",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d %H:%M",
                "%Y-%m-%d",
                "%d/%m/%Y",
                "%d/%m/%Y %H:%M:%S",
                "%d/%m/%Y %H:%M",
                "%d/%m/%Y %H:%M:%S",                
                "%Y/%m/%d:%H:%M:%S",
                "%a, %d %b %Y %H:%M:%S %Z",
                ]
    def guess_date(string):
        for i in range(len(FORMATS)):
            try:
                f = FORMATS[i]
                result = time.strptime(string, f)
                ## Move the format to the start we are likely to use it again
                if i>0:
                    FORMATS.pop(i)
                    FORMATS.insert(0,f)

                return date_obj(result)
            except ValueError:
                pass

        raise ValueError("Unable to parse date %s" % string)

class TableObj:
    """ An abstract object representing a table in the database """
    table = ""
    key = 'id'
    ## This maps columns to names. Columns that are not listed here
    ## are ignored:
    columns = ()
    _column_keys = ()
    _column_names = ()
    ## This maps columns to functions that are used to generate
    ## specific form elements. If there is no mapping, we
    ## automatically produce textfield. The prototype is:
    
    ##    def function(description, name, results)
    
    ## Where name is the name of the query parameter that will be
    ## generated. query is the query string, and results is the ui to
    ## draw on.
    input_types={}
    ## These are functions run over each column named. They can stop
    ## the operation by throwing an exception or merely return a new
    ## value to be added. The prototype is:

    ## def function(fieldname,proposed_value,id)

    add_constraints = {}
    edit_constraints = {}
    display_actions = {}
    delete_actions = {}
    form_actions = {}

    def __init__(self,case=None,id=None):
        self.id=id
        self._column_keys= [ self.columns[i] for i in range(0,len(self.columns)) if not i % 2 ]
        self._column_names = [ self.columns[i] for i in range(0,len(self.columns)) if i % 2 ]
        self.case = case

    def _make_column_sql(self):
        return self.key+','+','.join([ "`%s` as %r" % (self._column_keys[i],self._column_names[i]) for i in range(len(self._column_keys)) ] + self._column_keys)

    def __getitem__(self,id):
        """ Emulates a table accessor.

        id is the key value which will be retrieved. We return a row record.
        """
        dbh =DB.DBO(self.case)
        dbh.execute("select * from %s where %s=%r",(self.table,self.key,id))
        return dbh.fetch()

    def select(self, **kwargs):
        condition = [ "`%s`=%r" % (k,v.__str__()) for k,v in kwargs.items() if not k.startswith('_') ]
        condition += [ "%s=%s" % (k[1:],v) for k,v in kwargs.items() if k.startswith('_') ]
        sql = " and ".join(condition)
        
        dbh =DB.DBO(self.case)
        ## Although select * is usually frowned upon for the
        ## convenience its worth it here.
        dbh.execute("select * from %s where %s",(self.table,sql))
        return dbh.fetch()

    def edit(self,query,ui):
        """ Updates the row with id given in query[self.table.key] to the values in query """
        ## Make up the SQL Statement. Note that if query is missing a
        ## parameter which we need, we simply do not update it.
        tmp = []
        new_id = query[self.key]
        fields = {}
        
        for k in self._column_keys:
            ## Check for edit constaints:
            callback=self.edit_constraints.get(k,None)
            if not callback:
                callback=getattr(self.__class__,"edit_constraint_%s" % k,None)

            if callback:
                try:
                    replacement=callback(self,k,query.get(k,None),id=new_id,query=query,result=ui)
                    if(replacement):
                        del query[k]
                        query[k]=replacement
                except OmitValue:
                    del query[k]

            try:
                if k=='ip':
                    fields["_ip"]="inet_aton(\"%s\")" % query[k]
                else:
                    fields[k]=query[k]
            except KeyError:
                pass

        dbh = DB.DBO(self.case)
        dbh.update(self.table, where = "%s='%s'" % (self.key, new_id),
                   **fields)

        return new_id

    def add(self,query,ui):
        """ Adds a row given in query[self.table.key] to the table """
        dbh = DB.DBO(self.case)
        dbh.insert(self.table, **{'_'+self.key: 'NULL'})
        ## Work out what will be the next ID if it were to succeed. We
        ## create a placeholder and then remove/replace it later.
        new_id = dbh.autoincrement()
        try:
            result = {self.key:new_id}
            for k in self._column_keys:
                ## Check for add constaints:
                callback=self.add_constraints.get(k,None)
                if not callback:
                    callback=getattr(self.__class__,"add_constraint_%s" % k,None)

                if callback:
                    try:
                        replacement=callback(self,k,query.get(k,None),id=new_id,query=query,result=ui)
                        if(replacement):
                            del query[k]
                            query[k]=replacement
                    except OmitValue:
                        del query[k]

                try:
                    if k=='ip':
                        result["_ip"]="inet_aton(\"%s\")" % query[k]
                    else:
                        result[k]=query[k]
                except KeyError:
                    pass
        finally:
            ## Cleanup the placeholder
            dbh.delete(self.table, "%s=%s" % (self.key, int(new_id)))
            
        dbh.insert(self.table, **result)

        return new_id
        
    def get_name(self,col):
        """ Returns the name description for the column specified """
        return self._column_names[self._column_keys.index(col)]
    
    def form(self,query,result,defaults=None):
        """ Draws a form.

        @arg query: The global query object
        @arg results: The UI to draw in
        @arg defaults: A dictionary of defaults to assign into query
        """
        result.start_table()

        for k,v in zip(self._column_keys,self._column_names):
            ## If there is no input from the user - override the input from the database:
            try:
                query.default(k,defaults[k])
            except:
                pass
                
            ## Try to get the callback from the functional
            ## interface or the class interface:
            cb = self.form_actions.get(k,None)
            if not cb:
                cb = getattr(self.__class__,"form_%s" % k, None)
                
            if cb:
                cb(self,description=v,result=result,variable=k, defaults=defaults)
            else:
                result.textfield(v,k,size=40)

    def add_form(self,query,results, defaults=None):
        """ Generates a form to add a new record in the current table """
        self.form(query,results, defaults)

    def edit_form(self,query,results):
        """ Generates an editing form for the current table """
        id=query[self.key]

        dbh = DB.DBO(self.case)
        dbh.execute("select * from %s where %s=%r",(self.table,self.key,id))
        row=dbh.fetch()
        self.form(query,results,row)

    def delete(self,id,result,commit=False):
        """ This deletes the row with specified id from the table.

        Note that self.delete_actions is run to ensure that database consistancy is maintained. This method actually does the deletion, where show_delete describes what will be deleted but does not actually delete stuff (it uses self.show_deletes). It is up to derived classes to ensure that the two attributes return consistant results.

        If commit is True we really go ahead and delete, otherwise we just write on result what we are trying to do.
        """
        tmp = result.__class__(result)
        tmp.text("Will try to remove %s %s=%s. This record is shown here:" % (self.table,self.key,id),font='bold',color='red')
        result.row(tmp)
        self.show(id,result)
        
        for k,v in zip(self._column_keys,self._column_names):
            if self.delete_actions.has_key(k):
                value = row[k]
                self.delete_actions[k](description=v, variable=k, value=value, ui=result, row=row, id=id)

        if commit:
            dbh = DB.DBO(self.case)
            dbh.delete(self.table, "%s=%r" %( self.key,id))

    def show(self,id,result):
        dbh = DB.DBO(self.case)
        dbh.execute("select * from %s where %s=%r",
                         (self.table,self.key,id))

        row=dbh.fetch()
        if not row:
            tmp=result.__class__(result)
            tmp.text("Error: Record %s not found" % id,color='red')
            result.row(tmp)
            return
        
        result.start_table()
        for k,v in zip(self._column_keys,self._column_names):
            ## If there are any specific display functions we let them
            ## do it here...
            cb = self.display_actions.get(k,None)
            if not cb:
                cb = getattr(self.__class__,"display_%s" % k, None)
                
            if cb:
                cb(self,description=v, variable=k, ui=result, defaults=row)
            else:
                try:
                    tmp = result.__class__(result)
                    tmp.text(row[k],color='red')
                    result.row(v,tmp)
                except KeyError:
                    pass

class DisplayItem(Reports.report):
    """ Displays an item from the table """
    name = 'Generic Display Item'
    table=TableObj
    parameters = {}

    def __init__(self,flag,ui=None):
        self.table = self.table()
        self.parameters[self.table.key]='numeric'
        Reports.report.__init__(self,flag,ui)

        try:
            tablename = self.tblname
        except AttributeError:
            self.tblname = self.table.table

    def display(self,query,result):
        result.heading("%s id %s" % (self.name,query[self.table.key]))
        self.table.show(query[self.table.key],result)

    def form(self,query,result):
        result.textfield("Select key %s" % (self.table.key),self.table.key)

class EditItem(DisplayItem):
    """ Edit a row from a table """

    def __init__(self,flag,ui=None):
        self.parameters = {}
        self.parameters['__submit__']='any'
        DisplayItem.__init__(self,flag,ui)
        ## Add the required fields to the parameters list so the
        ## framework can ensure that they are all satisfied.
        for k in self.table._column_keys:
            self.parameters[k] = 'any'

    def display(self,query,result):
        self.table.case=query.get('case',None)
        try:
            self.table.edit(query,result)
            result.heading("Updated %s" % self.tblname)
        except ConstraintError,e:
            result.heading("Error editing a %s" % self.tblname )
            result.para("Updating record failed because:")
            result.para(e)
            result.para("Press the back button and try again")

    def form(self,query,result):
        self.table.case=query.get('case',None)
        try:
            self.table.edit_form(query,result)
        except KeyError:
            result.textfield("Select key %s" % self.table.key,self.table.key)
    
class AddItem(EditItem):
    """ Add a row to table """
        
    def display(self,query,result):
        self.table.case=query.get('case',None)
        try:
            self.table.add(query,result)
            result.heading("Added a new %s" % self.tblname)
        except ConstraintError,e:
            result.heading("Error Adding %s" % self.tblname )
            result.para("Adding a row failed because:")
            result.para(e)
            result.para("Press the back button and try again")

    def __init__(self,flag,ui=None):
        EditItem.__init__(self,flag,ui)
        self.parameters = { 'submitted':'numeric'}

    def form(self,query,result):
        self.table.case=query.get('case',None)
        result.hidden("submitted","1")
        self.table.add_form(query,result)

import re,struct

## The following are common column types which the parser can
## handle. ColumnTypes can be defined as plugins by extending the
## ColumnTypes base class.
class ColumnType:
    """ Base class for column type searches.

    Tables are just collections of column types. These objects are
    responsible for displaying the values from the column and are used
    to generate SQL.
    """
    ## This contols if the user is able to select it as a columntype
    ## when importing a log file.
    hidden = False
    ignore = False
    
    def __init__(self, name=None,
                 column=None, link='',
                 callback=None, link_pane='self',
                 regex = r"[^\s]+",
                 boundary = r'\s+',
                 escape=True, wrap=True, **kwargs
                 ):
        
        if not name or not column:
            raise RuntimeError("You must set both name and column")
        
        self.name = name
        self.extended_names = [ name ]
        self.column = column
        self.link = link
        self.callback = callback
        self.link_pane = link_pane
        self.regex = re.compile(regex)
        self.regex_str = regex
        self.boundary = re.compile(boundary)
        self.escape = escape
        self.wrap = wrap

    ## These are the symbols which will be treated literally
    symbols = {
        }

    def make_index(self, dbh, table):
        """ Creates an index on table using dbh """
        dbh.check_index(table, self.column)

    def operators(self, context = 'sql'):
        """ Returns a list of operators we support """
        ops = self.symbols.copy()
        if context == 'sql':
            prefix = 'operator_'
        else:
            prefix = "code_"
            
        for m in dir(self):
            if m.startswith(prefix):
                ops[m[len(prefix):]]=m

        return ops

    ## When returning an sql context we expect to get a string
    ## containing the sql to be written to the server. When called
    ## with code context, we expect to get back a function of
    ## prototype: x(row) which evaluates the expression given a dict
    ## row of all the columns in the row.
    def parse(self, column, operator, arg, context='sql'):
        ## Try to find the method which handles this operator. We look
        ## first in symbols and then in a method containing the name
        ## requested:
        if context == 'sql':
            prefix = "operator_"
        else:
            prefix = 'code_'

        if operator in self.symbols:
            ## This has to succeed or there is a programming error.
            method = getattr(self, prefix + self.symbols[operator])
        else:
            try:
                method = getattr(self, prefix + operator)
            except:
                raise RuntimeError("%s is of type %s and has no operator %r.\nDoes it make sense to use this operator on this data?" % (column, ("%s"% self.__class__).split('.')[-1], operator))

        return method(column, operator, arg)

    def escape_column_name(self, column_name):
        if self.escape:
            return '.'.join(["`%s`" % x for x in self.column.split('.')])
        else:
            return self.column

    def code_literal(self, column, operator, arg):
        ## Bit of a hack really:
        return lambda row: eval("%r %s %r" % (row[self.column], operator, arg.__str__()), {})

    def operator_literal(self, column,operator, arg):
        return "%s %s %r" % (self.escape_column_name(self.column),
                             operator, arg)

    def code_equal(self, column, operator, arg):
        ## Make sure our arg is actually an integer:
        return lambda row: row[self.column] == arg

    def operator_equal(self, column, operator, address):
        return self.operator_literal(column, '=', address)
    
    def display(self, value, row, result):
        """ This method is called by the table widget to allow us to
        translate the output from the database to the screen. Note
        that we have access to the entire row (i.e. all the values in
        the query if we need it).
        """
        ## By default just implement a simple callback:
        if self.callback:
            value = self.callback(value)
        elif self.wrap:
            value = textwrap.fill(value.__str__())
            
        if self.link and not self.callback:
            result = result.__class__(result)
            q = self.link.clone()
            q.FillQueryTarget(value)
            result.link(value, q, pane=self.link_pane)
            return result
        
        return value

    def csv(self, value):
        """ This outputs data for csv output"""
        ## We seem to need to escape this for some stupid spreadsheets
        try:
            value.replace("\n","\\n")
            value.replace("\r","\\r")
        except AttributeError:
            # Probably not a string...
            pass

        ## If we have a callback we cant render anything:
        if self.callback:
            return "-"
        else: return value

    def extended_csv(self, value):
        return {self.name:self.csv(value)}

    def create(self):
        """ This needs to generate a create clause for creating this
        table. It is used when we wish to make a table with this
        column type.
        """

    def insert(self, value):
        """ This function returns the sql required to set the name of
        the column to value.

        @returns: (column name, value)

        Note that column name must be preceeded with _ if value needs to be taken literally (not escaped).

        WARNING: It is up to the column type to enforce adequate
        escaping if _ is used. This may be a potential vulnerability
        when loading untrusted log files.

        If None is returned, the value is not inserted into this
        column position, and the columns default value will be used.
        """
        return self.column, value

    def select(self):
        """ Returns the SQL required for selecting from the table. """
        return self.escape_column_name(self.column)

    def column_decorator(self, table, sql, query, result):
        """ Every column type is given the opportunity to decorate its
        table heading
        """
        return self.name

    def log_parse(self, row):
        """ This is called by the log processing to parse the value of
        this column from the row.

        We start parsing at the start of the row. FIXME: Might be
        faster to get passed the offset where to start parsing, so we
        dont need to keep slicing strings.

        We need to return the tuple:

        consumed, name, sql

        Where consumed is the number of bytes consumed from the row.
        name is the name of the column to insert as, sql is the SQL to
        use for insertion - note that if name starts with _ we take
        sql as raw otherwise we escape it.
        """
        ## Try to consume a boundary:
        b = self.boundary.match(row)
        if b:
            row = row[b.end():]
            offset = b.end()
        else:
            offset = 0

        capture = self.regex.match(row)
        if not capture: raise RuntimeError("Unable to match %s on row %r " %
                                           (self.regex_str, row))

        return (capture.end()+offset, self.column, capture.group(0))

### Some common basic ColumnTypes:
class StateType(ColumnType):
    ## This is a list of states that we can take on. Keys are args,
    ## values are sql types.
    hidden = True
    states = {}
    symbols = {
        '=': 'is'
        }

    def __init__(self, name='', column='', link='', callback=None):
        ColumnType.__init__(self, name=name, column=column, link=link, callback=callback)
        self.docs = {'is': """ Matches when the column is of the specified state. Supported states are %s""" % self.states.keys()}

    def code_is(self, column, operator, state):
        for k,v in self.states.items():
            if state.lower()==k:
                return lambda row: row[self.column] == v

        raise RuntimeError("Dont understand state %r. Valid states are %s" % (state,self.states.keys()))
        
    def operator_is(self, column, operator, state):
        for k,v in self.states.items():
            if state.lower()==k:
                return "%s = %r" % (self.escape_column_name(self.column), v)

        raise RuntimeError("Dont understand state %r. Valid states are %s" % (state,self.states.keys()))

    def create(self):
        return "`%s` enum(%s) default NULL" % (self.column, ','.join(["%r"% x for x in self.states.keys()]))

class IntegerType(ColumnType):
    symbols = {
        "=":"equal",
        "!=":"literal",
        "<=": "literal",
        ">=": "literal",
        "<": "literal",
        ">": "literal",
        }

    def code_equal(self, column, operator, arg):
        ## Make sure our arg is actually an integer:
        integer = int(arg)
        return lambda row: int(row[self.column]) == integer

    def create(self):
        return "`%s` int(11) default 0" % self.column

class EditableStringType(ColumnType):
    hidden = True
    def display(self, value, row, result):
        """ This method is called by the table widget to allow us to
        translate the output from the database to the screen. Note
        that we have access to the entire row (i.e. all the values in
        the query if we need it).
        """
        result = result.__class__(result) 
        
        def edit_cb(query, result):
            
            timeline = TimelineObj(case=query['case'])
      
            if 'Update' in query.getarray('__submit__'):
                query['id']=row['id']
                new_id=timeline.edit(query,result)
                return result.refresh(0, query, pane='parent')

            ## Present the user with the form:
            result.start_form(query, pane='self')
            result.heading("Edit Event")
            
            ## Then show the form
            query['id']=row['id']
            timeline.edit_form(query,result)
            result.end_form(value='Update')

        def delete_row_cb(query, result):
            dbh = DB.DBO(query['case'])
            dbh.delete('timeline', "id=%i" % row['id'])
            result.refresh(0, query, pane='parent')

        tmp1 = result.__class__(result)
        tmp2 = result.__class__(result)
        tmp3 = result.__class__(result)
        tmp1.popup(edit_cb, "Edit this string", icon="balloon.png")
        tmp2.popup(delete_row_cb, "Delete this row from the database", icon="delete.png")
        tmp3.text(value, font='typewriter')
        result.row(tmp1, tmp2, tmp3)
        return result

class StringType(ColumnType):
    symbols = {
        "=":"equal",
        "!=":"literal",
        }

    def create(self):
        return "`%s` VARCHAR(255) default NULL" % self.column

    def code_contains(self, column, operator, arg):
        def x(row):
            return arg in row[self.column]
        return x
    
    def operator_contains(self, column, operator, arg):
        """ Matches when the column contains the pattern anywhere. Its the same as placing wildcards before and after the pattern. """
        return self.operator_literal(column , 'like' , "%" + arg + "%")

    def code_matches(self, column, operator, arg):
        regex = arg.replace("%",".*")
        return lambda row: re.match(regex, row[self.column])

    def operator_matches(self, column, operator, arg):
        """ This matches the pattern to the column. Wild cards (%) can be placed anywhere, but if you place it in front of the pattern it could be slower. """
        return self.operator_literal(column , 'like' , arg)

    def code_regex(self, column, operator, arg):
        return lambda row: re.match(arg, row[self.column])

    def operator_regex(self,column,operator,arg):
        """ This applies the regular expression to the column (Can be slow for large tables) """
        return self.operator_literal(column, 'rlike', arg)

class TimestampType(IntegerType):
    """
    This is a timestamp parser.
    ===========================
    
    We can accept a format string to use to parse the timestamp from the log file.
    
    The following directives can be embedded in the FORMAT string.
    They are shown without the optional field width and precision
    specification, and are replaced by the indicated characters in the
    result:

    =========              =====================
    Directive              Meaning                
    ---------              ---------------------              
    %a                     Locale's abbreviated   
                           weekday name.          
    %A                     Locale's full weekday  
                           name.                  
    %b                     Locale's abbreviated   
                           month name.            
    %B                     Locale's full month    
                           name.                  
    %c                     Locale's appropriate   
                           date and time          
                           representation.        
    %d                     Day of the month as a  
                           decimal number         
                           [01,31].               
    %H                     Hour (24-hour clock)   
                           as a decimal number    
                           [00,23].               
    %I                     Hour (12-hour clock)   
                           as a decimal number    
                           [01,12].               
    %j                     Day of the year as a   
                           decimal number         
                           [001,366].             
    %m                     Month as a decimal     
                           number [01,12].        
    %M                     Minute as a decimal    
                           number [00,59].        
    %p                     Locale's equivalent  
                           of either AM or PM.    
    %S                     Second as a decimal  
                           number [00,61].        
    %U                     Week number of the   
                           year (Sunday as the    
                           first day of the       
                           week) as a decimal     
                           number [00,53].  All   
                           days in a new year     
                           preceding the first    
                           Sunday are considered  
                           to be in week 0.       
    %w                     Weekday as a decimal   
                           number [0(Sunday),6].  
    %W                     Week number of the   
                           year (Monday as the    
                           first day of the       
                           week) as a decimal     
                           number [00,53].  All   
                           days in a new year     
                           preceding the first    
                           Monday are considered  
                           to be in week 0.       
    %x                     Locale's appropriate   
                           date representation.   
    %X                     Locale's appropriate   
                           time representation.   
    %y                     Year without century   
                           as a decimal number    
                           [00,99].               
    %Y                     Year with century as   
                           a decimal number.      
    %Z                     Time zone name (no     
                           characters if no time  
                           zone exists).          
    %%                     A literal %          
                           character.             
    =========              =====================
    """
    def __init__(self, name=None, column=None, format="%d/%b/%Y %H:%M:%S",
                 override_year = 0
                 ):
        IntegerType.__init__(self, name, column)
        self.format = format
        self.override_year = int(override_year)

    def create(self):
        return "`%s` TIMESTAMP" % self.column

    def code_after(self, column, operator, arg):
        """ Matches if the time in the column is later than the time
        specified. We try to parse the time formats flexibly if
        possible.
        """
        date_arg = guess_date(arg)
        return lambda row: guess_date(row[self.column]) > date_arg
    
    def operator_after(self, column, operator, arg):
        """ Matches times after the specified time. The time arguement must be given in the format 'YYYY-MM-DD HH:MM:SS' (i.e. Year, Month, Day, Hour, Minute, Second). """
        date_arg = guess_date(arg)
        return "%s > '%s'" % (self.escape_column_name(self.column), date_arg)

    def code_before(self,column, operator, arg):
        date_arg = guess_date(arg)
        return lambda row: guess_date(row[self.column]) <= date_arg
        
    def operator_before(self,column, operator, arg):
        """ Matches times before the specified time. The time arguement must be as described for 'after'."""
        date_arg = guess_date(arg)
        return "%s < '%s'" % (self.escape_column_name(self.column), date_arg)

    def display(self, value, row, result):
        original_query = result.defaults

        ## Do default stuff so we don't break anything:
        ## By default just implement a simple callback:
        self.row = row
        if self.callback:
            value = self.callback(value)
        elif self.link:
            result = result.__class__(result)
            q = self.link.clone()
            q.FillQueryTarget(value.__str__())
            result.link(value, q, pane=self.link_pane)
            return result

        result = result.__class__(result)

        def add_to_timeline_cb(query, result):

            timeline = TimelineObj(case=query['case'])

            ## We got submitted - actually try to do the deed:
            if 'Add to Timeline' in query.getarray('__submit__'):
                result.start_table()

                newEvent = timeline.add(query, result)

                result.para("The following is the new annotated record:")
                timeline.show(newEvent,result)

                result.end_table()
                result.link("Close this window", target=original_query, pane='parent_pane')
                return result

            ## Present the user with the form:
            result.start_form(query, pane='self')
            result.heading("Adding an event at time %s" % value)

            ## First set it up with the info from the table as defaults
            defaultInfo = dict() 
            defaultInfo['time']=value
            defaultInfo['notes']=""
            for infoFromCol in self.row:
                    defaultInfo['notes']+=str(infoFromCol)
                    defaultInfo['notes']+=":"
                    defaultInfo['notes']+=str(row[infoFromCol])
                    defaultInfo['notes']+="     \n"
            
            #query.default('notes', defaultInfo['notes'])
            ## Then show the form
            timeline.add_form(query,result, defaultInfo)
            result.end_form(value='Add to Timeline')

        tmp1 = result.__class__(result)

        ## You can only add to timeline if you are dealing with a case
        if original_query.has_key('case') and value:
            tmp1.popup(add_to_timeline_cb, "Add to Timeline", 
                       icon="stock_timer.png")
            result.row(tmp1, value)
        else:
            result.row(value)

        return result

    def log_parse(self, row):
        t,m = Time.strptime(row, format = self.format)

        if self.override_year:
            t = list(t)
            t[0] = self.override_year
            
        date = time.strftime("%Y-%m-%d %H:%M:%S", t)

        return m.end(), self.column, date

import plugins.LogAnalysis.Whois as Whois

## The following options control how we display IPs within the GUI:
# Would be nice if somewhere we did a count(*) and if whois wasn't there 
# we didn't show this either....
config.add_option("WHOIS_DISPLAY", default=True, 
                  help="Should the WHOIS data be shown within the GUI?")

if Whois.gi_resolver:
    config.add_option("GEOIP_DISPLAY", default=True, 
                      help="Should we show GEOIP data in the normal " \
                      "display of IP addresses? This only works if the " \
                      "GEOIPDIR option is set correctly")
    
if Whois.gi_org_resolver or Whois.gi_isp_resolver:
    config.add_option("EXTENDED_GEOIP_DISPLAY", default=True, 
                      help="Should we show extended GEOIP information? ")
    
class IPType(ColumnType):
    """ Handles creating appropriate IP address ranges from a CIDR specification.

    Code and ideas were borrowed from Christos TZOTZIOY Georgiouv ipv4.py:
    http://users.forthnet.gr/ath/chrisgeorgiou/python/
    """
    def __init__(self, name='', column='', link='', callback=''):
        ColumnType.__init__(self, name=name, column=column,
                            link=link, callback=callback)
        self.extended_names = [name, name + "_geoip_city", name + "_geoip_country", name + "_geoip_org", name + "_geoip_isp", name + "_geoip_lat", name + "_geoip_long"]
    
    # reMatchString: a re that matches string CIDR's
    reMatchString = re.compile(
        r'(\d+)' # first byte must always be given
        r'(?:' # start optional parts
            r'\.(\d+)' # second byte
            r'(?:'#  optionally third byte
                r'\.(\d+)'
                r'(?:' # optionally fourth byte
                    r'\.(\d+)'
                r')?'
            r')?' # fourth byte is optional
        r')?' # third byte is optional too
        r'(?:/(\d+))?$') # and bits possibly

    # masks: a list of the masks indexed on the /network-number
    masks = [0] + [int(-(2**(31-x))) for x in range(32)]

    symbols = {
        '=': 'equal',
        '<': 'literal',
        '>': 'literal',
        '<=': 'literal',
        '>=': 'literal',
        '!=': 'literal',
        }

    def code_equal(self, column, operator, address):
        return lambda row: row[self.column] == address

    def operator_equal(self, column, operator, address):
        return "%s = INET_ATON(%r)" % (self.escape_column_name(self.column), address)

    def literal(self, column, operator, address):
        return "%s %s INET_ATON(%r)" % (self.escape_column_name(self.column), operator, address)

    def extended_csv(self, value):
        #if self.callback: return ["-", "-", "-"]

        value.replace("\n","\\n")
        value.replace("\r","\\r")
       
        geoipdata = Whois.get_all_geoip_data(value)
        
        if geoipdata.has_key("city"):
            returnCity = geoipdata['city'] or "Unknown"
        else:
            returnCity = "Unknown"

        if geoipdata.has_key("country_code3"):
            returnCountry = geoipdata['country_code3'] or "---"
        else:
            returnCountry = "---"
   
        if geoipdata.has_key("org"):
            returnOrg = geoipdata['org'] or "Unknown" 
        else:
            returnOrg = "Unknown"

        if geoipdata.has_key("isp"):
            returnISP = geoipdata['isp'] or "Unknown" 
        else:
            returnISP = "Unknown"

        if geoipdata.has_key("latitude"):
            returnLat = geoipdata['latitude'] or "Unknown" 
        else:
            returnLat = "Unknown"

        if geoipdata.has_key("longitude"):
            returnLong = geoipdata['longitude'] or "Unknown"
        else:
            returnLong = "Unknown"
        
        #self.extended_names = [name, name + "_geoip_city", name + "_geoip_country", name + "_whois_organisation", name + "_geoip_isp", name + "_geoip_lat", name + "_geoip_long"]
        return {self.name:value, 
                self.name + "_geoip_city":returnCity, 
                self.name + "_geoip_country":returnCountry, 
                self.name + "_geoip_org":returnOrg, 
                self.name + "_geoip_isp":returnISP, 
                self.name + "_geoip_lat":returnLat,
                self.name + "_geoip_long":returnLong}

    def code_matches(self, column, operator, address):
        """ Matches the IP address specified exactly """
        return self.code_netmask(column, operator, address)

    def code_netmask(self, column, operator, address):
        """ Matches IP addresses that fall within the specified netmask. Netmask must be provided in CIDR notation or as an IP address (e.g. 192.168.1.1/24)."""        
        numeric_address, broadcast = self.parse_netmask(address)
        def f(row):
            ip = FlagFramework.inet_aton(row[column])
            return ip > numeric_address and ip < broadcast
        return f
        
    def operator_matches(self, column, operator, address):
        """ Matches the IP address specified exactly """
        return self.operator_netmask(column, operator,address)

    def parse_netmask(self, address):
        # Parse arg as a netmask:
        match = self.reMatchString.match(address)
        try:
            if match:
                numbers = [x and int(x) or 0 for x in match.groups()]
                # by packing we throw errors if any byte > 255
                packed_address = struct.pack('4B', *numbers[:4]) # first 4 are in network order
                numeric_address = struct.unpack('!I', packed_address)[0]
                bits = numbers[4] or numbers[3] and 32 or numbers[2] and 24 or numbers[1] and 16 or 8
                mask = self.masks[bits]
                broadcast = (numeric_address & mask)|(~mask)
                return numeric_address, broadcast
            
        except: pass    
        raise ValueError("%s does not look like a CIDR netmask (e.g. 10.10.10.0/24)" % address)
    
    def operator_netmask(self, column, operator, address):
        """ Matches IP addresses that fall within the specified netmask. Netmask must be provided in CIDR notation or as an IP address (e.g. 192.168.1.1/24)."""
        numeric_address, broadcast = self.parse_netmask(address)
        return " ( %s >= %s and %s <= %s ) " % (self.escape_column_name(self.column),
                                                    numeric_address,
                                                    self.escape_column_name(self.column),
                                                    broadcast)

    def operator_whois_country(self, column, operator, country):
        """ Matches the specified country whois string (e.g. AU, US, CA). Note that this works from the whois cache table so you must have allowed complete calculation of whois data when loading the log file or these results will be meaningless. """

        ## We must ensure there are indexes on the right columns or
        ## this query will never finish. This could lead to a delay
        ## the first time this is run...
        dbh=DB.DBO()
        dbh.check_index("whois_cache", "ip")
        dbh.check_index("whois","country")

        return " ( `%s` in (select ip from %s.whois_cache join " \
               "%s.whois on %s.whois.id=%s.whois_cache.id and "\
               "%s.whois.country=%r ) ) " \
               % (self.column, config.FLAGDB, config.FLAGDB, config.FLAGDB,
                  config.FLAGDB, config.FLAGDB, country)

    def code_maxmind_isp_like(self, column, operator, isp):
        """ Returns true if column has an ISP which contains the word isp in it """
        def f(row):
            data = Whois.get_all_geoip_data(row[self.column])
            ## this is not that accurate but close:
            clean_isp = isp.replace('%','.*')
            if 'isp' in data and re.search(clean_isp,data['isp']):
                return True
            else:
                return False

        return f

    def code_maxmind_isp(self, column, operator, isp):
        """ Returns true if column has an ISP which contains the word isp in it """
        return self.code_maxmind_isp_like(column, operator, isp)
    
    def operator_maxmind_isp(self, column, operator, isp):
        """ Matches the specified isp based on maxmind data. Note that works from the whois cache table so you must have allowed complete calculation of whois data when loading the log file or these results will be meaningless. """

        ## We must ensure there are indexes on the right columns or
        ## this query will never finish. This could lead to a delay
        ## the first time this is run...
        dbh=DB.DBO()
        dbh.check_index("whois_cache", "ip")
        dbh.check_index("geoip_isp", "id")

        return " ( `%s` in (select ip from %s.whois_cache join " \
               "%s.geoip_isp on %s.whois_cache.geoip_isp=%s.geoip_isp.id where "\
               "%s.geoip_isp.isp = %r ) ) " \
               % (self.column, config.FLAGDB, config.FLAGDB, config.FLAGDB,
                  config.FLAGDB, config.FLAGDB, isp)

    def operator_maxmind_isp_like(self, column, operator, isp):
        """ Matches the specified isp. Note that works from the whois cache table so you must have allowed complete calculation of whois data when loading the log file or these results will be meaningless. """

        ## We must ensure there are indexes on the right columns or
        ## this query will never finish. This could lead to a delay
        ## the first time this is run...
        dbh=DB.DBO()
        dbh.check_index("whois_cache", "ip")
        dbh.check_index("geoip_isp", "id")

        if not "%" in isp:
            isp = "%%%s%%" % isp

        return " ( `%s` in (select ip from %s.whois_cache join " \
               "%s.geoip_isp on %s.whois_cache.geoip_isp=%s.geoip_isp.id where"\
               " %s.geoip_isp.isp like %r ) ) " \
               % (self.column, config.FLAGDB, config.FLAGDB, config.FLAGDB,
                  config.FLAGDB, config.FLAGDB, isp)

    def code_maxmind_org(self, column, operator, org):
        """ Returns true if column has an ISP which contains the word isp in it """
        def f(row):
            data = Whois.get_all_geoip_data(row[self.column])
            ## this is not that accurate but close:
            clean_isp = org.replace('%','.*')
            if 'org' in data and re.search(clean_isp,data['org']):
                return True
            else:
                return False

        return f

    def code_maxmind_org_like(self, column, operator, org):
        return self.code_maxmind_org( column, operator, org)

    def operator_maxmind_org(self, column, operator, org):
        """ Matches the specified isp. Note that works from the whois cache table so you must have allowed complete calculation of whois data when loading the log file or these results will be meaningless. """

        ## We must ensure there are indexes on the right columns or
        ## this query will never finish. This could lead to a delay
        ## the first time this is run...
        dbh=DB.DBO()
        dbh.check_index("whois_cache", "ip")
        dbh.check_index("geoip_org", "id")

        return " ( `%s` in (select ip from %s.whois_cache join " \
               "%s.geoip_org on %s.whois_cache.geoip_org=%s.geoip_org.id where"\
               " %s.geoip_org.org = %r ) ) " \
               % (self.column, config.FLAGDB, config.FLAGDB, config.FLAGDB,
                  config.FLAGDB, config.FLAGDB, org)

    def operator_maxmind_organisation_like(self, column, operator, org):
        """ Matches the specified organisation. Note that works from the whois cache table so you must have allowed complete calculation of whois data when loading the log file or these results will be meaningless. """

        ## We must ensure there are indexes on the right columns or
        ## this query will never finish. This could lead to a delay
        ## the first time this is run...
        dbh=DB.DBO()
        dbh.check_index("whois_cache", "ip")
        dbh.check_index("geoip_org", "id")

        return " ( `%s` in (select ip from %s.whois_cache join " \
               "%s.geoip_org on %s.whois_cache.geoip_org=%s.geoip_org.id where"\
               " %s.geoip_org.org like %r ) ) " \
               % (self.column, config.FLAGDB, config.FLAGDB, config.FLAGDB,
                  config.FLAGDB, config.FLAGDB, org)

    def code_maxmind_city(self, column, operator, city):
        """ Returns true if column has an ISP which contains the word isp in it """
        def f(row):
            data = Whois.get_all_geoip_data(row[column])
            ## this is not that accurate but close:
            clean_isp = isp.replace('%','.*')
            if 'city' in data and re.search(clean_isp,data['city']):
                return True
            else:
                return False

        return f

    def operator_maxmind_city(self, column, operator, city):
        """ Matches the specified city string (e.g. Canberra, Chicago). Note that this works from the whois cache table so you must have allowed complete calculation of whois data when loading the log file or these results will be meaningless. """

        ## We must ensure there are indexes on the right columns or
        ## this query will never finish. This could lead to a delay
        ## the first time this is run...
        dbh=DB.DBO()
        dbh.check_index("whois_cache", "ip")
        dbh.check_index("geoip_city", "id")

        return " ( `%s` in (select ip from %s.whois_cache join " \
               "%s.geoip_city on %s.whois_cache.geoip_city=%s.geoip_city.id " \
               "where %s.geoip_city.city=%r ) ) " \
               % (self.column, config.FLAGDB, config.FLAGDB, config.FLAGDB,
                  config.FLAGDB, config.FLAGDB, city)

    # TODO - How do we do this if we don't have access to the case name? 
    #
    #def operator_annotatedIPs(self, column, operator, category):
    #    """ Annotated IPs. Show only those IPs that have annotations 
    #       associated with them of a certain category, or all.  """
    #    
    #   ## We must ensure there are indexes on the right columns or
    #   ## this query will never finish. This could lead to a delay
    #   ## the first time this is run...
    #   dbh=DB.DBO()
    #   dbh.check_index("%s.interesting_ips" % self.case, "ip")
    #   if category=="All":
    #      return " ( `%s` in (select ip from %s.interesting_ips) ) " \
    #           % (self.column, self.case)       
    #   else:
    #      return " ( `%s` in (select ip from %s.interesting_ips where " \
    #             " %s.interesting_ips.category = %r) ) " \
    #           % (self.column, self.case, self.case, country)

    def code_maxmind_country(self, column, operator, country):
        def f(row):
            data = Whois.get_all_geoip_data(row[column])
            return data.get("country_code3")==country

        return f

    def operator_maxmind_country(self, column, operator, country):
        """ Matches the specified country string in the GeoIP Database (e.g. FRA, USA, AUS). Note that this works from the whois cache table so you must have allowed complete calculation of whois data when loading the log file or these results will be meaningless. """

        ## We must ensure there are indexes on the right columns or
        ## this query will never finish. This could lead to a delay
        ## the first time this is run...
        dbh=DB.DBO()
        dbh.check_index("whois_cache", "ip")
        dbh.check_index("geoip_country", "id")

        return " ( `%s` in (select ip from %s.whois_cache join " \
               "%s.geoip_country on %s.whois_cache.geoip_country=" \
               "%s.geoip_country.id where %s.geoip_country.country=%r ) ) " \
               % (self.column, config.FLAGDB, config.FLAGDB, config.FLAGDB,
                  config.FLAGDB, config.FLAGDB, country)

    def create(self):
        ## IP addresses are stored as 32 bit integers 
        return "`%s` int(11) unsigned default 0" % self.column

    def select(self):
        ## Upon selection they will be converted to strings:
        return "inet_ntoa(`%s`)" % (self.column)

    def insert(self,value):
        ### When inserted we need to convert them from string to ints
        if config.PRECACHE_IPMETADATA==True:
            Whois.lookup_whois(value)

        return "_"+self.column, "inet_aton(%r)" % value.strip()

    def display(self, value, row, result):
        result = result.__class__(result)

        self.row = row
        original_query=result.defaults
        ## We can only have interesting IPs if we are associated with a case
        ## otherwise (e.g. for previews), it doesn't make sense..
        if original_query.has_key('case'):
            interestingIPs = InterestingIPObj(original_query['case'])
        else:
            interestingIPs = None

        def edit_ips_of_interest_cb(query, result):

            ## We got submitted - actually try to do the deed:
            if 'Edit Note' in query.getarray('__submit__'):
                result.start_table()
                row = interestingIPs.select(_ip='inet_aton(%r)' % value)
                if row:
                    query['id'] = row['id']
                newEvent = interestingIPs.edit(query, result)
                
                result.para("The following is the new annotated record:")
                interestingIPs.show(newEvent,result)
                
                result.end_table()
                result.link("Close this window", target=original_query, pane='parent_pane')
                return result

            ## Present the user with the form:
            result.start_form(query, pane='self')
            result.heading("Adding a note for IP %s" % value)

            row = interestingIPs.select(_ip='inet_aton(%r)' % value)
            if row:
                query['id'] = row['id']

            query['ip']=value
            ## Then show the form
            interestingIPs.edit_form(query,result)
            result.end_form(value='Edit Note')

        def add_to_ips_of_interest_cb(query, result):
            ## We got submitted - actually try to do the deed:
            if 'Add Note' in query.getarray('__submit__'):
                result.start_table()
                newEvent = interestingIPs.add(query, result)
                
                result.para("The following is the new annotated record:")
                interestingIPs.show(newEvent,result)
                
                result.end_table()
                result.link("Close this window", target=original_query, pane='parent_pane')
                return result

            ## Present the user with the form:
            result.start_form(query, pane='self')
            result.heading("Adding a note for IP %s" % value)

            ## First set it up with the info from the table as defaults
            defaultInfo = dict() 
            defaultInfo['ip']=value
            defaultInfo['notes']=""

            defaultInfo['notes'] = "IP Address of Interest"
            
            ## Then show the form
            interestingIPs.add_form(query,result, defaultInfo)
            result.end_form(value='Add Note')

        ## Check if this IP has any notes with it:
        if interestingIPs:
            row = interestingIPs.select(_ip='inet_aton(%r)' % value)
        else:
            row = None

        ## Provide a way for users to save the IP address:
        tmp1 = result.__class__(result)
        
        ## We try to show a whois if possible
        id = Whois.lookup_whois(value)
        tmp2 = result.__class__(result)
        tmp3 = result.__class__(result)
        
        if config.WHOIS_DISPLAY:
            Whois.identify_network(id, value, tmp3)

        try:
            if config.GEOIP_DISPLAY:
                Whois.geoip_resolve(value,tmp3)
        except AttributeError:
            pass

        try:
            if config.EXTENDED_GEOIP_DISPLAY:
                Whois.geoip_resolve_extended(value,tmp3)
        except AttributeError:
            pass

        tmp2.link(tmp3,
                  target=query_type(family="Log Analysis", 
                                    report="LookupIP", address=value),
                  pane='popup')
        result.row(tmp2)

        opts = {}
        if row:
            tmp1.popup(edit_ips_of_interest_cb, 
                       row['notes'], icon="balloon.png")
            opts = {'class': 'match'}
        elif interestingIPs:
            tmp1.popup(add_to_ips_of_interest_cb, 
                       "Add a note about this IP", 
                       icon="treenode_expand_plus.gif")

        if self.link:
            q = self.link.clone()
            q.FillQueryTarget(value.__str__())
            tmp1.link(value, q, pane=self.link_pane)
        else:
            tmp1.text("  ", value, font="bold")

        result.row(tmp1, **opts)
        return result

class InodeType(StringType):
    """ A unified view of inodes """
    hidden = True
    def __init__(self, name='Inode', column='inode', link=None, case=None, callback=None):
        self.case = case
        ColumnType.__init__(self,name,column,link,callback=callback)

    def get_inode(self, inode):
        return inode

    def column_decorator(self, table, sql, query, result):
        case = query['case']

        def browse_cb(query, result):
            try:
                limit = int(query.get('inode_limit',0))
            except: limit = 0

            dbh = DB.DBO(case)
            dbh.cached_execute(sql, limit=limit, length=2)
            row = dbh.fetch()
            if not row:
                result.heading("No inodes matching")
                return
            
            next_row = dbh.fetch()
            inode = self.get_inode(row[self.name])

            annotate = query.get('annotate','no')
            
            if annotate == 'yes':
                query.set('annotate','no')
                result.toolbar(icon='no.png', link = query, pane = 'pane')
            else:
                query.set('annotate','yes')
                result.toolbar(icon='yes.png', link = query, pane = 'pane')

            query.clear('annotate')
                
            new_query = FlagFramework.query_type(family ="Network Forensics",
                                                 report ="ViewFile",
                                                 case   = case,
                                                 inode  =inode)
            
            result.iframe(link = new_query)
            
            new_query = FlagFramework.query_type(family ="Disk Forensics",
                                                 report ="ViewFile",
                                                 case   = case,
                                                 mode   ="Summary",
                                                 inode  = inode)

            result.toolbar(icon = 'view.png', link = new_query, pane='new')

            new_query = query.clone()

            if limit==0:
                result.toolbar(icon = 'stock_left_gray.png')
            else:
                new_query.set('inode_limit', limit-1)
                result.toolbar(icon = 'stock_left.png', link=new_query, pane='self')

            if not next_row:
                result.toolbar(icon = 'stock_right_gray.png')
            else:
                new_query.set('inode_limit', limit + 1)
                result.toolbar(icon = 'stock_right.png', link=new_query, pane='self')
                
        result.toolbar(cb = browse_cb, icon="browse.png",
                       tooltip = "Browse Inodes in table", pane='new')

        return self.name

    def display(self, value, row, result):
        if not value: return ''

        result = result.__class__(result)
        link = FlagFramework.query_type(case=self.case,
                                        family='Disk Forensics',
                                        report='ViewFile',
                                        mode = 'Summary',
                                        inode = value)
        ## This is the table object which is responsible for the
        ## annotate table:
        original_query = result.defaults

        def annotate_cb(query, result):
            # We just close since we have just deleted it
            if query.has_key('delete'):
                del query['delete']
                return result.refresh(0, query, pane='parent')

            annotate = AnnotationObj(case=self.case)
            ## We are dealing with this inode
            del query['inode']
            query['inode'] = value
            ## does a row already exist?
            row = annotate.select(inode=value)
            if row:
                query['id'] = row['id']

            ## We got submitted - actually try to do the deed:
            if 'Annotate' in query.getarray('__submit__'):
                result.start_table()
                if row:
                    new_id=annotate.edit(query,result)
                else:
                    new_id=annotate.add(query,result)

                result.para("The following is the new annotated record:")
                annotate.show(new_id,result)
                
                result.end_table()
                result.link("Close this window", target=original_query, pane='parent')
                return result

            ## Present the user with the form:
            result.start_form(query, pane='self')
            result.heading("Inode %s" % value)
            if row:
                annotate.edit_form(query,result)
            else:
                annotate.add_form(query,result)            

            result.end_form(value='Annotate')

            def del_annotation(query, result):
                dbh = DB.DBO(query['case'])
                dbh.delete('annotate', "inode=%r" % value)

                del query['note']
                del query['category']
                query['delete'] = 'yes'

                result.refresh(0, query, pane='parent')

            result.toolbar(cb=del_annotation, icon='delete.png',tooltip="Click here to delete this annotation")

        ## Check to see if the inode exists at all:
        dbh = DB.DBO(self.case)
        dbh.execute("select inode from inode where inode.inode = %r", value)
        if not dbh.fetch(): return ''

        annotate = AnnotationObj(case=self.case)
        row = annotate.select(inode=value)
        tmp1 = result.__class__(result)
        tmp2 = result.__class__(result)
        if row:
            tmp1.popup(annotate_cb, row['note'], icon="balloon.png")
        else:
            tmp1.popup(annotate_cb, "Annotate", icon="pen.png")

        if len(value)> 15:
            value1="..%s" % value[-13:]
        else:
            value1 = value
        tmp2.link(value1, tooltip = value, target=link)
        result.row(tmp1,tmp2)
        return result

    def operator_annotated(self, column, operator, pattern):
        """ This operator selects those inodes with pattern matching their annotation """
        return '`%s`=(select annotate.inode from annotate where note like "%%%s%%")' % (self.column, pattern)

## This is an example of using the table object to manage a DB table
import TableActions

class InterestingIPObj(TableObj):
    table = "interesting_ips"
    columns = (
        'ip', 'IP Address',
        'notes','Notes',
        'category', 'category',
        )

    add_constraints = {
        'category': TableActions.selector_constraint,
        }

    edit_constraints = {
        'category': TableActions.selector_constraint,
        }

    def __init__(self, case=None, id=None):
        self.form_actions = {
            'notes': TableActions.textarea,
            'category': Curry(TableActions.selector_display,
                              table='interesting_ips', field='category', case=case),
            }
        self.case=case
        self.key='id'
        TableObj.__init__(self,case,id)

    def show(self,id,result):
        dbh = DB.DBO(self.case)
        dbh.execute("select * from %s where %s=%r",
                         (self.table,self.key,id))

        row=dbh.fetch()
        dbh.execute("select inet_ntoa(ip) as ip from %s where %s=%r", 
                                (self.table, self.key, id))
        iprow=dbh.fetch()
        row['ip']=iprow['ip']

        if not row:
            tmp=result.__class__(result)
            tmp.text("Error: Record %s not found" % id,color='red')
            result.row(tmp)
            return
        result.start_table()
        for k,v in zip(self._column_keys,self._column_names):
            ## If there are any specific display functions we let them
            ## do it here...
            cb = self.display_actions.get(k,None)
            if not cb:
                cb = getattr(self.__class__,"display_%s" % k, None)
                
            if cb:
                cb(self,description=v, variable=k, ui=result, defaults=row)
            else:
                try:
                    tmp = result.__class__(result)
                    tmp.text(row[k],color='red')
                    result.row(v,tmp)
                except KeyError:
                    pass
#    def add(self,query,ui):
#        """ Adds a row given in query[self.table.key] to the table """
#        dbh = DB.DBO(self.case)
#        dbh.insert(self.table, **{'_'+self.key: 'NULL'})
#        ## Work out what will be the next ID if it were to succeed. We
#        ## create a placeholder and then remove/replace it later.
#        new_id = dbh.autoincrement()
#        try:
#            result = {self.key:new_id}
#            for k in self._column_keys:
#                try:
#                    result[k]=query[k]
#                except KeyError:
#                    pass
#        finally:
#            ## Cleanup the placeholder
#            dbh.delete(self.table, "%s=%r" % (self.key, int(new_id)))
#            
#        dbh.insert(self.table, **result)
#
#        return new_id

class TimelineObj(TableObj):
    table = "timeline"
    columns = (
        'time', 'Time',
        'notes','Notes',
        'category', 'category',
        )

    add_constraints = {
        'category': TableActions.selector_constraint,
        }

    edit_constraints = {
        'category': TableActions.selector_constraint,
        }

    def __init__(self, case=None, id=None):
        self.form_actions = {
            'notes': TableActions.textarea,
            'category': Curry(TableActions.selector_display,
                              table='timeline', field='category', case=case),
            }
        self.case=case
        TableObj.__init__(self,case,id)


class AnnotationObj(TableObj):
    table = "annotate"
    columns = (
        'inode', 'Inode', 
        'note','Notes', 
        'category', 'category',
        )

    add_constraints = {
        'category': TableActions.selector_constraint,
        }

    edit_constraints = {
        'category': TableActions.selector_constraint,
        }

    def __init__(self, case=None, id=None):
        self.form_actions = {
            'note': TableActions.textarea,
            'category': Curry(TableActions.selector_display,
                              table='annotate', field='category', case=case),
            }

        TableObj.__init__(self,case,id)

class InodeIDType(InodeType):
    def parse(self, column, operator,arg, context = 'sql'):
        column = self.column
        self.column = 'inode'
        
        result = "%s in (select %s from inode where %s)" % (column, column,
                                                            InodeType.parse(self, column, operator, arg))
        self.column = column
        return result

    def get_inode(self, inode_id):
        fsfd = FileSystem.DBFS(self.case)
        inode = fsfd.lookup(inode_id=inode_id)
        return inode

    def display(self, value, row, result):
        inode = self.get_inode(value)
        return InodeType.display(self,inode,row,result)

class FilenameType(StringType):
    hidden = True
    def __init__(self, name='Filename', inode_id='inode_id',
                 basename=False, table=None,
                 link=None, link_pane=None, case=None):
        if not link:
            link = query_type(case=case,
                              family='Disk Forensics',
                              report='Browse Filesystem',
                              __target__='open_tree',open_tree="%s")

        ## This is true we only display the basename
        self.table = table
        self.basename = basename
        ColumnType.__init__(self,name=name, column=inode_id,
                            link=link, link_pane=link_pane)

    def display(self, value, row, result):
        if row['link']:
            tmp = result.__class__(result)
            tmp.text("%s\n->%s" % (value, row['link']), style="red")
            value = tmp
            
        return ColumnType.display(self, value, row, result)

    def select(self):
        if self.basename:
            return "(select link from file where inode_id=%s.inode_id limit 1) as link," % self.table + \
                   "(select name from file where inode_id=%s.inode_id limit 1)" % self.table
        else:
            return "(select link from file where inode_id=%s.inode_id limit 1) as link," % self.table + \
                   "(select concat(path,name) from file where inode_id=%s.inode_id limit 1)" % self.table
    
    ## FIXME: implement filename globbing operators - this should be
    ## much faster than regex or match operators because in marches,
    ## the SQL translates to 'where concat(path,name) like "..."'. With
    ## a globbing operator it should be possible to split the glob
    ## into directory components and therefore create SQL specifically
    ## using path and name.
    def operator_glob(self, column, operator, pattern):
        """ Performs a glob operation on the Virtual file system. Wildcards are * and ?"""
        directory,filename = os.path.split(pattern)
        sql = ''
        if directory:
            pass

    def operator_literal(self, column, operator, pattern):
        return "`%s` in (select inode_id from file where concat(file.path, file.name) %s %r)" % (self.column, operator, pattern) 

class InodeInfo(StringType):
    """ Displays inode information from inode_id """
    hidden = True
    def __init__(self, name='Size', inode_id='inode_id', field='size',
                 table=None,
                 link=None, link_pane=None, case=None):

        ## This is true we only display the basename
        self.table = table
        self.field = field
        ColumnType.__init__(self,name=name, column=inode_id,
                            link=link, link_pane=link_pane)

    def select(self):
        return "(select `%s` from inode where inode_id=%s.inode_id limit 1)" % (self.field, self.table)
    
    def operator_literal(self, column, operator, pattern):
        return "`%s` in (select inode_id from inode where `%s` %s %r)" % (self.column, self.field, operator, pattern) 

class DeletedType(StateType):
    """ This is a column type which shows deleted inodes graphically
    """
    hidden = True
    states = {'deleted':'deleted', 'allocated':'alloc'}
              
    def display(self,value, row, result):
        """ Callback for rendering deleted items """
        tmp=result.__class__(result)
        if value=='alloc':
            tmp.icon("yes.png")
        elif value=='deleted':
            tmp.icon("no.png")
        else:
            tmp.icon("question.png")

        return tmp

class BinaryType(StateType):
    """ This type defines fields which are either true or false """
    states = {'true':'1', 'false':'0', 'set': 1, 'unset':0 }
    def display(self,value, row,result):
        if value:
            return "*"
        else:
            return " "

class CounterType(IntegerType):
    """ This is used to count the total numbers of things (in a group by) """
    def __init__(self, name=None):
        IntegerType.__init__(self, name=name, column='count')
        
    def select(self):
        return "count(*)"

class PacketType(IntegerType):
    """ A Column type which links directly to the packet browser """
    def __init__(self, name, column, case):
        IntegerType.__init__(self, name=name, column=column,
                             link = query_type(family='Network Forensics',
                                               report="View Packet",
                                               case=case,
                                               __target__='id'))

## Unit tests for the column types.
import unittest,re

class ColumnTypeTests(unittest.TestCase):
    """ Column Types """
    def setUp(self):
        import pyflag.UI as UI
        
        self.ui = UI.GenericUI()

        self.elements = [ IntegerType('IntegerType',column='table.integer_type'),
                          StringType('StringType',column='foobar.string_type'),
                          DeletedType('DeletedType', column='deleted'),
                          TimestampType('TimestampType','timestamp'),
                          IPType('IPType','source_ip'),
                          InodeType('InodeType','inode'),
                          FilenameType('FilenameType'),
                          ]
        self.tablename = 'dummy'

    def generate_sql(self, filter):
        sql = self.ui._make_sql(elements = self.elements, filter_elements=self.elements,
                                 table = self.tablename, case=None, filter = filter)
        ## We are only interested in the where clause:
        match = re.search("where \((.*)\) order", sql)
        return match.group(1)
        
    def test05FilteringTest(self):
        """ Test filters on columns """
        self.assertEqual(self.generate_sql("'IntegerType' > 10"),
                         "(1) and (`table`.`integer_type` > '10')")
        
        self.assertEqual(self.generate_sql("'StringType' contains 'Key Word'"),
                         "(1) and (`foobar`.`string_type` like '%Key Word%')")

        self.assertEqual(self.generate_sql("'StringType' matches 'Key Word'"),
                         "(1) and (`foobar`.`string_type` like 'Key Word')")

        self.assertEqual(self.generate_sql("'StringType' regex '[a-z]*'"),
                         "(1) and (`foobar`.`string_type` rlike '[a-z]*')")

        self.assertEqual(self.generate_sql("'DeletedType' is allocated"),
                         "(1) and (`deleted` = 'alloc')")

        self.assertRaises(RuntimeError, self.generate_sql, ("'DeletedType' is foobar")),
        self.assertEqual(self.generate_sql("'TimestampType' after 2005-10-10"),
                         "(1) and (`timestamp` > '20051010 00:00:00')")

        self.assertEqual(self.generate_sql("'IPType' netmask 10.10.10.1/24"),
                         "(1) and ( ( `source_ip` >= 168430081 and `source_ip` <= 168430335 ) )")
        
        self.assertEqual(self.generate_sql("'InodeType' annotated FooBar"),
                         '(1) and (`inode`=(select annotate.inode from annotate where note like "%FooBar%"))')

        ## Joined filters:
        self.assertEqual(self.generate_sql("InodeType contains 'Z|' and TimestampType after 2005-10-10"),
                         "(1) and (`inode` like '%Z|%' and `timestamp` > '20051010 00:00:00')")
        self.assertEqual(self.generate_sql("InodeType contains 'Z|' or TimestampType after 2005-10-10 and IntegerType > 5"),
                         "(1) and (`inode` like '%Z|%' or `timestamp` > '20051010 00:00:00' and `table`.`integer_type` > '5')")
        self.assertEqual(self.generate_sql("(InodeType contains 'Z|' or TimestampType after 2005-10-10) and IntegerType > 5"),
                         "(1) and (( `inode` like '%Z|%' or `timestamp` > '20051010 00:00:00' ) and `table`.`integer_type` > '5')")

    def test10CreateTable(self):
        """ Test table creation """
        dbh = DB.DBO()
        
        ## Check to see if the table create code is valid sql:
        dbh.execute("create temporary table foobar_001 (%s)", (
            ',\n'.join([ x.create() for x in self.elements])
            ))
