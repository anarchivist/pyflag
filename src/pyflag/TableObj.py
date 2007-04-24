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
#  Version: FLAG $Version: 0.84RC1 Date: Fri Feb  9 08:22:13 EST 2007$
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
        dbh.execute("select %s from %s where %s=%r",(self._make_column_sql(),self.table,self.key,id))
        return dbh.fetch()

    def select(self, **kwargs):
        sql = " and ".join(["%s=%r" % (k,v) for k,v in kwargs.items()])
        dbh =DB.DBO(self.case)
        dbh.execute("select %s from %s where %s",(self._make_column_sql(),self.table,sql))
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
                fields[k]=query[k]
            except KeyError:
                pass

        dbh = DB.DBO(self.case)
        dbh.update(self.table, where = "%s=%r" % (self.key, new_id),
                   **fields)

        return new_id

    def add(self,query,ui):
        """ Adds a row given in query[self.table.key] to the table """
        dbh = DB.DBO(self.case)
        dbh.insert(self.table, **{self._column_keys[0]: 'NULL'})
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
                    result[k]=query[k]
                except KeyError:
                    pass
        finally:
            ## Cleanup the placeholder
            dbh.delete(self.table, "%s=%r" % (self.key, int(new_id)))
            
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
            if defaults and not query.has_key(k):
                try:
                    query[k]=defaults[k]
                except KeyError:
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
        self.form(query,results,defaults)

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
    def __init__(self, name='', column='', link='', sql=None, callback=None, link_pane='self'):
        self.name = name
        self.column = column
        self.link = link
        self.callback = callback
        self.link_pane = link_pane
        if sql:
            self.sql = sql
        else:
            self.sql = column

    ## These are the symbols which will be treated literally
    symbols = {
        }

    def operators(self):
        """ Returns a list of operators we support """
        ops = self.symbols.copy()
        for m in dir(self):
            if m.startswith("operator_"):
                ops[m[len("operator_"):]]=m

        return ops

    def parse(self, column, operator, arg):
        ## Try to find the method which handles this operator. We look
        ## first in symbols and then in a method containing the name
        ## requested:
        if self.symbols.has_key(operator):
            ## This has to succeed or there is a programming error.
            method = getattr(self, self.symbols[operator])
        else:
            try:
                method = getattr(self, "operator_"+operator)
            except:
                raise RuntimeError("%s is of type %s and has no operator %r. Does it make sense to use this operator on this data?" % (column, ("%s"% self.__class__).split('.')[-1], operator))

        return method(column, operator, arg)

    def literal(self, column,operator, arg):
        return "%s %s %r" % (self.column, operator, arg)
    
    def display(self, value, row, result):
        """ This method is called by the table widget to allow us to
        translate the output from the database to the screen. Note
        that we have access to the entire row (i.e. all the values in
        the query if we need it).
        """
        ## By default just implement a simple callback:
        if self.callback:
            value = self.callback(value)
        elif self.link:
            result = result.__class__(result)
            q = self.link.clone()
            q.FillQueryTarget(value.__str__())
            result.link(value, q, pane=self.link_pane)
            return result
        
        return value

    def csv(self, value):
        """ This outputs data for csv output"""
        ## We seem to need to escape this for some stupid spreadsheets
        value.replace("\n","\\n")
        value.replace("\r","\\r")

        ## If we have a callback we cant render anything:
        if self.callback:
            return "-"
        else: return value

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
        return self.sql or '.'.join(["`%s`" % x for x in self.column.split('.')])

    def column_decorator(self, table, result):
        """ Every column type is given the opportunity to decorate its
        table heading
        """

### Some common basic ColumnTypes:
class StateType(ColumnType):
    ## This is a list of states that we can take on. Keys are args,
    ## values are sql types.
    states = {}
    symbols = {
        '=': 'operator_is'
        }

    def __init__(self, name='', column='', link='', callback=None):
        ColumnType.__init__(self, name=name, column=column, link=link, callback=callback)
        self.docs = {'operator_is': """ Matches when the column is of the specified state. Supported states are %s""" % self.states.keys()}
        
    def operator_is(self, column, operator, state):
        for k,v in self.states.items():
            if state.lower()==k:
                return "%s = %r" % (self.column, v)

        raise RuntimeError("Dont understand state %r. Valid states are %s" % (state,self.states.keys()))

    def create(self):
        return "`%s` enum(%s) default NULL" % (self.column, ','.join(["%r"% x for x in self.states.keys()]))

class IntegerType(ColumnType):
    symbols = {
        "=":"literal",
        "!=":"literal",
        "<=": "literal",
        ">=": "literal",
        "<": "literal",
        ">": "literal",
        }

    def create(self):
        return "`%s` int(11) default 0" % self.column

class EditableStringType(ColumnType):
    def display(self, value, row, result):
        """ This method is called by the table widget to allow us to
        translate the output from the database to the screen. Note
        that we have access to the entire row (i.e. all the values in
        the query if we need it).
        """
        ## By default just implement a simple callback:
        if self.callback:
            value = self.callback(value)
        elif self.link:
            result = result.__class__(result)
            q = self.link.clone()
            q.FillQueryTarget(value.__str__())
            result.link(value, q, pane=self.link_pane)
            return result
        
        result = result.__class__(result) 
        
        def edit_cb(query, result):
            
            timeline = TimelineObj(case=query['case'])
      
            if 'Update' in query.getarray('__submit__'):
                query['id']=row['id']
                new_id=timeline.edit(query,result)
                return result.refresh(0, query, pane='parent')

            ## Present the user with the form:
            result.start_form(query, pane='self')
            result.heading("Edit string %s" % value)
            
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
        tmp1.popup(edit_cb, "Edit this string", icon="balloon.png")
        tmp2.popup(delete_row_cb, "Delete this row from the database", icon="delete.png")
        result.row(tmp1, tmp2, value)
        return result

class StringType(ColumnType):

    Symbols = {
        "=":"literal",
        "!=":"literal",
        }

    def create(self):
        return "`%s` VARCHAR(255) default NULL" % self.column

    def operator_contains(self, column, operator, arg):
        """ Matches when the column contains the pattern anywhere. Its the same as placing wildcards before and after the pattern. """
        return '%s like %r' % (self.select(), "%" + arg + "%")

    def operator_matches(self, column, operator, arg):
        """ This matches the pattern to the column. Wild cards (%) can be placed anywhere, but if you place it in front of the pattern it could be slower. """
        return '%s like %r' % (self.column, arg)

    def operator_regex(self,column,operator,arg):
        """ This applies the regular expression to the column (Can be slow for large tables) """
        return '%s rlike %r' % (self.column, arg)


class TimestampType(IntegerType):
    def create(self):
        return "`%s` TIMESTAMP" % self.column
    
    def operator_after(self, column, operator, arg):
        """ Matches times after the specified time. The time arguement must be given in the format 'YYYY-MM-DD HH:MM:SS' (i.e. Year, Month, Day, Hour, Minute, Second). """
        ## FIXME Should parse arg as a date - for now pass though to mysql
        return "%s > %r" % (self.column, arg)

    def operator_before(self,column, operator, arg):
        """ Matches times before the specified time. The time arguement must be as described for 'after'."""
        ## FIXME Should parse arg as a date
        return "%s < %r" % (self.column, arg)

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
                    defaultInfo['notes']+="   "
            
    
            ## Then show the form
            timeline.add_form(query,result,defaultInfo)
            result.end_form(value='Add to Timeline')

        tmp1 = result.__class__(result)
        tmp1.popup(add_to_timeline_cb, "Add to Timeline", icon="treenode_expand_plus.gif")
        result.row(tmp1, value)
        return result



import plugins.LogAnalysis.Whois as Whois

class IPType(ColumnType):
    """ Handles creating appropriate IP address ranges from a CIDR specification.

    Code and ideas were borrowed from Christos TZOTZIOY Georgiouv ipv4.py:
    http://users.forthnet.gr/ath/chrisgeorgiou/python/
    """
    def __init__(self, name='', column='', link='', callback=''):
        ColumnType.__init__(self, name=name, column=column,
                            link=link, callback=callback)
        
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
        '=': 'literal',
        '<': 'literal',
        '>': 'literal',
        '<=': 'literal',
        '>=': 'literal',
        '!=': 'literal',
        }

    def literal(self, column, operator, address):
        return "%s %s INET_ATON(%r)" % (self.column, operator, address)

    def operator_matches(self, column, operator, address):
        """ Matches the IP address specified exactly """
        return self.operator_netmask(column, operator,address)

    def operator_netmask(self, column, operator, address):
        """ Matches IP addresses that fall within the specified netmask. Netmask must be provided in CIDR notation or as an IP address (e.g. 192.168.1.1/24)."""
        # Parse arg as a netmask:
        match = self.reMatchString.match(address)
        try:
            if not match:
                raise Exception
            else:
                    numbers = [x and int(x) or 0 for x in match.groups()]
                    # by packing we throw errors if any byte > 255
                    packed_address = struct.pack('4B', *numbers[:4]) # first 4 are in network order
                    numeric_address = struct.unpack('!I', packed_address)[0]
                    bits = numbers[4] or numbers[3] and 32 or numbers[2] and 24 or numbers[1] and 16 or 8
                    mask = self.masks[bits]
                    broadcast = (numeric_address & mask)|(~mask)
        except:
            raise ValueError("%s does not look like a CIDR netmask (e.g. 10.10.10.0/24)" % address)
        
        return " ( `%s` >= %s and `%s` <= %s ) " % (self.column, numeric_address, self.column, broadcast)

    def create(self):
        ## IP addresses are stored as 32 bit integers 
        return "`%s` int(11) unsigned default 0" % self.column

    def select(self):
        ## Upon selection they will be converted to strings:
        return "inet_ntoa(`%s`)" % self.column

    def insert(self,value):
        ### When inserted we need to convert them from string to ints
        return "_"+self.column, "inet_aton(%r)" % value

    def display(self, value, row, result):
        ## Provide a way for users to save the IP address:
        
        
        ## We try to show a whois if possible
        id = Whois.lookup_whois(value)
        result = result.__class__(result)
        result.link(Whois.identify_network(id) + "<br>" + Whois.geoip_resolve(value),
                    target=query_type(family="Log Analysis", report="LookupIP", address=value),
                    pane='popup')
        result.text("\n%s" %value)
        return result

class InodeType(StringType):
    """ A unified view of inodes """
    def __init__(self, name='Inode', column='inode', link=None, case=None, callback=None):
        self.case = case
        ColumnType.__init__(self,name,column,link,callback=callback)

    def display(self, value, row, result):
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

        annotate = AnnotationObj(case=self.case)
        row = annotate.select(inode=value)
        tmp1 = result.__class__(result)
        tmp2 = result.__class__(result)
        if row:
            tmp1.popup(annotate_cb, row['note'], icon="balloon.png")
        else:
            tmp1.popup(annotate_cb, "Annotate", icon="pen.png")

        tmp2.link(value, target=link)
        result.row(tmp1,tmp2)
        return result

    def operator_annotated(self, column, operator, pattern):
        """ This operator selects those inodes with pattern matching their annotation """
        return '%s=(select annotate.inode from annotate where note like "%%%s%%")' % (self.column, pattern)

## This is an example of using the table object to manage a DB table
import TableActions


class TimelineObj(TableObj):
    table = "timeline"
    columns = (
        'id', 'id',
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
    def display(self, value, row, result):
        fsfd = FileSystem.DBFS(self.case)
        inode = fsfd.lookup(inode_id=value)
        return InodeType.display(self,inode,row,result)

class FilenameType(StringType):
    def __init__(self, name='Filename', filename='name', path='path', case=None):
        link = query_type(case=case,
                          family='Disk Forensics',
                          report='Browse Filesystem',
                          __target__='open_tree',open_tree="%s")
        self.path = path
        self.filename = filename
        ColumnType.__init__(self,name, None,
                            link=link)

    def select(self):
        return "concat(`%s`,`%s`)" % (self.path,self.filename)
    
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
#            sql += "%s rlike %r" % (self.path, glob_re(

class DeletedType(StateType):
    """ This is a column type which shows deleted inodes graphically
    """
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
                         "(1) and (table.integer_type > '10')")
        
        self.assertEqual(self.generate_sql("'StringType' contains 'Key Word'"),
                         "(1) and (foobar.string_type like '%Key Word%')")

        self.assertEqual(self.generate_sql("'StringType' matches 'Key Word'"),
                         "(1) and (foobar.string_type like 'Key Word')")

        self.assertEqual(self.generate_sql("'StringType' regex '[a-z]*'"),
                         "(1) and (foobar.string_type rlike '[a-z]*')")

        self.assertEqual(self.generate_sql("'DeletedType' is allocated"),
                         "(1) and (deleted = 'alloc')")

        self.assertRaises(RuntimeError, self.generate_sql, ("'DeletedType' is foobar")),
        self.assertEqual(self.generate_sql("'TimestampType' after 2005-10-10"),
                         "(1) and (timestamp > '2005-10-10')")

        self.assertEqual(self.generate_sql("'IPType' netmask 10.10.10.1/24"),
                         "(1) and ( ( `source_ip` >= 168430081 and `source_ip` <= 168430335 ) )")
        
        self.assertEqual(self.generate_sql("'InodeType' annotated FooBar"),
                         '(1) and (inode=(select annotate.inode from annotate where note like "%FooBar%"))')

        ## Joined filters:
        self.assertEqual(self.generate_sql("InodeType contains 'Z|' and TimestampType after 2005-10-10"),
                         "(1) and (inode like '%Z|%' and timestamp > '2005-10-10')")
        self.assertEqual(self.generate_sql("InodeType contains 'Z|' or TimestampType after 2005-10-10 and IntegerType > 5"),
                         "(1) and (inode like '%Z|%' or timestamp > '2005-10-10' and table.integer_type > '5')")
        self.assertEqual(self.generate_sql("(InodeType contains 'Z|' or TimestampType after 2005-10-10) and IntegerType > 5"),
                         "(1) and (( inode like '%Z|%' or timestamp > '2005-10-10' ) and table.integer_type > '5')")

    def test10CreateTable(self):
        """ Test table creation """
        dbh = DB.DBO()
        
        ## Check to see if the table create code is valid sql:
        dbh.execute("create temporary table foobar_001 (%s)", (
            ',\n'.join([ x.create() for x in self.elements])
            ))
