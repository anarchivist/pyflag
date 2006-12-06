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
#  Version: FLAG $Version: 0.82 Date: Sat Jun 24 23:38:33 EST 2006$
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
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.DB as DB
import pyflag.TypeCheck as TypeCheck

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
        return ','.join([ "`%s` as %r" % (self._column_keys[i],self._column_names[i]) for i in range(len(self._column_keys)) ] + self._column_keys)

    def __getitem__(self,id):
        """ Emulates a table accessor.

        id is the key value which will be retrieved. We return a row record.
        """
        dbh =DB.DBO(self.case)
        dbh.execute("select %s from %s where %s=%r",(self._make_column_sql(),self.table,self.key,id))
        return dbh.fetch()

    def edit(self,query,ui):
        """ Updates the row with id given in query[self.table.key] to the values in query """
        ## Make up the SQL Statement. Note that if query is missing a
        ## parameter which we need, we simply do not update it.
        tmp = []
        new_id = query[self.key]
        
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
                tmp.append("%s=%r" % (k,query[k]))
            except KeyError:
                pass

        dbh = DB.DBO(self.case)
        dbh.execute("UPDATE %s set %s where %s=%r ",(self.table,
                         ','.join(tmp),
                         self.key, new_id))
        
        ui.para("The following is the new record:")
        self.show(new_id,ui)

    def add(self,query,ui):
        """ Adds a row given in query[self.table.key] to the table """
        dbh = DB.DBO(self.case)
        dbh.insert(self.table, **{self._column_keys[0]: 'NULL'})
        ## Work out what will be the next ID if it were to succeed. We
        ## create a placeholder and then remove/replace it later.
        new_id = dbh.autoincrement()
        try:
            result=[]
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
                    result.append("%s=%r" % (k,query[k]))
                except KeyError:
                    pass
        finally:
            ## Cleanup the placeholder
            dbh.execute("delete from %s where %s=%r", (self.table, self.key, new_id))
                        
        dbh.execute("insert into %s set %s=%r,%s ",(
                self.table,
                self.key, new_id,
                ",".join(result),
                ))
        
    def get_name(self,col):
        """ Returns the name description for the column specified """
        return self._column_names[self._column_keys.index(col)]
    
    def form(self,query,results,defaults=None):
        """ Draws a form.

        @arg query: The global query object
        @arg results: The UI to draw in
        @arg defaults: A dictionary of defaults to assign into query
        """
        results.start_table()
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
                cb(self,description=v,ui=results,variable=k, defaults=defaults)
            else:
                results.textfield(v,k,size=40)

    def add_form(self,query,results):
        """ Generates a form to add a new record in the current table """
        self.form(query,results)

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
            dbh.execute("delete from %s where %s=%r",
                             ( self.table,self.key,id))

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
        self.parameters['submit']='any'
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
    def __init__(self, name='', sql='', link='', callback=''):
        self.name = name
        self.sql = sql
        self.link = link
        if callback:
            self.callback = callback
        ## Not specified - the identity callable
        else: self.callback=lambda x: x

    ## These are the symbols which will be treated literally
    symbols = {
        "=":"literal",
        "!=":"literal",
        "<=": "literal",
        ">=": "literal",
        "<": "literal",
        ">": "literal",
        }

    def operators(self):
        """ Returns a list of operators we support """
        ops = self.symbols.copy()
        for m in dir(self):
            if m.startswith("operator_"):
                ops[m[len("operator_"):]]=1

        return ops.keys()

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
        return "%s %s %r" % (self.sql, operator, arg)

    def operator_contains(self, column, operator, arg):
        return '%s like %r' % (self.sql, "%" + arg + "%")

    def operator_matches(self, column, operator, arg):
        return '%s like %r' % (self.sql, arg)

    def display(self, value, row, result):
        """ This method is called by the table widget to allow us to
        translate the output from the database to the screen. Note
        that we have access to the entire row (i.e. all the values in
        the query if we need it).
        """
        ## By default just implement a simple callback:
        if self.callback:
            value = self.callback(value)

        ## The result can now be linked if needed:
        ## Note this only makes sense if cb returns a simple string
        if self.link and value == value.__str__():
            result = result.__class__(result)
            q = self.link.clone()
            q.FillQueryTarget(value.__str__())
            result.link(value, q)
            return result
        
        return value
    
class TimestampType(ColumnType):
    def operator_after(self, column, operator, arg):
        ## FIXME Should parse arg as a date - for now pass though to mysql
        return "%s > %r" % (self.sql, arg)

    def operator_before(self,column, operator, arg):
        ## FIXME Should parse arg as a date
        return "%s < %r" % (self.sql, arg)

class IPType(ColumnType):
    """ Handles creating appropriate IP address ranges from a CIDR specification.

    Code and ideas were borrowed from Christos TZOTZIOY Georgiouv ipv4.py:
    http://users.forthnet.gr/ath/chrisgeorgiou/python/
    """
    def __init__(self, name='', column='', link='', callback=''):
        self.column = column
        ColumnType.__init__(self, name=name, sql="inet_ntoa(%s)" % column,
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

    def operator_netmask(self, column, operator, address):
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
        
        return " ( %s >= %s and %s <= %s ) " % (self.column, numeric_address, self.column, broadcast)

class InodeType(ColumnType):
    """ A unified view of inodes """
    def __init__(self, name='Inode', column='inode', link=None, case=None, callback=None):
        if not link:
            link = FlagFramework.query_type(case=case,
                                            family='Disk Forensics',
                                            report='ViewFile',
                                            __target__='inode', inode="%s")

        ColumnType.__init__(self,name,column,link,callback=callback)
