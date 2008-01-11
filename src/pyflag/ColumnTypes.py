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

""" This module implements the base classes for column types. These
are used by the table widget for implementing special handling for
data types, operators etc.
"""
from pyflag.TableObj import TableObj
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
import re,struct, textwrap

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

    def link_display_hook(self, value, row, result):
        if self.link and not self.callback:
            q = self.link.clone()
            q.FillQueryTarget(value)
            result.link(value, q, pane=self.link_pane)

    def plain_display_hook(self, value, row, result):
        if value:
            result.text(value)

    display_hooks = [ plain_display_hook, link_display_hook, ]
    display_hooks_names = [ "plain_display_hook", "link_display_hook", ]
    
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

        ## Allow all our display hooks to do their things
        for hook in self.display_hooks:
            hook(self, value, row, result)

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

def add_display_hook(cls, name, cb, position=-1):
    if name not in cls.display_hooks_names:
        cls.display_hooks_names.append(name)
        cls.display_hooks.insert(position,cb)

def clear_display_hook(cls):
    cls.display_hooks = []
    cls.display_hooks_names = []

### Some common basic ColumnTypes:
class StateType(ColumnType):
    """ This column can hold one of several different states. """
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
    def edit_display_hook(self, value, row, result):
        """ This method is called by the table widget to allow us to
        translate the output from the database to the screen. Note
        that we have access to the entire row (i.e. all the values in
        the query if we need it).
        """
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

    display_hooks = [edit_display_hook,]

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

    def log_parse(self, row):
        t,m = Time.strptime(row, format = self.format)

        if self.override_year:
            t = list(t)
            t[0] = self.override_year
            
        date = time.strftime("%Y-%m-%d %H:%M:%S", t)

        return m.end(), self.column, date

class IPType(ColumnType):
    """ Handles creating appropriate IP address ranges from a CIDR specification. """    
    ## Code and ideas were borrowed from Christos TZOTZIOY Georgiouv ipv4.py:
    ## http://users.forthnet.gr/ath/chrisgeorgiou/python/
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

    def create(self):
        ## IP addresses are stored as 32 bit integers 
        return "`%s` int(11) unsigned default 0" % self.column

    def select(self):
        ## Upon selection they will be converted to strings:
        return "inet_ntoa(`%s`)" % (self.column)

    def insert(self,value):
        return "_"+self.column, "inet_aton(%r)" % value.strip()

    display_hooks = IntegerType.display_hooks[:]

class InodeType(StringType):
    """ A unified view of inodes """
    hidden = True
    def __init__(self, name='Inode', column='inode', link=None, case=None, callback=None):
        raise RuntimeError("InodeType is depracated - you must use InodeIDType now")
        self.case = case
        ColumnType.__init__(self,name,column,link,callback=callback)

    def get_inode(self, inode):
        return inode

    def column_decorator(self, table, sql, query, result):
        case = query['case']
        report = Registry.REPORTS.dispatch(family = 'Disk Forensics',
                                           report = "ViewFile")

        report = report(None, result)
        
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
            fsfd = FileSystem.DBFS(self.case)
            inode = self.get_inode(row[self.name])

            query.set('inode', inode)
            report.display(query, result)

            annotate = query.get('annotate','no')
            
            if annotate == 'yes':
                query.set('annotate','no')
                result.toolbar(icon='no.png', link = query, pane = 'pane')
            else:
                query.set('annotate','yes')
                result.toolbar(icon='yes.png', link = query, pane = 'pane')

            query.clear('annotate')

            new_query = query.clone()
            if limit==0:
                result.toolbar(icon = 'stock_left_gray.png')
            else:
                new_query.set('inode_limit', limit-1)
                result.toolbar(icon = 'stock_left.png', link=new_query,
                               pane='self', tooltip = "Inode %s" % (limit -1))

            if not next_row:
                result.toolbar(icon = 'stock_right_gray.png')
            else:
                new_query.set('inode_limit', limit + 1)
                result.toolbar(icon = 'stock_right.png', link=new_query,
                               pane='self',tooltip = "Inode %s" % (limit + 1))
                
        result.toolbar(cb = browse_cb, icon="browse.png",
                       tooltip = "Browse Inodes in table", pane='new')

        return self.name

class InodeIDType(IntegerType):
    def __init__(self, name='Inode', column='inode_id', link=None, case=None, callback=None):
        self.case = case
        ColumnType.__init__(self,name,column,link,callback=callback)

clear_display_hook(InodeIDType)

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

    def render_links_display_hook(self, value,row,result):
        if row['link']:
            result.text("%s\n->%s" % (value, row['link']), style="red")

    display_hooks = [render_links_display_hook, StringType.link_display_hook]

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
                         "(1) and (`timestamp` > '2005-10-10 00:00:00')")

        self.assertEqual(self.generate_sql("'IPType' netmask 10.10.10.1/24"),
                         "(1) and ( ( `source_ip` >= 168430081 and `source_ip` <= 168430335 ) )")
        
        self.assertEqual(self.generate_sql("'InodeType' annotated FooBar"),
                         '(1) and (`inode`=(select annotate.inode from annotate where note like "%FooBar%"))')

        ## Joined filters:
        self.assertEqual(self.generate_sql("InodeType contains 'Z|' and TimestampType after 2005-10-10"),
                         "(1) and (`inode` like '%Z|%' and `timestamp` > '2005-10-10 00:00:00')")
        self.assertEqual(self.generate_sql("InodeType contains 'Z|' or TimestampType after 2005-10-10 and IntegerType > 5"),
                         "(1) and (`inode` like '%Z|%' or `timestamp` > '2005-10-10 00:00:00' and `table`.`integer_type` > '5')")
        self.assertEqual(self.generate_sql("(InodeType contains 'Z|' or TimestampType after 2005-10-10) and IntegerType > 5"),
                         "(1) and (( `inode` like '%Z|%' or `timestamp` > '2005-10-10 00:00:00' ) and `table`.`integer_type` > '5')")

    def test10CreateTable(self):
        """ Test table creation """
        dbh = DB.DBO()
        
        ## Check to see if the table create code is valid sql:
        dbh.execute("create temporary table foobar_001 (%s)", (
            ',\n'.join([ x.create() for x in self.elements])
            ))
