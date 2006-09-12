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

""" This module defines a number of usefull actions for the table objects.

These functions can be used as callbacks in the Table objects actions
after appropriately being curried.
"""

import pyflag.FlagFramework as FlagFramework
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.TableObj as TableObj
import pyflag.DB as DB
import calendar
import datetime

## Some useful display actions
def textarea(description = None, variable= None, ui=None, **options):
    """ Draws a textarea as form input for input """
    ui.textarea(description,variable,rows=5,cols=40,**options)

def date_selector(description = None, callback=None, variable= None, ui=None, label=None, **options):
    """ Draws a popup for selecting a date """
    tmp=ui.__class__(ui)
    try:
        date=ui.defaults[variable]
        ui.hidden(variable,date)
        date="%s"% date
        date = datetime.date(int(date[0:4]),int(date[5:7]),int(date[8:10]))
        tmp.text(date.strftime("%a %b %d %Y    ") ,color='red')
    except ValueError:
        pass
    
    tmp.popup(callback,label,**options)
    ui.row(description,tmp)

def draw_calendar(query,ui,target=None):
    """ Draw the calendar for popup window """
    ui.decoration='naked'
    
    try:
        date=query[target]
        print "Query is %s" % query[target]
        date = datetime.date(int(date[0:4]),int(date[5:7]),int(date[8:10]))
    except (KeyError,ValueError),e:
        print "%s"% e
        date=datetime.date.today()

    print "Date is %s" % date
        
    ui.heading(date.strftime("%B %Y"))

    q=query.clone()
    del q[target]
    q[target]="%04u-%02u-%02u" % (date.year-1,date.month,15)
    ui.toolbar(text="Previous Year",icon="stock_left-with-subpoints.png",link=q)

    q=query.clone()
    del q[target]
    month=date.month-1
    year=date.year
    if month<1:
        month=12
        year-=1
    q[target]="%04u-%02u-%02u" % (year,month,15)
    ui.toolbar(text="Previous Month",icon="stock_left.png",link=q)
        
    q=query.clone()
    month=date.month+1
    year=date.year
    if month>12:
        month=1
        year+=1
    del q[target]
    q[target]="%04u-%02u-%02u" % (year,month,15)
    ui.toolbar(text="Next Month",icon="stock_right.png",link=q)

    q=query.clone()
    del q[target]
    q[target]="%04u-%02u-%02u" % (date.year+1,date.month,15)
    ui.toolbar(text="Next Year",icon="stock_right-with-subpoints.png",link=q)
    
    query.poparray('callback_stored')
    del query['__opt__']
    del query[target]
    query['__opt__'] = 'parent'

    ui.start_table(border=1)
    for week in calendar.monthcalendar(date.year,date.month):
        new_week=[]
        for day in week:
            q=query.clone()
            q[target]= "%04u-%02u-%02u" % (date.year,date.month,day)
            tmp=ui.__class__(ui)
            if day == 0:
                pass
            elif day==date.day:
                tmp2=tmp.__class__(ui)
                tmp2.link(day,q)
                tmp.row(tmp2,bgcolor='yellow',border=1)
            else:
                tmp.link(day,q)
            new_week.append(tmp)
            
        ui.row(*new_week,**{'align':'right'})
            
def popup(description = None, variable= None, ui=None, callback= None, label=None, **options):
    """ Open a new popup window with callback being the target """
    tmp=ui.__class__(ui)
    tmp.popup(callback,label,**options)
    ui.row(description,tmp)

def const_selector(description=None, choices=None, variable=None, ui=None, **options ):
    """ Draw a constant selector on ui

    @arg description: The description that should appear.
    @arg choices: A list of possible choices to show.
    @arg variable: The target of the selector box.
    @arg query: The query that was given to the page - the default value of the selector is taken from this query object as the value supplied to variable.
    @arg ui: The ui object to draw on.
    """
    ui.const_selector(description,variable,choices,choices,**options)

## Some useful constrains
def uniq(table_object,fieldname,proposed_value,query=None,id=None,result=None):
    """ Raises an exception if the field already has the proposed value.

    @arg table_object: The object to operate on
    @arg fieldname: The name of the field to check
    @arg proposed_value: The value we want to set this field
    @arg id: If set, we exclude this ID from the comparison. This is used for example when editing a row to ensure that the current row id is not considered a duplicate.
    """
    dbh = DB.DBO(table_object.case)
    if id:
        dbh.execute("select * from %s where %s=%r and %s!=%r",(table_object.table,fieldname,proposed_value,table_object.key,id))
    else:
        dbh.execute("select %s from %s where %s=%r",(table_object.key, table_object.table,fieldname,proposed_value))
    row=dbh.fetch()
    
    if(row):
        result = result.__class__(result)
        result.text("there is already a row (key %s) with field %s set to %s. These are the details of the existing row:" % (row[table_object.key],fieldname,proposed_value),color='red')
        table_object.show(row[table_object.key],result)
        raise TableObj.ConstraintError(result)

def noop(description=None, choices=None, variable=None, ui=None, **options ):
    """ A noop action """

def selector_display(description=None, variable=None, ui=None, table=None, **options ):
    """ Draws a selector based on a column from a table """
    tmp=ui.__class__(ui)
    dbh=DB.DBO(ui.defaults['case'])
    dbh.execute("select %s from %s group by %s", (variable,table,variable))
    keys= [None]+[ row[variable] for row in dbh]
    tmp.const_selector('',variable,keys,keys)
    tmp2=ui.__class__(ui)
    tmp3=ui.__class__(ui)
    tmp3.textfield('','new_%s' % variable)
    tmp2.start_table(bgcolor='lightgray')
    tmp2.row(tmp," or type ",tmp3)
    tmp2.end_table()
    ui.row(description,tmp2)

def selector_constraint(table_object,fieldname,proposed_value,query=None,id=None, result=None):
    """ Checks if the user types a new value in selector_display to overrride the selector """
    print "About to check %s in %s" %(fieldname,query)
    try:
        tmp=query["new_%s" % fieldname]
        del query["new_%s" % fieldname]
        if tmp and len(tmp)>0 and tmp!="None":
            del query[fieldname]
            query[fieldname]=tmp
    except KeyError:
        pass

def time_input(description=None,ui=None, target=None, **options):
    """ Show a time input form.
    This consists of seperate inputs for hours and minutes
    """
    ## First convert any time to displayable time units:
    try:
        t = ("%s"%ui.defaults[target]).split(':')
        if len(t)<2: t[1]='0'
    except (KeyError,IndexError):
        t = "0:0".split(':')

    ui.defaults["%s_hours" % target] = t[0]
    ui.defaults["%s_mins" % target] = t[1]        

    tmp=ui.__class__(ui)
    tmp.textfield('Hours:',"%s_hours" % target,size=4)
    tmp2=ui.__class__(ui)
    tmp2.textfield('Minutes:',"%s_mins" % target,size=4)
    tmp3=ui.__class__(ui)
    tmp3.row(tmp,tmp2)
    ui.hidden(target,"0")
    ui.row(description,tmp3)

def time_constraint(table_object, fieldname, proposed_value, query=None, **args):
    """ Convert time time given in hours and minutes back to a real timestamp """
    
    tmp = "%s:%s:00" % (query["%s_hours" % fieldname], query["%s_mins" % fieldname])
    del query[fieldname]
    query[fieldname] = tmp

def selector(table=None, keys=None, values=None, variable=None, ui=None, description=None, **args):
    """ Allows the user to choose from system users

    @arg table: The table we should use
    @arg keys: The column which the keys are taken from. (These will be stored in the table).
    @arg values: The column where the displayed options are taken from.
    @arg variable: The name of CGI variable we should use.
    @arg description: The description of this field.
    """
    ui.selector(description,variable,
                "select %s,%s from %s",( keys,values,table))

def user_display(description=None,value=None,ui=None, **args):
    """ Displays the username from a given user ID """
    import plugins.User as User

    u=User.UserOBJ()
    tmp=ui.__class__(ui)
    try:
        tmp.text(u[value]['Name'],color='red')
    except TypeError:
        tmp.text("No user selected",color="blue")
    
    ui.row(description,tmp)

def foreign_key(table_object, fieldname,proposed_value,query=None,id=None, result=None, table=None):
    """ A constraint that ensures that the proposed_value exists within a table table. This is effectively enforcing a foreign key relationship. Note that table is an instance of a TableObj.
    """
    if not proposed_value or not table[proposed_value]:
        result.heading("Incorrect %s specified" % table.table)
        result.text("Please ensure that a valid %s exists and is properly specified. Hit the back button and try again." % table.table)
        raise TableObj.ConstraintError(result)

def not_empty_constraint(table_object, fieldname,proposed_value,query=None,id=None, result=None):
    """ A constraint that ensures that proposed_value is not empty """
    if not proposed_value or proposed_value == "None":
        result.heading("Unspecified %s value" % table_object.get_name(fieldname))
        result.text("Please ensure that %s is filled in" % table_object.get_name(fieldname))
        raise TableObj.ConstraintError(result)

def combine_constraints(table_object, fieldname,proposed_value,query=None,id=None, result=None, constraints=()):
    """ A constraint that combines an arbitrary number of constrains together.

    Any of the combined constraints can raise an error at any time. We only allow this constraint if _all_ constraints are satisfied. Note that constraints is a list of constraint functions.
    """
    for c in constraints:
        c(table_object,fieldname,proposed_value,query,id,result)

import tempfile,os

def FileUploadConstraint(table_object,fieldname,proposed_value,query=None,id=None, result=None, server_filename_field=None):
    """ This function saves the file in the results directory and replaces query[fieldname] with the filename to the uploaded file """
    try:
        filename = query['%s_filename' % fieldname]
    except:
        filename = ""

    ## The user did not upload a new file at all - we reset these to
    ## the values they used to be
    if(id and len(filename)<2):
        t = table_object[id]
        del query[fieldname]
        query[fieldname] = t[fieldname]
        del query[server_filename_field]
        query[server_filename_field] = t[server_filename_field]
        return
    
    data = query[fieldname]
    
    del query[fieldname]
    query[fieldname]=filename
    
    fd , server_filename= tempfile.mkstemp("bin","ISGDB_",config.RESULTDIR)
    os.write(fd, data)
    
    del query[server_filename_field]
    query[server_filename_field]=server_filename

    os.close(fd)

def draw_icon(value,result,icon=None,tooltip=None):
    """ A generic function to draw an icon in a table """
    tmp=result.__class__(result)
    tmp.icon(icon,tooltip=tooltip)
    return tmp

def get_user_record(username):
    """ Given a username, returns the ID or None if no such user """
    dbh=DB.DBO(None)
    dbh.execute("select * from users where username=%r",username)
    row=dbh.fetch()
    if row:
        return row

def get_user_id(username):
    """ Given a username, returns the ID or None if no such user """
    dbh=DB.DBO(None)
    dbh.execute("select id from users where username=%r",username)
    row=dbh.fetch()
    if row:
        return int(row['id'])

def get_user_priv(username):
    """ Given a username, returns the privileges of this user. """
    dbh=DB.DBO(None)
    dbh.execute("select priviledges from users where username=%r",username)
    row=dbh.fetch()
    if row:
        return int(row['priviledges'])
    
def table_popup(description = None, variable= None, ui=None, callback= None, label=None, table_obj=None, **options):
    """ Open a new popup window with callback being the target """
    tmp=ui.__class__(ui)
    try:
        t = table_obj()
        t.show(tmp.defaults[variable],tmp)
        ui.hidden(variable,tmp.defaults[variable])
        tmp.end_table()
    except (AttributeError, TypeError),e:
        raise

    tmp.popup(callback,label,**options)
    ui.row(description,tmp)

