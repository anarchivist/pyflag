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
#  Version: FLAG 0.4 (12-02-2004)
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

""" Main UI module.

The output within flag is abstracted such that it is possible to connect any GUI backend with any GUI Front end. This is done by use of UI objects. When a report runs, it will generate a UI object, which will be built during report execution. The report then returns the object to the calling framework which will know how to handle it. Therefore the report doesnt really know or care how the GUI is constructed """

import re,cgi,types
import pyflag.FlagFramework as FlagFramework
import pyflag.DB as DB
import pyflag.conf
import pyflag.logging as logging
config=pyflag.conf.ConfObject()

config.LOG_LEVEL=7

class UIException(Exception): pass

class GenericUI:
    """ Baseclass for UI objects. Note that this is an abstract class which must be implemented fully by derived classes. This base class exists for the purpose of documentations. UI method prototypes should be added to this base class so they could be implemented in derived classes as well. """
    def __init__(self,default = None):
        """Create a new UI object.
        Default is another UI object which we are basing this UI object on. In particular this new UI object and the default object share the same internal state variables, so that changes on one will affect the other. This is required for example when we are creating a temporary UI object inside an object which has a form in it. This way the new UI object can adjust the internal state of the form.
        """
        pass
    
    def __str__(self):
        """ A string description of this UI type. Probably needs to return a UI name """
        pass

    def pre(self,string):
        """ A paragraph formatting directive """
        logging.log(logging.DEBUG, "pre not implemented")

    def heading(self,string):
        """ Used for drawing a heading with a large font """
        logging.log(logging.DEBUG, "pre not implemented")

    def para(self,string,**options):
        """ Add a paragraph to the output """
        logging.log(logging.DEBUG, "para not implemented")

    def start_table(self,**options):
        """ Start a table. Note that all rows should have the same number of elements within a table """
        logging.log(logging.DEBUG, "start_table not implemented")

    def row(self,*columns, **options):
        """ Add a row to the table. If a table is not defined as yet, a new table is created. Column entries for the row should be given as a list of arguements. Options may be given as named pairs. Note that column objects may be strings or other UI entities.

        options is usually passed to the underlying implementation, but a number of keywords are understood by the UI:
              - type: heading - this row is the table's heading
              - colspan: The row has fewer elements than are needed, and the extra columns are to be filled with blanks.
        """
        logging.log(logging.DEBUG, "row not implemented")
    
    def start_form(self,target, **hiddens):
        """ Creates a form. Target is a query_type object and is implemented as hidden fields. hiddens are name/value pairs of hidden parameter than should be passed. """
        logging.log(logging.DEBUG, "start_form not implemented")
        
    def end_table(self):
        """ End this table. This will cause the table to be drawn and a new table may be created """
        logging.log(logging.DEBUG, "end_table not implemented")
               
    def ruler(self):
        """ Draw a horizontal ruler """
        logging.log(logging.DEBUG, "ruler not implemented")
        
    def link(self,string,target=FlagFramework.query_type(()),**target_options):
        """ Create a link to somewhere else.

        A link is categorized by a list of named arguements, usually given as elements of query_type.
        Derived classes must make the link launch the correct part of the front end as specified by the link attributes """
        logging.log(logging.DEBUG, "link not implemented")
    
    def display(self):
        """ Main display method.

        Called when the framework is ready to display the UI object. Note that further operations on this UI are not defined once display is called. Note also that  the specific type of object returned here really depends on the implementation. The front-end should handle the return type appropriately

        This function in combination with the front end is expected to produce all the navigational aids required (e.g. nav bar or tool bars etc).
        """
        logging.log(logging.DEBUG, "display not implemented")

    def selector(self,description,name,sql,parms,**options):
        """ Present a listbox selector based on sql. name is the target of the selector"""
        try:
            case = options['case']
            del options['case']
        except KeyError:
            case = None

        dbh = DB.DBO(case)
        keys=[]
        values=[]
        try:
            dbh.execute(sql,parms)
            while 1:
                row = dbh.cursor.fetchone()
                if not row: break
                keys.append(row[0])
                values.append(row[1])

        ## If the SQL failed, we present an empty selector
        except DB.DBError:
            pass

        self.const_selector(description,name,keys,values,**options)

    def textfield(self,description,name,**options):
        """ Draws a textfield in a table row. """
        logging.log(logging.DEBUG, "textfield not implemented")
        
    def end_form(self,name):
        """ Called to end the form, possibly providing a submit button """
        logging.log(logging.DEBUG, "end_form not implemented")
        
    def hidden(self,name,value):
        """ Create a hidden parameter to be passed on form submission """
        logging.log(logging.DEBUG, "hidden not implemented")
        
    def checkbox(self,description,name,value,**options):
        """ Create a checkbox input for the name,value pair given. """
        logging.log(logging.DEBUG, "checkbox not implemented")
        
    def filebox(self,dir=None,target="datafile",multiple="single"):
        """ Draws a file selector for all the files in directory dir.
        
        For security purposes, flag is unable to read files outside that directory.
        """
        logging.log(logging.DEBUG, "filebox not implemented")
    
    def case_selector(self,case='case',message='Case:', **options):
        """ Present a case selection box. Reports should call this method in their form in order to allow the user to specify the exact case to select. Note that a report may not need a case to operate on. """
        self.selector(message,case,'select value as `key`,value as `value` from meta where property=\'flag_db\'',(),**options)

    def meta_selector(self, case=config.FLAGDB,message='Select Value',property=None, **options):
        """ Present a selection box to select stuff from the meta table"""
        self.selector(message,property,'select value,value from meta where property=%r group by value',(property),case=case, **options)
        
    def tooltip(self,message):
        """ Renders the tooltip message each time the mouse hovers over this UI.

        The UI method may choose where the tooltip is displayed (for example it maybe more appropriate to show it on the status bar).
        """
        logging.log(logging.DEBUG, "tooltip not implemented")

    def make_link(self,query,target,target_format = None,**options):
        """ Makes a query_type object suitable for use in the links array of the table

        @note: the returned object is a clone of query.
        @note: Private ui parameters are automatically cleaned. e.g. limit, nextpage etc.
        @arg query: Original query to base the new object on
        @arg target: a string representing the name of the target
        @arg target_format: An optional format string that will be used to format the target arg for each cell in the table. There must be only one format specifier.
        """
        q = query.clone()
        del q[target]
        del q['__target__']
        del q['limit']
        del q['order']
        del q['dorder']
        for i in q.keys():
            if i.startswith('where_'):
                del q[i]
        
        q['__target__']=target
        try:
            q['__mark__']=options['mark']
        except KeyError:
            pass
        
        if target_format:
            q[target]=target_format

        return q

    def FillQueryTarget(self,query,dest):
        """ Given a correctly formatted query (see table()), and a target, this function returns a query object with a filled in target

        @Note: FillQueryTarget makes a clone copy of query since it is altered quite heavily.
        @except KeyError: if the query is not formatted properly (i.e. no _target_ key)
        """
        #Need to clone because we will trash our local copy
        q = query.clone()
        for target in q.getarray('__target__'):
            try:
            ## Replace the target arg with the new one (note we cant just add one because that will append it to the end of a cgi array)
                tmp = str(q[target]) % dest
                del q[target]
                q[target] = tmp
            
            ## No q[target]
            except (KeyError,TypeError):
                del q[target]
                q[target] = dest

        try:
            ## If we were asked to mark this target, we do so here. (Note that __mark__ could still be set to a constant, in which case we ignore it, and its query_type.__str__ will fill it in)
            if q['__mark__']=='target':
                del q['__mark__']
                q['__mark__']=dest
        except KeyError:
            pass
            
        del q['__target__']
        return q

    def text(self,*cuts,**options):
        """ Adds the cuts to the current UI.

        Note that this widget may choose to implement the text as an editor widget or simply as a label. Repeated calls to this method could be made sequentially which should all end up in the same widget. This is not an editable UI element, see textfield if thats what you need.
        Supported keywork options: (defaults are in ())
              - color: A color to render this text widget in. Defaults: black
              - font: Font to render this widget in - can be (normal), bold, typewriter, small, large
              - wrap: How to wrap long lines, maybe full,(none) or word
              - sanitise: How much to sanitise the output. This probably only makes sense in the HTMLUI where output may be rendered incorrectly in the browser:
                     - Full: All tags are escaped
                     - (None): No sanitation is done
        """
        logging.log(logging.DEBUG, "text not implemented")
