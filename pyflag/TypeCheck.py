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
#  Version: FLAG $Version: 0.75 Date: Sat Feb 12 14:00:04 EST 2005$
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

""" Module used for sanity checking of strings according to classifications """
import pyflag.DB as DB
import pyflag.Reports as Reports
import pyflag.conf
config=pyflag.conf.ConfObject()
import os.path,os

class ReportInvalidParamter(Reports.ReportError):
    """ Exception thrown if the type test fails """
    pass

class TypeChecker:
    """ Class responsible for type checking input. This class is instantiated in order to manage type access control. All methods in this class should be of the prototype:

    def method(self,string,query)

    where string is the value of the paramter to be checked, while method checks it against a named test. query is supplied in case the test needs it and gives the test access to all other CGI parameters. The return value should be true, or else a ReportInvalidParamter exception is raised.
    
    If a parameter was rejected we throw a ReportInvalidParamter exception outlining why this parameter was rejected.

    If specific plugins need to add their own type checks, they can extend this class and add whatever method they wish. The name of the method can then be added as a string to the report.parameters dictionary. The extended class instance can then be used to replace report.TypeCheck. See the report base class documentation for more details.
    """

    def check_type(self,type,field,query):
        """ Looks through introspection at this modules methods and calls them if they match the string passed """
        for a in dir(self):
            if a==type:
                #Set the calling function to the string indicated by type
                fn = TypeChecker.__dict__[type]
                #call it
                return fn(self,field,query)

        raise ReportInvalidParamter, "Type %s not recognised " % type

    def numeric(self,field,query):
        """ Tests input for numeric values """
        string = query[field]

        if not string.isdigit():
            raise ReportInvalidParamter,"Not numeric input"

    def alphanum(self,field,query):
        """ Tests input for alphanumeric chars """
        string = query[field]

        if not string.isalnum():
            raise ReportInvalidParamter,"Not alphanumeric input"

    def flag_db(self,field,query):
        """ Tests to see if the string is a valid flag case database """
        string = query[field]

        dbh = DB.DBO(None)
        dbh.execute("select * from meta where property='flag_db' and value=%r",string)
        if not dbh.cursor.fetchone():
            return False
            raise ReportInvalidParamter, "%s is not a valid flag database" % string

    def filename(self,field,query):
        """ Tests to see if the string is a valid filename within the upload dir """
        string =os.path.normpath( query[field])

        dir = config.UPLOADDIR
        if string.startswith(dir) and os.access(string,os.R_OK):
            return
        else:
            raise ReportInvalidParamter,"Not a filename in dir %s " % dir

    def unique(self,field,query):
        """ Tests all fields given by fieldxx for unique values. """
        values=[]
        
        for f in query.keys():
            if f.startswith(field):
                #we ignore those fields with the value ignore
                if query[f] == 'ignore': continue
                
                if query[f] in values:
                    raise ReportInvalidParamter,"%s group (%s) has multiple value %s" % (field,f,query[f])
                else:
                    values.append(query[f])

    def sqlsafe(self,field,query):
        """ Checks to see if the type had bad characters in it """
        for d in query.getarray(field):
            for char in "`\\\"' !@#$%^&*+/-()":
                if char in d:
                    raise ReportInvalidParamter,"Invalid character (%s) in field name" % char

    def iosubsystem(self,field,query):
        """ Check to see that the io subsystem is adequitely filled in

        instantiate an IO object, and try to pass the query to it.
        If the query is ok, we then pass the test, else we fail.
        """
        import pyflag.IO as IO
        
        try:
            IO.IOFactory(query,subsys=field)
        except (IOError, KeyError):
            return False

    def iosource(self,field,query):
        """ Check that the given string is a valid IO system identifier """
        
        dbh = DB.DBO(query['case'])
        dbh.execute("select * from meta where property='iosource' and value=%r",query[field])
        if not dbh.cursor.fetchone():
            return False
##            raise ReportInvalidParamter, "%s is not a valid IO Data Source" % query[field]

    def fsimage(self,field,query):
        """ Check that the given string is a valid Filesystem identifier """
        
        dbh = DB.DBO(query['case'])
        dbh.execute("select * from meta where property='fsimage' and value=%r",query[field])
        if not dbh.cursor.fetchone():
            return False
##            raise ReportInvalidParamter, "%s is not a loaded FS Image" % query[field]

    def casetable(self,field,query):
        """ Checks that field is a table within the case given as query[case]. This is not a fatal error, we just return false if not. """
        dbh= DB.DBO(query['case'])
        try:
            dbh.execute("select * from %s_log limit 1",query[field])
        except DB.DBError:
            return False

    def ipaddress(self,field,query):
        import re
        if re.match("^(?:\d|\.)+$", query[field]):
            return
        else:
            return False
        
    def any(self,field,query):
        """ A default type that accepts anything """
        pass

    def string(self,field,query):
        """ A default type that accepts anything """
        pass
