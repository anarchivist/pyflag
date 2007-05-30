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
#  Version: FLAG $Version: 0.84RC4 Date: Wed May 30 20:48:31 EST 2007$
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
import pyflag.pyflaglog as pyflaglog
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
        
        # this allows arbirtary meta table properties to become types
        if type.startswith('meta_'):
            type = type[len('meta_'):]
            return self.metatype(type, field, query)

        for a in dir(self):
            if a==type:
                #Set the calling function to the string indicated by type
                fn = TypeChecker.__dict__[type]
                #call it
                result=fn(self,field,query)
#                if not result:
#                    pyflaglog.log(pyflaglog.DEBUG,"Failed to check %s for %s of type %s" % (query,field,type))
                return result

        raise ReportInvalidParamter, "Type %s not recognised " % type

    def metatype(self, type, field, query, case='query'):
        """ Test for matches against meta entries in the meta table """
        string = query[field]

        if not case:
            dbh = DB.DBO(None)
        else:
            dbh = DB.DBO(query['case'])
            
        dbh.execute("select * from meta where property=%r and value=%r",(type, string))
        if dbh.cursor.fetchone():
            return True
        
        return False

    def numeric(self,field,query):
        """ Tests input for numeric values """
        string = query[field]

        if not string.isdigit():
            raise ReportInvalidParamter,"Not numeric input"

    def any(self,field,query):
        """ A Generic type which will OK everything """

    def alphanum(self,field,query):
        """ Tests input for alphanumeric chars """
        string = query[field]

        if not string.isalnum():
            raise ReportInvalidParamter,"Not alphanumeric input"

    def flag_db(self,field,query):
        """ Tests to see if the string is a valid flag case database """
        return self.metatype('flag_db', field, query,case = None)

    def filename(self,field,query):
        """ Tests to see if the string is a valid filename within the upload dir """
        for filename in query.getarray(field):
            string=os.path.normpath(filename)
            
            full_filename = os.path.normpath(config.UPLOADDIR + "/" + string)
            if not os.access(full_filename,os.R_OK):
                raise ReportInvalidParamter,"%s is not a filename" % (full_filename)

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
        ### FIXME: PyFlag should be able to handle special characters
        ### in anything by properly escaping all places. We want to
        ### see when things break badly so we just issue a warning
        ### here and let it go.
        pyflaglog.log(pyflaglog.WARNING, "Unusual characters in field %s: %r. We should be able to handle it though." % (field, query[field]))
        return True
                    
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
        except (IOError, KeyError, RuntimeError):
            return False

    def iosource(self,field,query):
        """ Check that the given string is a valid IO system identifier """
        return self.metatype('iosource', field, query)

    def fsimage(self,field,query):
        """ Check that the given string is a valid Filesystem identifier """
        return self.metatype('fsimage', field, query)

    def casetable(self,field,query):
        """ Checks that field is a table within the case given as query[case]. This is not a fatal error, we just return false if not. """
        dbh= DB.DBO(query['case'])
        try:
            dbh.execute("select * from `%s_log` limit 1",query[field])
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
        return True

    def string(self,field,query):
        """ A default type that accepts anything """
        pass

    def onoff(self,field,query):
        if query[field]=='on' or query[field]=='off':
            return True
        
        raise ReportInvalidParamter("Field %s must be either 'on' or 'off'" % field)
