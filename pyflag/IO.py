# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG  $Name:  $ $Date: 2004/09/14 09:17:15 $
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

"""
    Flag IO subsystem
    =================
    
    This module presents a file like object using the python iosubsys
    module from Sleuthkit.
"""
import iosubsys
import pyflag.FlagFramework as FlagFramework
import pyflag.conf
config=pyflag.conf.ConfObject()
import marshal
import os

class IO:
    """ class for IO subsystem, provides basic contructor and read/seek functions

    This returns file-like objects for use in other python code. This object behaves as follows:

          1) The init method gets called,
          2) if the parameters are bad (i.e. an IO subsystem can not be initialised with them),
                - the form is written on the result.
                - it raises an error and fails to create the object
          4) if the parameters are good, it writes the form again on the result, and returns

    Callers of this object should be prepared to catch IOError exceptions in case this object fails to instantiate. If callers suppy a ui object for result, a form will be drawn on the ui object to assist the user with selecting appropriate parameters for this IO subsystem.

    @Note: The actual subsystem that will be instatiated is query[susbsys].
    """
    readptr=0
    cache={}
    parameters=()
    options = ()

    def set_options(self,key,value):
        """ Sets key and value to the susbsystem """

    def get_options(self):
        """ returns a marshalled representation of options to cache in the database """
        return marshal.dumps(self.options)
        
    def form(self,query,result):
        """ Draw a form in result (ui object) to obtain all the needed parameters from query """

    def __init__(self, query=None,result=None,subsys='subsys',options=None):
        """ initialise the object before use. """
        try:
            if not options:
                options=tuple([query.getarray(i) for i in self.parameters])
                               
            self.options = options
            
            try:
                self.io=IO.cache[self.options]
            except KeyError:
                #Try and make the subsystem based on the args
                self.io=iosubsys.Open(self.options[0][0])
                try:
                    for k in range(len(self.options) - 1):
                        for j in range(len(self.options[k+1])):
                            self.set_options(self.parameters[k+1],self.options[k+1][j])
                            
                    # try reading to see if we get an IOError
                    self.read(10)

                    ## If we are here it should be ok to cache the object.
                    IO.cache[self.options]=self.io
                except (KeyError,IOError):
                    #iosubsys.io_close(self.io)
                    raise
            self.readptr = 0
            
        except (KeyError, IOError):
            if(query and result):
                self.form(query,result)
            raise
            
        if(query and result):
            self.form(query,result)
  
    def seek(self, offset):
        """ fake seeking routine """
        self.readptr = offset

    def tell(self):
        """ return current read pointer """
        return self.readptr

    def read(self, length=None):
        """ read length bytes from subsystem starting at readptr """            
        if length==None:
            return ""
        (len, buf) =  iosubsys.read_random(self.io,length,self.readptr)
        self.readptr += len
        return buf

    def close(self):
        """ close subsystem """
        pass
      
    def set_options(self,key,value):
        iosubsys.parse_options(self.io,"%s=%s" % (key[3:],value))

class sgzip(IO):
    parameters=('subsys','io_filename','io_offset')
    
    def form(self,query,result):
        print "sgzip form"
        tmp = result.__class__(result)
        tmp.filebox(target="io_filename")
        result.row("Select SGZ image:", tmp)
        result.textfield("Enter partition offset in file:",'io_offset')
  
class standard(IO):
    parameters=('subsys','io_filename')

    def form(self,query,result):
        tmp = result.__class__(result)
        tmp.filebox(target="io_filename")
        result.row("Select DD Image:",tmp)

class raid(IO):
    """ Subsystem used to access raid devices """
    parameters=('subsys','file','blocksize','slots','map')

    def form(self,query,result):
        tmp = result.__class__(result)
        tmp.filebox(target="file",multiple="multiple")
        result.row("Select image(s):", tmp)
        result.textfield("Blocksize:",'blocksize')
        result.textfield("Numberr of slots:",'slots')
        result.para("The map is given as a set series of logical blocks delimited with . and with P for the parity block (e.g. 0.1.2.3.4.5.P.P.6.7.8.9.10.11.17.P.12.13.14.15.16.22.23.P.18.19.20.21.27.28.29.P.24.25.26.32.33.34.35.P.30.31.37.38.39.40.41.P.36)")
        result.textfield("map:",'map')

class advanced(IO):
    parameters=('subsys','io_filename','io_offset')

    def form(self,query,result):
        tmp = result.__class__(result)
        tmp.filebox(target="io_filename",multiple="multiple")
        result.row("Select image(s):", tmp)
        result.textfield("Enter partition offset in file:",'io_offset')

class ewf(IO):
    parameters=('subsys','io_filename','io_offset')
    
    def form(self,query,result):
        tmp = result.__class__(result)
        tmp.filebox(target="io_filename",multiple="multiple")
        result.row("Select EWF image(s):",tmp)
        result.textfield("Enter partition offset in file:",'io_offset')

class mounted(IO):
    parameters=('subsys','directory')

    def form(self,query,result):
        print "Drew form"
        result.textfield("Enter mount point:",'directory')

    def read(self, length=None):
        raise FlagFramework.FlagException("Reading of raw mounted IOSources does not make sense - You probably want to load the raw image file as a standard IOSubsystem !!!")

    def __init__(self, query=None,result=None,subsys='subsys',options=None):
        """ Here we implement a dumb constructor which just checks if the directory is valid """
        if not options:
            options=tuple([query.getarray(i) for i in self.parameters])

        self.options = options
        if(query and result):
            self.form(query,result)

        try:
            self.mount_point=self.options[1][0]
            os.listdir(self.mount_point)
        except OSError,e:                
            raise IOError("%s"%e)
        except IndexError:
            raise KeyError

def IOFactory(query,result=None, subsys='subsys'):
    """ Dispatcher for the correct form depending on query['subsys'] """
    io=subsystems[query[subsys]]
    return io(query,result,subsys)

import pyflag.DB as DB

subsystems={'standard':standard,
            'advanced':advanced,
            'sgzip':sgzip,
            'ewf':ewf,
            'mounted':mounted,
            'raid':raid,
            }

def open(case, iosource):
    """ lookup iosource in database and return an IO object """
    dbh = DB.DBO(case)
    try:
        optstr = dbh.get_meta(iosource)
#        dbh.execute("select property from meta where value=%r", iosource)
#        optstr = dbh.fetch()['property']
    except TypeError:
        raise IOError, "Not a valid IO Data Source: %s" % iosource
#
    # unmarshal the option tuple from the database
    # opts[0] is always the subsystem name
    opts = marshal.loads(optstr)
    io=subsystems[opts[0][0]]
    return io(options=opts)
