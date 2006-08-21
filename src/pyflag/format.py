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
""" A Generic library for working with low level file formats.

This is most useful when reading data structure with a fixed format (structs, arrays etc).
"""
import struct,time,cStringIO

class Buffer:
    """ This class looks very much like a string, but in fact uses a file object.

    The advantage here is that when we do string slicing, we are not duplicating strings all over the place (better performace). Also it is always possible to tell where a particular piece of data came from.
    """
    def __init__(self,fd,offset=0,size=None):
        """ We can either specify a string, or a fd as the first arg """
        self.offset=offset
        ## If fd is really a string, we make a StringIO
        if isinstance(fd, basestring):
            self.fd=cStringIO.StringIO(fd)
            self.size=len(fd)
        else:
            self.fd=fd
            if size!=None:
                self.size=size
            else:
                self.size=-1

#        if self.size<0:
#            raise IOError("Unable to set negative size (%s) for buffer (offset was %s)" % (self.size,self.offset))
        
    def clone(self):
        return self.__class__(fd=self.fd, offset=self.offset, size=self.size)

    def __len__(self):
        return self.size
    
    def set_offset(self,offset):
        """ This sets the absolute offset.

        It is useful in files which specify an absolute offset into the file within some of the data structures.
        """
        return self.__class__(fd=self.fd,offset=offset)

    def __getitem__(self,offset):
        """ Return a single char from the string """
        self.fd.seek(offset+self.offset)
        return self.fd.read(1)

    def __getslice__(self,a=None,b=None):
        """ Returns another Buffer object which may be manipulated completely independently from this one.

        Note that the new buffer object references the same fd that we are based on.
        """
        return self.__class__(fd=self.fd,offset=self.offset+a,size=b-a)

    def __str__(self):
        self.fd.seek(self.offset)
        if self.size>0:
            data=self.fd.read(self.size)
        else:
            data=self.fd.read()
            
#        if len(data) < self.size:
#            raise IOError("Unable to read %s bytes from %s" %(self.size,self.offset))

        return data

#### Start of data definitions:
class DataType:
    """ Base class that reads a data type from the file."""
    ## Controls if this is visible in the GUI
    visible = False

    ## This is the SQL type which is most appropriate for storing the
    ## results of value()
    sql_type = "text"
    
    def __init__(self,buffer,*args,**kwargs):
        """ This will force this class to read the data type from data at the specified offset """
        if isinstance(buffer,str):
            self.buffer=Buffer(buffer)
        else:
            self.buffer=buffer
        self.data=None
##        self.parameters = kwargs
##        try:
##            self.parent=kwargs['parent']
##        except:
##            pass
        self.data=self.read()

    def size(self):
        """ This is the size of this data type - it returns the number of bytes we consume. """
        return 0

    def __str__(self):
        return "%s" % (self.data,)

    def read(self):
        """ Abstract method that returns the data type required to be
        stored internally
        """
        return None

    def __ne__(self,target):
        return not self.__eq__(target)

    def get_value(self):
        """ In the general case we return ourself as the opaque data type """
        return self

    def form(self,prefix, query,result):
        pass

    def display(self, result):
        result.text(self.__str__(), wrap='full', sanitise='full', font='typewriter')

    def value(self):
        return self.__str__()
        

class RAW(DataType):
    """ This data type is simply a data buffer. """
    def __init__(self,buffer,*args,**kwargs):
        DataType.__init__(self,buffer,*args,**kwargs)
        self.buffer.size = kwargs['count']

    def size(self):
        return self.buffer.size
        
    def get_value(self):
        return self.buffer.clone()

    def read_data(self):
        self.data = self.buffer.__str__()

    def __repr__(self):
        if not self.data: self.read()
        result = ''.join([self.data[a].__str__() for a in range(len(self.data))])
        return result     

    def __str__(self):
        if not self.data: self.read_data()
        tmp = []
        for i in range(len(self.data)):
            char = "%s" % self.data[i]
            if char.isalnum() or char in '!@#$%^&*()_+-=;\'[]\,./<>? ':
                tmp.append(char)
            else:
                tmp.append('.')

        return ''.join(tmp)
