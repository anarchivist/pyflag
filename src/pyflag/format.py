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
#  Version: FLAG $Version: 0.80.1 Date: Tue Jan 24 13:51:25 NZDT 2006$
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

number_of_sections=4

## Some helper functions    
class NamedArray:
    """ A simple helper class to address arrays by names.
    """
    def __init__(self,array,names):        
        self.names = names
        self.array=array

    def __getitem__(self,item):
        return self.array[self.names.index(item)]

    def __iter__(self):
        self.index=0
        return self

    def next(self):
        try:
            result = self.__class__(self.array[self.index],self.names)
            self.index+=1
            return result
        except:
            raise StopIteration()

class Buffer:
    """ This class looks very much like a string, but in fact uses a file object.

    The advantage here is that when we do string slicing, we are not duplicating strings all over the place (better performace). Also it is always possible to tell where a particular piece of data came from.
    """
    def __init__(self,string='',fd=None,offset=0,size=None):
        """ We can either specify a string, or a fd """
        self.offset=offset
        if fd!=None:
            self.fd=fd
            if size!=None:
                self.size=size
            else:
                self.size=2147483647
        else:
            self.fd=cStringIO.StringIO(string)
            self.size=len(string)

        if self.size<0:
            raise IOError("Unable to set negative size (%s) for buffer (offset was %s)" % (self.size,self.offset))
        
    def clone(self):
        return self.__class__(fd=self.fd)

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
        try:
            self.fd.seek(self.offset)
            return self.fd.read(self.size)
        except Exception,e:
            raise IOError("Unable to read %s bytes from %s - %r" %(self.offset,self.size,e))

#### Start of data definitions:
class DataType:
    """ Base class that reads a data type from the file."""
    ## Controls if this is visible in the GUI
    visible = False
    
    def __init__(self,buffer,*args,**kwargs):
        """ This will force this class to read the data type from data at the specified offset """
        if isinstance(buffer,str):
            self.buffer=Buffer(buffer)
        else:
            self.buffer=buffer
        self.data=None
        try:
            self.parent=kwargs['parent']
        except:
            pass

    def initialise(self):
        self.data=self.read(self.buffer)
        
    def size(self):
        """ This is the size of this data type - it returns the number of bytes we consume. """
        return 0

    def __str__(self):
        if not self.data:
            self.initialise()

        return "%s" % (self.data,)

    def read(self,data):
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
        

class RAW(DataType):
    """ This data type is simply a data buffer. """
    def __init__(self,buffer,count,*args,**kwargs):
        DataType.__init__(self,buffer,*args,**kwargs)
        self.raw_size=count

    def size(self):
        return self.raw_size
        
    def __str__(self):
        return "Raw data of %s byte" % self.raw_size

    def get_value(self):
        return self.buffer[:self.raw_size]
