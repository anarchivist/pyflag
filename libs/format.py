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
""" A Generic library for working with low level file formats.

This is most useful when reading data structure with a fixed format (structs, arrays etc).
"""
import struct,time

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

#### Start of data definitions:
class DataType:
    """ Base class that reads a data type from the file."""
    def __init__(self,buffer,offset,*args,**kwargs):
        """ This will force this class to read the data type from data at the specified offset """
        self.buffer=buffer
        self.data=None
        self.offset=offset
        self.parent=kwargs['parent']

    def initialise(self):
        self.data=self.read(self.buffer[self.offset:])
        
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
    
class BasicType(DataType):
    """ Base class for basic types that unpack understands """
    def size(self):
        ## We consume 2 bytes here
        return struct.calcsize(self.fmt)

    def read(self,data):
        return struct.unpack(self.fmt,data[:self.size()])[0]

    def __int__(self):
        if not self.data:
            self.initialise()
            
        return int(self.data)

    def get_value(self):
        if not self.data:
            self.initialise()
        return self.data

    def __eq__(self,target):
        if not self.data:
            self.initialise()

        if isinstance(target,int):
            return self.data==target
        
        return self.data==self.read(target)

class WORD(BasicType):
    """ Reads a word (short int) from the data in big endian """
    fmt = 'H'

class LONG(BasicType):
    fmt='l'

class ULONG(BasicType):
    fmt='L'

class LONGLONG(BasicType):
    fmt='q'
    
class DWORD(LONG):
    pass

class CHAR(BasicType):
    fmt='c'

class BYTE(BasicType):
    fmt='b'
    
    def __str__(self):
        if not self.data:
            self.initialise()

        ## This is done to remove deprecation warnings:
        str="%x" % (0x100+self.data)
        return "0x%s" % (str[-2:])
    
class SimpleStruct(DataType):
    """ A class representing a simple struct to read off disk """
    field_names = ["Type","Count","Name","Description","Function" ]

    def __init__(self,buffer,offset,*args,**kwargs):
        self.parent=kwargs['parent']
        DataType.__init__(self,buffer,offset,*args,**kwargs)
        self.init()
        self.data={}
        self.offsets={}

    def init(self):
        raise AttributeError("%r: You must override this method and set self.fields in here!!!" % self)
    
    def read(self,data):
        fields = NamedArray(self.fields,self.field_names)
        offset=0
        result={}
        for item in fields:
            tmp=item['Type'](data,offset,item['Count'],parent=self)
            self.offsets[item['Name']]=offset
            offset+=tmp.size()
            result[item['Name']]=tmp
            
        return result

    def size(self):
        size=0

        if not self.data:
            self.initialise()
            
        for i in self.data.values():
            size+=i.size()
            
        return size
            
    def __str__(self):
        """ Prints the array nicely """
        if not self.data:
            self.initialise()

        result='Struct %s:\n' % ("%s" %self.__class__).split('.')[-1]
        result+='-'*(len(result)-1)+"\n"

        for i in range(len(self.fields)):
            item=NamedArray(self.fields[i],self.field_names)
            try:
                desc = item['Description']
            except:
                desc = item['Name']
                
            try:
                result+="%04X - %s(%s): %s\n" % (
                    self.offsets[item['Name']]+self.offset,
                    item['Name'],                   
                    desc,
                    item['Function'](self.data[item['Name']]))
            except IndexError,e:
                tmp = "\n   ".join(("%s" % self.data[item['Name']]).splitlines())
                result+="%04X - %s(%s): %s\n" % (
                    self.offsets[item['Name']]+self.offset,
                    item['Name'],
                    desc,tmp)
                                  
        return result

    def __getitem__(self,attr):
        if not self.data:
            self.initialise()
            
        return self.data[attr]

class POINTER(LONG):
    """ This represents a pointer to a struct within the file """
    def __init__(self,buffer,offset,*args,**kwargs):
        LONG.__init__(self,buffer,offset,*args,**kwargs)
        self.pointed=None
        
    def read(self,data):
        result=LONG.read(self,data)
        self.pointed = self.target_class(self.buffer,self.data,parent=self.parent)
        return result

    def p(self):
        if not self.pointed:
            self.initialise()
        return self.pointed
    
    def __str__(self):
        if not self.data:
            self.initialise()
            
        result="*%s\n" % self.data
        return result

class StructArray(SimpleStruct):
    def __init__(self,buffer,offset,count,*args,**kwargs):
        self.count=count
        SimpleStruct.__init__(self,buffer,offset,*args,**kwargs)
        self.data=[]

    def init(self):
        pass

    def size(self):
        size=0
        if not self.data:
            self.initialise()
            
        for x in self.data:
            size += x.size() 

        return size

    def __str__(self):
        if not self.data:
            self.initialise()
            
        result = "Array %s:" % ("%s" %self.__class__).split('.')[-1]
        for i in range(len(self.data)):
            result+="\nMember %s of %s:\n" % (i,len(self.data))
            result+="\n  ".join(self.data[i].__str__().splitlines())

        return result

    def read(self,data):
        result=[]
        offset=0
        for x in range(self.count):
            tmp=self.target_class(data,offset,parent=self)
            result.append(tmp)
            offset+=tmp.size()

        return result

    def extend(self,target):
        ## Ensure that the target has been evaluated
        if not target.data:
            target.initialise()
            
        self.data+=target.data
        
    def __eq__(self,target):
        if not self.data:
            self.initialise()
            
        for x in range(len(self.data)):
            if not self.data[x]==target[x]:
                return False
        return True

    def __iter__(self):
        if not self.data: self.initialise()
        
        self.index=0
        return self

    def next(self):
        try:
            result=self.data[self.index]
        except IndexError:
            raise StopIteration()
        self.index+=1
        return result

    def get_value(self):
        if not self.data:
            self.initialise()
            
        return [ x.get_value() for x in self.data ]
            
class ARRAY(StructArray):
    def __str__(self):
        if not self.data:
            self.initialise()
            
        result = ','.join([a.__str__() for a in self.data])
        return result

class BYTE_ARRAY(ARRAY):
    target_class=BYTE


class WORD_ARRAY(ARRAY):
    target_class=WORD

class LONG_ARRAY(ARRAY):
    target_class = LONG

class ULONG_ARRAY(ARRAY):
    target_class = ULONG

class STRING(BYTE):
    def __init__(self,buffer,offset,count,*args,**kwargs):
        self.fmt="%ss" % count
        BYTE.__init__(self,buffer,offset,count,*args,**kwargs)

    def __str__(self):
        if not self.data: self.initialise()
        return "%s" % self.data

    def substr(self,start,end):
        """ Truncates the string at a certain point """
        self.data=self.data[start:end]
        
class BYTE_ENUM(BYTE):
    types={}
    
    def read(self,data):
        result=BYTE.read(self,data)
        try:
            return self.types[result]
        except KeyError:
            return "Unknown (%s)" % result
    
    def __str__(self):
        if not self.data: self.initialise()
        return self.data

class UCS16_STR(STRING):
    def  read(self,data):
        """ FIXME: do proper UCS16 processing here """
        result=STRING.read(self,data)
        return ''.join([ result[i] for i in range(0,len(result),2)])

class CLSID(ULONG_ARRAY):
    """ A class id - common in windows """
    def __init__(self,buffer,offset,*args,**kwargs):
        ARRAY.__init__(self,buffer,offset,4,*args,**kwargs)

    def __str__(self):
        if not self.data: self.initialise()
        result=[]
        for i in self:
            result.append("%0.8X" % i.get_value())

        return "{%s}" % '-'.join(result)

class WIN_FILETIME(SimpleStruct):
    """ A FileTime 8 byte time commonly see in windows.

    This represent the number of 100ns periods since 1601 - how did they come up with that???
    """
    def init(self):
        self.fields = [
            [ ULONG,1,'low'],
            [ ULONG,1,'high']
            ]

    def to_unixtime(self):
        """ Returns the current time as a unix time """
        t=float(self['high'].get_value())* 2**32 +self['low'].get_value()
        return (t*1e-7 - 11644473600)

    def __str__(self):
        return "%s" % (time.ctime(self.to_unixtime()))
