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
    def __init__(self,string='',fd=None,offset=0,size=0):
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
        self.offset=offset

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
    
class BasicType(DataType):
    """ Base class for basic types that unpack understands """
    def size(self):
        ## We consume 2 bytes here
        return struct.calcsize(self.fmt)

    def read(self,data):
        return struct.unpack(self.fmt,data[:self.size()].__str__())[0]

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

        try:
            return self.data==self.read(target)
        except:
            return False

class WORD(BasicType):
    """ Reads a word (short int) from the data in big endian """
    fmt = 'H'
    def __str__(self):
        if not self.data:
            self.initialise()

        return "0x%X" % (self.data,)

class LONG(BasicType):
    fmt='l'

class ULONG(BasicType):
    fmt='L'
    
    def __str__(self):
        if not self.data:
            self.initialise()

        return "%s (0x%X)" % (self.data,self.data)

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

    def __init__(self,buffer,*args,**kwargs):
        try:
            self.parent=kwargs['parent']
        except:
            self.parent=None
        DataType.__init__(self,buffer,*args,**kwargs)
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
            tmp=item['Type'](data[offset:],item['Count'],parent=self)
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

            tmp = "\n   ".join((self.data[item['Name']].__str__()).splitlines())
            result+="%04X - %s(%s): %s\n" % (
                self.offsets[item['Name']] + self.buffer.offset,
                item['Name'],
                desc,tmp)
                                  
        return result

    def __getitem__(self,attr):
        if not self.data:
            self.initialise()
            
        return self.data[attr]


    def __setitem__(self,k,attr):
        print "Setting %s to %s " % (k,attr)
        if not self.data:
            self.initialise()

        self.data[k]=attr
        
class POINTER(LONG):
    """ This represents a pointer to a struct within the file """
    def __init__(self,buffer,*args,**kwargs):
        LONG.__init__(self,buffer,*args,**kwargs)
        self.pointed=None

    def calc_offset(self,data,offset):
        """ Given the offset we just read, return a buffer from data pointing to the correct place """
        ## The data is pointed to is relative to our parents structure
        offset=self.parent.buffer.offset+offset
        data.set_offset(offset)
        return data
    
    def read(self,data):
        result=LONG.read(self,data)
        data=self.calc_offset(data,result)
        self.pointed = self.target_class(data,parent=self.parent)
        return result

    def p(self):
        if not self.pointed:
            self.initialise()
        return self.pointed
    
    def __str__(self):
        if not self.data:
            self.initialise()
            
        result="->%s" % self.data
        return result

class StructArray(SimpleStruct):
    def __init__(self,buffer,count,*args,**kwargs):
        self.count=count
        SimpleStruct.__init__(self,buffer,*args,**kwargs)
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
            ## If we run out of space, we just stop.
            if offset>=len(data): break
            tmp=self.target_class(data[offset:],parent=self)
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
    def __init__(self,buffer,count,*args,**kwargs):
        self.fmt="%ss" % count
        BYTE.__init__(self,buffer,count,*args,**kwargs)

    def __str__(self):
        if not self.data: self.initialise()
        return "%s" % self.data

    def substr(self,start,end):
        """ Truncates the string at a certain point """
        self.data=self.data[start:end]

class TERMINATED_STRING(DataType):
    """ This data structure represents a string which is terminated by a terminator.

    For efficiency we read large blocks and use string finds to locate the terminator
    """
    terminator='\x00'
    max_blocksize=1024*1024
    initial_blocksize=1024
    def read(self,data):
        blocksize=self.initial_blocksize
        tmp=''
        end=-1
        while end<0:
            tmp=data[:blocksize].__str__()
            if len(tmp)<blocksize:
                end=blocksize
                break

            end=tmp.find(self.terminator)
            blocksize*=2
            if blocksize>self.max_blocksize:
                end=self.max_blocksize
                break

        return data[0:end]

    def get_value(self):
        if not self.data:
            self.initialise()
            
        return self.data

    def __eq__(self,target):
        if not self.data:
            self.initialise()
            
        return self.data==target

    def __getitem__(self,x):
        if not self.data:
            self.initialise()

        print "x is %s" % x
        return self.data[x]
        
class BYTE_ENUM(BYTE):
    types={}
    
    def read(self,data):
        result=BYTE.read(self,data)
        return result
        
    def __str__(self):
        if not self.data: self.initialise()
        try:
            return "%s (%s)" % (self.data,self.types[self.data])
        except KeyError:
            return "Unknown (%s)" % self.data
    
    def __eq__(self,target):
        if not self.data:
            self.initialise()
        try:    
            return target==self.types[self.data]
        except KeyError:
            return target==self.data
    
class LONG_ENUM(BYTE_ENUM):
    fmt='l'    

class WORD_ENUM(BYTE_ENUM):
    fmt='H'    

class UCS16_STR(STRING):
    def  read(self,data):
        result=STRING.read(self,data)
        ## This is the common encoding for windows system:
        try:
            return result.decode("utf_16_le")
        except UnicodeDecodeError:
            print "Unable to decode %s" % result
            raise

    def __str__(self):
        if not self.data:
            self.initialise()
            
        try:
            return "%s" % self.data.__str__()
        except UnicodeEncodeError:
            return "%r" % self.data
        
class CLSID(ULONG_ARRAY):
    """ A class id - common in windows """
    def __init__(self,buffer,*args,**kwargs):
        ARRAY.__init__(self,buffer,4,*args,**kwargs)

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

    def get_value(self):
        """ We just return the unix time here """
        return self.to_unixtime()

    def __str__(self):
        t = self.to_unixtime()
        if t<0: return "Invalid Timestamp"
        return "%s" % (time.ctime(t))

class WIN12_FILETIME(WIN_FILETIME):
    """ A 12 byte variant of above. Last LONG is just all zeros usually so we ignore it """
    def init(self):
        WIN_FILETIME.init(self)
        self.fields.append([ ULONG,1,'pad'])

class LPSTR(STRING):
    """ This is a string with a size before it """
    def __init__(self,buffer,*args,**kwargs):
        BYTE.__init__(self,buffer,*args,**kwargs)

    def read(self,data):
        length = LONG(data)
        self.fmt="%ss" % length.get_value()
        return STRING.read(self,data[length.size():])
