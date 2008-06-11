# ******************************************************
# Copyright 2006
#
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.87-pre1 Date: Thu Jun 12 00:48:38 EST 2008$
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
from pyflag.format import *
    
class BasicType(DataType):
    """ Base class for basic types that unpack understands """
    sql_type = "int"

    def __init__(self,buffer,*args,**kwargs):
        try:
            if kwargs['endianess'].startswith('l'):
                direction = "<"
            elif kwargs['endianess'].startswith('b'):
                direction = ">"

            ## Enforce the endianess
            if self.fmt[0] in '<>=@':
                self.fmt = direction+self.fmt[1:]
            else:
                self.fmt = direction+self.fmt

        except KeyError:
            pass

        try:
            self.data = kwargs['value']
        except KeyError:
            pass

        DataType.__init__(self,buffer,*args,**kwargs)
    
    def size(self):
        return struct.calcsize(self.fmt)

    def read(self):
        try:
            length = struct.calcsize(self.fmt)
            if length>0:
                return struct.unpack(self.fmt,self.buffer[:length].__str__())[0]
            return ''
        except struct.error,e:
            raise IOError("%s. Tried to use format string %s"% (e, self.fmt))

    def write(self, output):
        try:
#            print "%r" % self,self.data, self.fmt
            data = struct.pack(self.fmt, self.data)
            output.write(data)
        except struct.error,e:
            raise IOError("%s" % e)

    def __int__(self):
        return int(self.data)

    def get_value(self):
        return self.data

    def set_value(self,v):
        self.data=v

    def __eq__(self,target):
        if isinstance(target,int):
            return self.data==target

        try:
            return self.data==target
        except:
            return False

    def form(self,prefix, query,result):
        result.row("Size", self.size())

class WORD(BasicType):
    """ Reads a word (short int) from the data in big endian """
    fmt = '=H'
    visible = True
    sql_type = "int"
        
    def __str__(self):
        return "0x%X" % (self.data,)

class USHORT(WORD):
    pass

class LONG(BasicType):
    fmt='=l'
    visible = True
    
class ULONG(BasicType):
    fmt='=L'
    visible = True
    
    def __str__(self):
        return "%s (0x%X)" % (self.data,self.data)

class ULONG_CONSTANT(ULONG):
    """ This class enforces a condition raising an error otherwise """
    def read(self):
        result = ULONG.read(self)
        if not result==self.parameters['expected']:
            raise RuntimeError("Expected value 0x%X, got 0x%X" %( self.parameters['expected'], result))

        return result

class USHORT_CONSTANT(USHORT):
    """ This class enforces a condition raising an error otherwise """
    def read(self):
        result = USHORT.read(self)
        if not result==self.parameters['expected']:
            raise RuntimeError("Expected value 0x%X, got 0x%X" %( self.parameters['expected'], result))
        
        return result

class LEWORD(WORD):
    fmt = "<H"

class LELONG(LONG):
    fmt = "<l"

class LEULONG(ULONG):
    fmt = "<L"

class BEWORD(WORD):
    fmt = ">H"

class BELONG(LONG):
    fmt = ">l"

class BEULONG(ULONG):
    fmt = ">L"

class LONGLONG(BasicType):
    fmt='=q'
    visible = True
    
class DWORD(LONG):
    pass

class CHAR(BasicType):
    fmt='=c'
    visible = True

class BYTE(BasicType):
    fmt='b'
    visible = True
        
    def __str__(self):
        ## This is done to remove deprecation warnings:
        try:
            return "%0x" % (self.data,)
        except: return self.data

class BYTE_CONSTANT(BYTE):
    """ This class enforces a condition raising an error otherwise """
    def read(self):
        result = BYTE.read(self)
        if not result==self.parameters['expected']:
            raise RuntimeError("Expected value 0x%X, got 0x%X" %( self.parameters['expected'], result))
        
        return result

class UBYTE(BasicType):
    fmt='=B'
    visible = True
        
    def __str__(self):
        ## This is done to remove deprecation warnings:
        return "%02x" % (self.data,)

class SimpleStruct(DataType):
    """ A class representing a simple struct to read off disk """
    ## These are the fields that are required to define the
    ## struct. They may be terminated at any time for exmaple the
    ## array may stop after Name:
    ## ["Name","Type","Parameters","Description","Function" ]
    fields = []

    def __init__(self,buffer,*args,**kwargs):
        self.buffer = buffer
        self.parameters = kwargs
        ## Keep a reference to our original fields list
        self._fields = self.fields

        ## This may change the fields attribute
        self.init()
            
        self.data={}
        self.offsets={}
        DataType.__init__(self,buffer,*args,**kwargs)

    def init(self):
        pass

    def add_element(self,result, name,element, *args):
        """ Adds an element to the dict as well as to the fields table.

        This function allows users to dynamically add new elements to the struct from the read() method.
        """
        ## we are about to modify our fields attribute. We should make
        ## a copy to ensure that we do not modify the class
        ## attribute. This is done so that fields can be filled in the
        ## class definition to make it more efficient.
        if self._fields==self.fields:
            self.fields=self.fields[:]
        
        result[name]=element
        self.fields.append([name, element.__class__])
        self.offsets[name]=element.buffer.offset-self.buffer.offset
    
    def read(self):
        self.offset=0
        result={}
        
        for item in self.fields:
            try:
                name = item[0]
                element = item[1]
            except:
                continue

            parameters = self.parameters.copy()
            try:
                parameters.update(item[2])
            except Exception,e:
                parameters = {}

            ## Evaluate the parameters if needed:
            for k,v in parameters.items():
                if callable(v):
                    parameters[k]=v(result)

            ## Handle offset specially:
            if parameters.has_key('offset'):
                self.offset = parameters['offset']
                ## Consume the offset to prevent it from propegating
                ## to the element (in case its a SimpleStruct too).
                del parameters['offset']

            try:
                result[name]=element(self.buffer[self.offset:],**parameters)
            except Exception,e:
                #raise
                raise e.__class__("When parsing field %r of %s, %s" % (name, self.__class__,e))

            self.offsets[name]=self.offset            
            self.offset+=result[name].size()

            if self.offset >= self.buffer.size: break
                
        return result

    def write(self,output):
        for item in self.fields:
            self.data[item[0]].write(output)

    def calculate_struct_size(self,struct):
        """ calculates the total size of struct by summing its individual sizes.

        struct is a dict of classes.
        """
        size=0
    
        for i in struct.values():
            size+=i.size()
        
        return size
        
    def size(self):
        return self.calculate_struct_size(self.data)
            
    def __str__(self):
        """ Prints the array nicely """
        result='Struct %s:\n' % ("%s" %self.__class__).split('.')[-1]
        result+='-'*(len(result)-1)+"\n"

        for i in range(len(self.fields)):
            item=self.fields[i]
            try:
                desc = "%s(%s)" % (item[0],item[3])
            except:
                desc = item[0]

            try:
                element=self.data[item[0]]
            except KeyError: continue
            
            tmp = "\n   ".join((element.__str__()).splitlines())
            result+="%04X - %s: %s\n" % (
                element.buffer.offset,
                desc,tmp)
                                  
        return result

    def __getitem__(self,attr):
        return self.data[attr]

    def __setitem__(self,k,attr):
##        print "Setting %s to %s " % (k,attr)
        self.data[k]=attr

    def form(self,prefix, query,result):
        result.row("Size", self.calculate_struct_size(self.data))
        
class POINTER(LONG):
    """ This represents a pointer to a struct within the file """
    visible = True
    
    def __init__(self,buffer,*args,**kwargs):
        LONG.__init__(self,buffer,*args,**kwargs)
        try:
            self.relative_offset = kwargs['relative_offset']
        except:
            self.relative_offset = 0

    def calc_offset(self):
        """ return a buffer object seeked to the correct offset """
        offset=self.relative_offset+self.data
        return self.buffer.set_offset(offset)
    
    def get_value(self):
        data = self.calc_offset()

        if data==None: return None
        
        return self.target_class(data)

    def __str__(self):
        result="->%s (0x%08X)" % (self.data,self.data)
        return result

class StructArray(SimpleStruct):
    def __init__(self,buffer,*args,**kwargs):
        try:
            self.count=int(kwargs['count'])
#            print self.count
        except:
            self.count=0

        self.fields = [ [i,self.target_class, kwargs] for i in range(self.count)]        
#        if buffer:
#            print "offset %X %s" % (buffer.offset, buffer.size)

        SimpleStruct.__init__(self,buffer,*args,**kwargs)

    def __str__(self):
        result = "Array %s:" % ("%s" %self.__class__).split('.')[-1]
        for i in range(self.count):
            result+="\nMember %s of %s:\n" % (i,self.count)
            result+="\n  ".join(self.data[i].__str__().splitlines())

        return result

    def extend(self,target):
        self.data[self.count]=target
        self.count+=1
        
    def __eq__(self,target):
        for x in range(self.count):
            try:
                if not self.data[x]==target[x]:
                    return False
            except:
                return False
            
        return True

    def __iter__(self):
        self.index=0
        return self

    def next(self):
        try:
            result=self.data[self.index]
        except (KeyError, IndexError):
            raise StopIteration()
        self.index+=1
        return result

    def get_value(self):
        return [ self.data[x].get_value() for x in range(self.count) ]
            
class ARRAY(StructArray):
    def __str__(self):
        result = ','.join([self.data[a].__str__() for a in range(self.count) if self.data.has_key(a)])
        return result

class BYTE_ARRAY(ARRAY):
    target_class=BYTE

class UBYTE_ARRAY(ARRAY):
    target_class=UBYTE

class WORD_ARRAY(ARRAY):
    target_class=WORD

class LONG_ARRAY(ARRAY):
    target_class = LONG

class ULONG_ARRAY(ARRAY):
    target_class = ULONG

class BELONG_ARRAY(ARRAY):
    target_class = BELONG

class BEULONG_ARRAY(ARRAY):
    target_class = BEULONG

class STRING(BYTE):
    visible = True
    
    def __init__(self,buffer,*args,**kwargs):
        try:
            self.data = kwargs['value']
            self.length = len(self.data)
            self.fmt = "%us" % self.length
        except KeyError:
            try:
                self.length = kwargs['length'].__int__()
                self.fmt = "%us" % self.length
            except:
                raise SystemError("you must specify the length of a STRING")

        BYTE.__init__(self,buffer,*args,**kwargs)

    def __str__(self):
        return "%s" % self.data

    def substr(self,start,end):
        """ Truncates the string at a certain point """
        self.data=self.data[start:end]

    def set_value(self, value):
        self.data = value
        ## Update our format string to use the length:
        self.length = len(value)
        self.fmt = "%ss" % self.length

    def __len__(self):
        return self.length

    def size(self):
        return self.length
    
    def form(self,prefix, query,result):
##        print "\nString Form\n"
        result.textfield("String length","%slength" % prefix)

    def display(self, result):
        result.text(self.__str__(), sanitise='full', font='typewriter')

class TERMINATED_STRING(DataType):
    """ This data structure represents a string which is terminated by a terminator.

    For efficiency we read large blocks and use string finds to locate the terminator
    """
    visible = True
    terminator='\x00'
    max_blocksize=1024*1024
    initial_blocksize=1024
    ## Do we include the terminator?
    inclusive = True

    def read(self):
        blocksize=self.initial_blocksize
        tmp=''
        end=-1
        while end<0:
            tmp=self.buffer[0:blocksize].__str__()
            end=tmp.find(self.terminator)

            if end>=0:
                break
            
            blocksize*=2
            if blocksize>self.max_blocksize:
                end=self.max_blocksize
                break

        ## The size of this string includes the terminator
        self.raw_size=end+len(self.terminator)
        return self.buffer[0:self.raw_size].__str__()
    
    def size(self):
        return self.raw_size

    def get_value(self):
        if self.inclusive:
            return self.data
        else:
            return self.data[:-len(self.terminator)]

    def __eq__(self,target):
        return self.data==target

    def __getitem__(self,x):
        return self.data[x]
        
class BYTE_ENUM(UBYTE):
    types={}

    def __str__(self):
        try:
            return "%s" % (self.types[self.data])
        except KeyError:
            return "Unknown (0x%02X)" % self.data
    
    def __eq__(self,target):
        try:    
            return target==self.types[self.data]
        except KeyError:
            return target==self.data

    def get_value(self):
        try:
            return self.types[self.data]
        except (KeyError,IndexError):
            return "Unknown (%s)" % self.data
    
class LONG_ENUM(BYTE_ENUM):
    fmt='=l'    

class WORD_ENUM(BYTE_ENUM):
    fmt='=H'    

class BitField(BYTE):
    ## This stores the masks
    masks = {}

    def __str__(self):
        result=[ v for k,v in self.masks.items() if k & self.data ]
        return ','.join(result)

class UCS16_STR(STRING):
    visible = True

    encoding = "utf_16_le"
    
    def  read(self):
        result=STRING.read(self)

        ## This is the common encoding for windows system:
        try:
            return result.decode(self.encoding)
        except UnicodeDecodeError:
            if result=='\0':
                return ''
            else:
                return "%r" % result

    def __str__(self):
        ## Return up to the first null termination
        try:
            result = self.data.__str__()
            try:
                return result[:result.index("\0")]
            except ValueError:
                return result
            
        except UnicodeEncodeError:
            return "%r" % self.data
        
class CLSID(ULONG_ARRAY):
    """ A class id - common in windows """
    visible = True
    
    def __init__(self,buffer,*args,**kwargs):
        ## Class IDs are 4 uint_32 long
        kwargs['count']=4
        ULONG_ARRAY.__init__(self,buffer,*args,**kwargs)

    def __str__(self):
        result=[]
        for i in self:
            result.append("%0.8X" % i.get_value())

        return "{%s}" % '-'.join(result)

class TIMESTAMP(ULONG):
    """ A standard unix timestamp.

    Number of seconds since the epoch (1970-1-1)
    """
    visible = True
    
    def __str__(self):
        return time.strftime("%Y/%m/%d %H:%M:%S",time.localtime(self.data))

class WIN_FILETIME(SimpleStruct):
    """ A FileTime 8 byte time commonly see in windows.

    This represent the number of 100ns periods since 1601 - how did they come up with that???
    """
    visible = True
    sql_type = "int"
    
    def init(self):
        self.fields = [
            [ 'low', ULONG ],
            [ 'high', ULONG ]
            ]

    def to_unixtime(self):
        """ Returns the current time as a unix time """
        t=float(self['high'].get_value())* 2**32 +self['low'].get_value()
        if t:
            return int(t*1e-7 - 11644473600)
        return 0

    def get_value(self):
        """ We just return the unix time here """
        return self.to_unixtime()

    def __str__(self):
        """ NOTE: time is returned in localtime according to your current TZ """
        t = self.to_unixtime()
        try:
            return time.strftime("%Y/%m/%d %H:%M:%S",time.localtime(t))
        except:
            return "Invalid Timestamp %X:%X" % (int(self['low']),int(self['high']))

#        return "%s" % (time.ctime(t))


class WIN12_FILETIME(WIN_FILETIME):
    """ A 12 byte variant of above. Last LONG is just all zeros usually so we ignore it """
    visible = True
    
    def init(self):
        WIN_FILETIME.init(self)
        self.fields.append(['pad',ULONG])

class LPSTR(SimpleStruct):
    """ This is a string with a size before it """
    def __init__(self, buffer,*args,**kwargs):
        SimpleStruct.__init__(self, buffer, *args,**kwargs)
        try:
            ## This initialises the LPSTR from kwargs
            length = len(kwargs['value'])
            new_string = STRING(kwargs['value'], length=length)
            
            self.data = dict(data = new_string,
                             length = ULONG(None, value=length))
            
        except KeyError:
            pass
        
    def init(self):
        self.fields = [
            [ 'length', LONG],
            [ 'data', STRING, dict(length=lambda x: x['length']) ]
            ]

    def set_value(self, value):
        """ Update our length field automatically """
        data = self['data']
        data.set_value(value)
        self['length'].set_value(len(data))

    def __str__(self):
        return self['data'].__str__()

class IPAddress(STRING):
    def __init__(self, buffer,*args,**kwargs):
        kwargs['length'] = 4
        STRING.__init__(self, buffer, *args, **kwargs)
        
    def __str__(self):
        return '.'.join([ord(x).__str__() for x in self.data])
