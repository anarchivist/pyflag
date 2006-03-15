from pyflag.format import *
    
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

    def form(self,prefix, query,result):
        result.row("Size", self.size())

class WORD(BasicType):
    """ Reads a word (short int) from the data in big endian """
    fmt = '=H'
    visible = True
    
    def __str__(self):
        if not self.data:
            self.initialise()

        return "0x%X" % (self.data,)

class LONG(BasicType):
    fmt='=l'
    visible = True
    
class ULONG(BasicType):
    fmt='=L'
    visible = True
    
    def __str__(self):
        if not self.data:
            self.initialise()

        return "%s (0x%X)" % (self.data,self.data)

class LONGLONG(BasicType):
    fmt='=q'
    visible = True
    
class DWORD(LONG):
    pass

class CHAR(BasicType):
    fmt='=c'
    visible = True

class BYTE(BasicType):
    fmt='=b'
    visible = True
        
    def __str__(self):
        if not self.data:
            self.initialise()

        ## This is done to remove deprecation warnings:
        return "%02x" % (self.data,)
    
class SimpleStruct(DataType):
    """ A class representing a simple struct to read off disk """
    field_names = ["Type","Parameters","Name","Description","Function" ]

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
        pass
##        raise AttributeError("%r: You must override this method and set self.fields in here!!!" % self)

    def add_element(self,dict,element,name):
        """ Adds an element to the dict as well as to the fields table.

        This function allows users to dynamically add new elements to the struct from the read() method.
        """
        dict[name]=element
        self.fields.append([element.__class__,element.size(),name])
        self.offsets[name]=element.buffer.offset-self.buffer.offset
    
    def read(self,data):
        fields = NamedArray(self.fields,self.field_names)
        offset=0
        result={}
        ## Temporarily set our data dict to be result, so that
        ## instantiated classes can call parent['boo'] to retrieve
        ## items already parsed.
        self.data=result
        for item in fields:
            tmp=item['Type'](data[offset:],item['Parameters'],parent=self)
            self.offsets[item['Name']]=offset
            offset+=tmp.size()
            result[item['Name']]=tmp
            
        return result

    def calculate_struct_size(self,struct):
        """ calculates the total size of struct by summing its individual sizes.

        struct is a dict of classes.
        """
        size=0
    
        for i in struct.values():
            size+=i.size()
        
        return size
        
    def size(self):
        if not self.data:
            self.initialise()

        return self.calculate_struct_size(self.data)
            
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

            element=self.data[item['Name']]
            tmp = "\n   ".join((element.__str__()).splitlines())
            result+="%04X - %s(%s): %s\n" % (
#                self.offsets[item['Name']] + self.buffer.offset,
                element.buffer.offset,
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

    def form(self,prefix, query,result):
        result.row("Size", self.calculate_struct_size(self.data))
        
class POINTER(LONG):
    """ This represents a pointer to a struct within the file """
    visible = True
    
    def __init__(self,buffer,*args,**kwargs):
        LONG.__init__(self,buffer,*args,**kwargs)
        self.pointed=None

    def calc_offset(self,data,offset):
        """ Given the offset we just read, return an new offset.

        Note that it is expected that this method update the offsets within data to point to the correct place """
        ## The data is pointed to is relative to our parents structure
        offset=self.parent.buffer.offset+offset
        return data.set_offset(offset)
    
    def read(self,data):
        result=LONG.read(self,data)
        data=self.calc_offset(data,result)
        if data:
            result=data.offset
        
        if result>0:
            self.pointed = self.target_class(data,parent=self.parent)
        else: self.pointed=None
        return result

    def p(self):
        if not self.pointed:
            self.initialise()
            
        return self.pointed
    
    def __str__(self):
        if not self.data:
            self.initialise()
            
        result="->%s (0x%08X)" % (self.data,self.data)
        return result

class StructArray(SimpleStruct):
    def __init__(self,buffer,parameters,*args,**kwargs):
        try:
            self.count=parameters['count']
        except:
            self.count=0
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
    visible = True
    
    def __init__(self,buffer,parameters,*args,**kwargs):
        try:
            self.fmt="%ss" % parameters['length']
        except:
            self.fmt="1s"
            
        BYTE.__init__(self,buffer,parameters,*args,**kwargs)

    def __str__(self):
        if not self.data: self.initialise()
        return "%s" % self.data

    def substr(self,start,end):
        """ Truncates the string at a certain point """
        self.data=self.data[start:end]

    def form(self,prefix, query,result):
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
    def read(self,data):
        blocksize=self.initial_blocksize
        tmp=''
        end=-1
        while end<0:
            tmp=data[0:blocksize].__str__()
            end=tmp.find(self.terminator)
            
            if len(tmp)<blocksize and end<0:
                end=blocksize
                break

            blocksize*=2
            if blocksize>self.max_blocksize:
                end=self.max_blocksize
                break

        ## The size of this string includes the terminator
        self.raw_size=end+len(self.terminator)
        return data[0:self.raw_size]
    
    def size(self):
        if not self.data:
            self.initialise()
            
        return self.raw_size

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

    def get_value(self):
        if not self.data:
            self.initialise()
            
        return self.types[self.data]
    
class LONG_ENUM(BYTE_ENUM):
    fmt='=l'    

class WORD_ENUM(BYTE_ENUM):
    fmt='=H'    

class BitField(BYTE):
    ## This stores the masks
    masks = {}

    def __str__(self):
        if not self.data: self.initialise()
        result=[ v for k,v in self.masks.items() if k & self.data ]
        return ','.join(result)

class UCS16_STR(STRING):
    visible = True
    
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
    visible = True
    
    def __init__(self,buffer,*args,**kwargs):
        ARRAY.__init__(self,buffer,4,*args,**kwargs)

    def __str__(self):
        if not self.data: self.initialise()
        result=[]
        for i in self:
            result.append("%0.8X" % i.get_value())

        return "{%s}" % '-'.join(result)

class TIMESTAMP(LONG):
    """ A standard unix timestamp.

    Number of seconds since the epoch (1970-1-1)
    """
    visible = True
    
    def __str__(self):
        if not self.data:
            self.initialise()
            
        return "%s" % time.ctime(self.data)

class WIN_FILETIME(SimpleStruct):
    """ A FileTime 8 byte time commonly see in windows.

    This represent the number of 100ns periods since 1601 - how did they come up with that???
    """
    visible = True
    
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
        return time.strftime("%Y%m%d%H%M%S",time.localtime(t))

#        return "%s" % (time.ctime(t))


class WIN12_FILETIME(WIN_FILETIME):
    """ A 12 byte variant of above. Last LONG is just all zeros usually so we ignore it """
    visible = True
    
    def init(self):
        WIN_FILETIME.init(self)
        self.fields.append([ ULONG,1,'pad'])

class LPSTR(STRING):
    """ This is a string with a size before it """
    visible = True
    
    def __init__(self,buffer,*args,**kwargs):
        BYTE.__init__(self,buffer,*args,**kwargs)

    def read(self,data):
        length = LONG(data)
        self.fmt="%ss" % length.get_value()
        return STRING.read(self,data[length.size():])
