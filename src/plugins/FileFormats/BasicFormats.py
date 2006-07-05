from pyflag.format import *
    
class BasicType(DataType):
    """ Base class for basic types that unpack understands """
    sql_type = "int"
    
    def size(self):
        ## We consume 2 bytes here
        return struct.calcsize(self.fmt)

    def read(self):
        try:
            return struct.unpack(self.fmt,self.buffer[:self.size()].__str__())[0]
        except struct.error,e:
            raise IOError("%s"% e)

    def __int__(self):
        return int(self.data)

    def get_value(self):
        return self.data

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

class LONG(BasicType):
    fmt='=l'
    visible = True
    
class ULONG(BasicType):
    fmt='=L'
    visible = True
    
    def __str__(self):
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
        ## This is done to remove deprecation warnings:
        return "%02x" % (self.data,)

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

    def __init__(self,buffer,*args,**kwargs):
        self.buffer = buffer
        self.init()
            
        self.data={}
        self.offsets={}
        DataType.__init__(self,buffer,*args,**kwargs)

    def init(self):
        pass
##        raise AttributeError("%r: You must override this method and set self.fields in here!!!" % self)

    def add_element(self,result, name,element, *args):
        """ Adds an element to the dict as well as to the fields table.

        This function allows users to dynamically add new elements to the struct from the read() method.
        """
        result[name]=element
        self.fields.append([name, element.__class__])
        self.offsets[name]=element.buffer.offset-self.buffer.offset
    
    def read(self):
        self.offset=0
        result={}
        ## Temporarily set our data dict to be result, so that
        ## instantiated classes can call parent['boo'] to retrieve
        ## items already parsed.
        #self.data=result
        
        for item in self.fields:
            try:
                name = item[0]
                element = item[1]
            except:
                continue

            try:
                parameters = item[2]
            except:
                parameters = {}

            result[name]=element(self.buffer[self.offset:],**parameters)
            self.offsets[name]=self.offset            
            self.offset+=result[name].size()
                
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

            element=self.data[item[0]]
            tmp = "\n   ".join((element.__str__()).splitlines())
            result+="%04X - %s: %s\n" % (
                element.buffer.offset,
                desc,tmp)
                                  
        return result

    def __getitem__(self,attr):
        return self.data[attr]

    def __setitem__(self,k,attr):
        print "Setting %s to %s " % (k,attr)
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
            self.count=kwargs['count']
        except:
            self.count=0

        self.fields = [ [i,self.target_class] for i in range(self.count)]        
        SimpleStruct.__init__(self,buffer,*args,**kwargs)

    def __str__(self):
        result = "Array %s:" % ("%s" %self.__class__).split('.')[-1]
        for i in range(self.count):
            result+="\nMember %s of %s:\n" % (i,self.count)
            result+="\n  ".join(self.data[i].__str__().splitlines())

        return result

    def extend(self,target):
        ## Ensure that the target has been evaluated
        self.count+=1
        self.data[self.count]=target
        
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
        result = ','.join([self.data[a].__str__() for a in range(self.count)])
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
    sql_type="text"
    
    def __init__(self,buffer,*args,**kwargs):
        try:
            self.fmt = "%ss" % kwargs['length']
        except:
            raise SystemError("you must specify the length of a STRING")
        
        BYTE.__init__(self,buffer,*args,**kwargs)

    def __str__(self):
        return "%s" % self.data

    def substr(self,start,end):
        """ Truncates the string at a certain point """
        self.data=self.data[start:end]

##    def read(self,data):
##        try:
##            length = int(self.paralength)
##        except ValueError,e:
##            print 'Read ValueError %s' % e
##            sibname = ''
##            sibnameoffset = self.paralength.find('col.')
##            if sibnameoffset != -1:
##                sibnameoffset += 4
##                while 1:
##                    try:
##                        if self.paralength[sibnameoffset].isalnum():
##                            sibname += self.paralength[sibnameoffset]
##                            sibnameoffset += 1
##                        else:
##                            break
##                    except IndexError:
##                        break
##                print 'sibname %s' % sibname
##                t = self.parent.data[sibname]
##                value = t.get_value()
##                evalexpr = self.paralength.replace('col.%s' % sibname, 'value')
##                print 'eval expression: %s' % evalexpr
##                length = eval(evalexpr, {'value':value})
##                print 'length %s' % length
##            else:
##                length = 1

            
##        self.fmt="%ss" % length
##        try:
##            return struct.unpack(self.fmt,data[:self.size()].__str__())[0]
##        except struct.error,e:
##            raise IOError("%s"% e)

    def form(self,prefix, query,result):
        print "\nString Form\n"
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

    def read(self):
        blocksize=self.initial_blocksize
        tmp=''
        end=-1
        while end<0:
            tmp=self.buffer[0:blocksize].__str__()
            end=tmp.find(self.terminator)

            if end>0:
                break
            
            blocksize*=2
            if blocksize>self.max_blocksize:
                end=self.max_blocksize
                break

        ## The size of this string includes the terminator
        self.raw_size=end+len(self.terminator)
        return self.buffer[0:self.raw_size]
    
    def size(self):
        return self.raw_size

    def get_value(self):
        return self.data

    def __eq__(self,target):
        return self.data==target

    def __getitem__(self,x):
        print "x is %s" % x
        return self.data[x]
        
class BYTE_ENUM(BYTE):
    types={}

    def __str__(self):
        try:
            return "%s (%s)" % (self.data,self.types[self.data])
        except KeyError:
            return "Unknown (%s)" % self.data
    
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
    
    def  read(self):
        result=STRING.read(self)
        ## This is the common encoding for windows system:
        try:
            return result.decode("utf_16_le")
        except UnicodeDecodeError:
            print "Unable to decode %s" % result
            return "Unable to decode '%r'" % result

    def __str__(self):
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
        return "%s" % time.ctime(self.data)

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
        self.fields.append(['pad',ULONG])

class LPSTR(STRING):
    """ This is a string with a size before it """
    visible = True
    
    def __init__(self,buffer,*args,**kwargs):
        BYTE.__init__(self,buffer,*args,**kwargs)

    def read(self):
        length = LONG(self.buffer)
        self.fmt="%ss" % length.get_value()
        return STRING(self.buffer[length.size():], length=length)
