import pyflag.Registry as Registry
import pyflag.FlagFramework as FlagFramework
import pyflag.format as format
import pyflag.HTMLUI as HTMLUI
import plugins.FileFormats.BasicFormats as BasicFormats

def numeric(num_str):
    try:
        if num_str.find('0x') == 0:
            result = int(num_str[2:],16)
        else:
            result = int(num_str)
    except TypeError:
        result = 0

    return result

class DynamicStruct(BasicFormats.SimpleStruct):
    def init(self):
        self.fields=[]

    def create_fields(self, query, key_prefix):
        self.count = 0
        parameters={}
        while 1:
            try:
                parameters[self.count]={}
                for k in query.keys():
                    key = '%s%s_' % (key_prefix, self.count)
                    if k.startswith(key):
                        parameters[self.count][k[len(key):]] = query[k]

                self.fields.append((Registry.FILEFORMATS[query['data_type_%s' % self.count]],
                                      parameters[self.count],
                                      query['name_%s' % self.count]
                                      ))
                self.count+=1
            except KeyError:
                break
        print self.fields
        
class AlignedOffset(format.DataType):
    visible = True
    def __init__(self, buffer, parameters, *args, **kwargs):
        self.buffer = buffer
        self.parameters = parameters

    def size(self):
        """ This consumes as many bytes until the next alignment boundary """
	align = numeric(self.parameters['alignment'])

	if self.buffer.offset % align == 0:
	    size = 0
	else:
	    size = align - (self.buffer.offset % align)

        return size 

    def __str__(self):
        return "Aligned to %s\nat 0x%08X" % (self.parameters['alignment'],
                                        self.buffer.offset + self.size())

    def form(self,prefix, query,result):
        result.textfield("Alignment boundary",prefix+"alignment")

class Offset(format.DataType):
    visible = True
    def __init__(self, buffer, parameters, *args, **kwargs):
        self.buffer = buffer

    def size(self):
        return 0

    def __str__(self):
        return "(0x%08X)" % self.buffer.offset

class SearchFor(format.DataType):

    visible = True
    max_blocksize=1024*1024
    initial_blocksize=1024

    def __init__(self, buffer, parameters, *args, **kwargs):
        self.buffer = buffer
        self.parameters = parameters
        self.data = None

    def read(self,data):
        try:
            blocksize=numeric(self.parameters['within'])
        except KeyError:
            blocksize=1024
            
        tmp=''
        tmp=data[0:blocksize].__str__()
        search = eval("'"+self.parameters['search']+"'")
        offset=tmp.find(search)

        if offset == -1:
            self.raw_size = blocksize
        else:
            self.raw_size = offset

        return data[0:self.raw_size]

    def size(self):
        if not self.data:
            self.initialise()
            
        return self.raw_size

    def __str__(self):
        return "Search for %s (0x%X bytes consumed)" % (self.parameters['search'], self.size())

    def form(self, prefix, query, result):
        result.textfield("Search string",prefix+"search")
        result.textfield("within n bytes",prefix+"within")
        
class HexDump(BasicFormats.STRING):
    sql_type = "text"
    
    def display(self, result):
        h=FlagFramework.HexDump(self.__str__(),result)
        h.dump()

    def get_value(self):
        tmp = HTMLUI.HTMLUI(None)
        self.display(tmp)
        return tmp
