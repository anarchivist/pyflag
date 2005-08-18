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
#  Version: FLAG $Version: 0.78 Date: Fri Aug 19 00:47:14 EST 2005$
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
""" A Library to read the windows NT/2k/XP registry format.

"""
from format import *
import sys

## This is where the first page starts
FIRST_PAGE_OFFSET=0x1000

class NK_TYPE(WORD_ENUM):
    types = {
        0x20: 'key',
        0x2c: 'ROOT_KEY'
        }

class RegF(SimpleStruct):
    def init(self):
        self.fields=[
            [ STRING,4,'Magic'],
            [ LONG_ARRAY,2,'Unknown1'],
            [ WIN_FILETIME,1,'Last Modified'],
            [ LONG_ARRAY,4,'Unknown2'],
            ##Offset is relative to FIRST_PAGE_OFFSET. This offset is
            ##to the root key's nk record.
            [ PNK_key,1,'root_key_offset'],
            [ LONG,1,'filesize'],
            [ RegFName,0x1fc-0x2c,'Name'],
            [ RegFCheckSum,1,'checksum'],
            ]

class RegFName(STRING):
    """ A string which does not print NULLs """
    def __str__(self):
        result=[c for c in STRING.__str__(self) if c!='\x00' ]
        return ''.join(result)

class RegFCheckSum(STRING):
    def read(self,data):
        cs = ULONG(data).get_value()
        section_offset = self.parent.buffer.offset
        our_offset=self.buffer.offset
        sum=0
        offset=section_offset
        while offset<our_offset:
            data=data.set_offset(offset)
            byte=ULONG(data)
#            print "0x%X" % (0L + byte.get_value())
            sum+=byte.get_value()
            offset+=byte.size()

        return "given %x calculated %x" % (cs,sum)

class Block(SimpleStruct):
    """ Blocks contain data within hbin sections.
    
    They can contain any number of different structs within the RAW data,
    but are always seperated by the size.
    """
    def init(self):
        self.fields = [
            [ LONG,1,'size'],
            ]

    def read(self,data):
 #       print "Reading data at offset %s" % data.offset
        result=SimpleStruct.read(self,data)

        ## This is the total size of the block:
        size=result['size'].get_value()
        if size<0:
            size=-size
        elif size==0:
            raise("Size is 0??? at offset %s" %data.offset)
#        else:
#            print "Got a positive size (%s) which must be ignored" % size
            
        ## If we dont have enough data to read from we raise
        if size>len(data):
            raise IOError("Error, last block is larger than data %s %s" % (size,len(data)))
                    
        ## The size of the data payload is the remainder of this block
        offset = result['size'].size()
        data_size = size - offset
        ## Add the new member as RAW data
        self.add_element(result,RAW(data[offset:], data_size),'data')
        return result

class BlockArray(ARRAY):
    """ This array represents all the blocks within a section.

    We keep adding blocks until we run out of space. """
    target_class=Block

    def __init__(self,buffer,*args,**kwargs):
        ARRAY.__init__(self,buffer,100000,*args,**kwargs)

class HBin(SimpleStruct):
    """ A hbin is a container which stores blocks in it.

    hbins form a doubly linked list with links to the next and previous hbin.
    """
    def init(self):
        self.fields=[
            [ STRING,4,'Magic'],
            [ LONG,1,'offset_from_1st'], #Offset from the 1st hbin-Block
            [ LONG,1,'size'],
            [ BYTE_ARRAY,14,'unknown1'],
            ## This is ignored as it is unclear what it is... (See ntchpw), we only use size above
            [ LONG,1,'page_length'],
            ]

    def read(self,data):
        result=SimpleStruct.read(self,data)
        if result['Magic'].get_value()!='hbin':
            raise IOError("This is not a hbin record at offset %s. Stopping to read (%s)"% ( data.offset,result['Magic']))

        ## The size of the data payload is the remainder of this block
        size=result['size'].get_value()-32
        self.add_element(result,RAW(data[32:],size),'data')
        return result

    def size(self):
        return self['size'].get_value()
    
class HBinArray(ARRAY):
    """ This is an array of hbin records.

    The length of the array is determined by the first non-hbin record.
    """
    target_class=HBin

    def read(self,data):
        result=[]
        offset=0
        try:
            while 1:
                tmp=self.target_class(data[offset:],parent=self)
                offset+=tmp.size()
                result.append(tmp)
        except:
            pass
        
        return result
    
class sk_key(SimpleStruct):
    def init(self):
        self.fields=[
            [ STRING,2,'id'],
            [ WORD,1,'pad'],
            [ LONG,1,'offset_prev'], #Offset of previous "sk"-Record
            [ LONG,1,'offset_next'], # To next sk record
            [ LONG,1,'usage_count'],
            [ LONG,1,'size'],
            ]

class NK_key(SimpleStruct):
    def init(self):
        self.fields=[
            [ STRING,2,'id'],
            [ NK_TYPE,1,'Type'],
            [ WIN12_FILETIME,1,'WriteTS'],
            [ LONG,1,'parent_offset'],
            [ ULONG,1,'number_of_subkeys'],
            [ LONG,4,'pad'],
            [ Plf_key,1,'offs_lf'],
            [ LONG,1,'pad'],
            [ LONG,1,'no_values'],
            [ LONG,1,'offs_vk_list'],  ## This will be replaced later with the contents of the array
            [ LONG,1,'offs_sk'],
            [ LONG,1,'offs_class_name'],
            [ LONG_ARRAY,5,'pad2'],
            [ KEY_NAME,1,'key_name'],
            ]

    def read(self,data):
        result=SimpleStruct.read(self,data)
        if result['id']!='nk':
            raise IOError("nk record expected, but not found at offset %s" % data.offset)

        ## Fixup offs_vk_list:
        offs_vk_list = result['offs_vk_list'].get_value()
        data=data.set_offset(FIRST_PAGE_OFFSET+4+offs_vk_list)
        no_values=result['no_values'].get_value()
        ## Try to find the vk lists:
        result['offs_vk_list'] = VK_Array(data,no_values)
        
        return result
        
class KEY_NAME(STRING):
    """ A key name is specified as a length and a string.
    
    Note that here we ignore the class name and its offset.
    """
    def read(self,data):
        length=WORD(data).get_value()
        self.fmt = "%ss" % length
        return STRING.read(self,data[4:])

class lf_hash(SimpleStruct):
    def init(self):
        self.fields = [
            [ PNK_key,1,'ofs_nk'],
            [ STRING,4,'name'],
            ]

class LF_HashArray(ARRAY):
    target_class=lf_hash

class lf_key(SimpleStruct):
    def init(self):
        self.fields = [
            [ STRING,2,'id'],
            [ WORD,1,'no_keys'],
            ]

    def read(self,data):
        result=SimpleStruct.read(self,data)
        if result['id']!='lf':
            raise IOError("lf record expected, but not found at offset 0x%08X" % data.offset)
        
        no_keys=result['no_keys'].get_value()
        self.add_element(result,LF_HashArray(data[4:],no_keys),'hashes')
        return result

class ri_key(SimpleStruct):
    def init(self):
        self.fields = [
            [ STRING,2,'id'],
            [ WORD,1,'no_pointers'],
            ]

    def read(self,data):
        result=SimpleStruct.read(self,data)
        if result['id']!='ri':
            raise IOError("ri record expected, but not found at offset 0x%08X" % data.offset)
        
class DATA_TYPE(LONG_ENUM):
    types = {
        0:'REG_NONE',
        1:'REG_SZ',  # Unicode nul terminated string 
        2:'REG_EXPAND_SZ',  # Unicode nul terminated string + env 
        3:'REG_BINARY',  # Free form binary 
        4:'REG_DWORD',  # 32-bit number 
        5:'REG_DWORD_BIG_ENDIAN',  # 32-bit number 
        6:'REG_LINK',  # Symbolic Link (unicode) 
        7:'REG_MULTI_SZ',  # Multiple Unicode strings 
        8:'REG_RESOURCE_LIST',  # Resource list in the resource map 
        9:'REG_FULL_RESOURCE_DESCRIPTOR', # Resource list in the hardware description 
        10:'REG_RESOURCE_REQUIREMENTS_LIST'
        }

class DATA(SimpleStruct):
    """ This represents the encoded data object.

    The data is encoded using the three vectors len_data,offs_data and val_type. There are many edge cases where these change meanings. This is another example of microsoft stupidity - increasing the complexity for no reason. Most of the code below handles the weird edge cases.
    """
    def init(self):
        self.fields=[
            [ LONG,1,'len_data'],
            [ LONG,1,'offs_data'],
            [ DATA_TYPE,1,'val_type'],
            ]
        
    def read(self,data):
        result=SimpleStruct.read(self,data)
        len_data=result['len_data'].get_value()
        size=len_data& 0x7fffffff
        offs_data=result['offs_data'].get_value()
        val_type=result['val_type']

        ## Work around all the weird edge cases:
        ## If the offset is zero, the value is represented inline inside the length:
        if size and val_type=='REG_DWORD' and len_data & 0x80000000L:
            self.raw_data=struct.pack('l',result['offs_data'].get_value())

        ## This is a catchall in case:
        elif len_data<0:
##            raise IOError("length is negative in data: %s %s %s" %(result['len_data'],result['offs_data'],result['val_type']))
##            print("length is negative in data: %s %s %s" %(result['len_data'],result['offs_data'],result['val_type']))
            self.raw_data=None
        else:
            ## Data is referenced by offs_data:
            data=data.set_offset(offs_data+FIRST_PAGE_OFFSET+4)
            self.raw_data=data[:len_data]
            
        return result

    def __repr__(self):
        return SimpleStruct.__str__(self)

    def __str__(self):
        """ We display ourselves nicely """
        result=''
        val_type=self['val_type']
        if self.raw_data==None:
            return 'None'
        elif val_type=='REG_SZ' or val_type=='REG_EXPAND_SZ':
            result+="%s" % UCS16_STR(self.raw_data,len(self.raw_data))
        elif val_type=='REG_DWORD':
            result+="0x08%X" % ULONG(self.raw_data).get_value()
        else:
            result+="%r" % "%s" % self.raw_data
        return result
    
class vk_key(SimpleStruct):
    def init(self):
        self.fields = [
            [ STRING,2,'id'],
            [ WORD,1,'len_name'],
            [ DATA,1,'data'],
            [ WORD,1,'flag'],
            [ WORD,1,'pad'],
            ]

    def read(self,data):
        result=SimpleStruct.read(self,data)
        if result['id']!='vk':
            raise IOError("vk record expected, but not found at offset 0x%08X" % data.offset)

        strlen=result['len_name'].get_value()
        if strlen>0:
            keyname=STRING(data[5*4:],strlen)
        else:
            keyname=STRING('@',1)

        ## New struct member is keyname:
        self.add_element(result,keyname,'keyname')
        return result

class Pri_key(POINTER):
    """ This is a pointer to the ri_key struct for a particular nk.

    It is pointing relative to FIRST_PAGE_OFFSET.
    """
    target_class=ri_key
    def calc_offset(self,data,offset):
        if offset>0:
            offset=offset+FIRST_PAGE_OFFSET+4
            data=data.set_offset(offset)
            return data
        else: return None

class Plf_key(Pri_key):
    target_class=lf_key

class PNK_key(Pri_key):
    target_class=NK_key

class Pvk_key(Pri_key):
    target_class=vk_key

class VK_Array(ARRAY):
    target_class=Pvk_key

def ls_r(root_key,path='/'):
    """ Lists all paths under root_key recursively.

    @arg root_key: An NK_key object
    """
    lf_key=root_key['offs_lf'].p()
    
    ## Node has no lf list, therefore no children:
    if not lf_key: return

    ## Iterate over all children:
    for lf in lf_key['hashes']:
        try:
            nk_key=lf['ofs_nk'].p()
            print "%s%s" % (path,nk_key['key_name'])
            if nk_key['no_values'].get_value()>0:
                try:
                    for value in nk_key['offs_vk_list']:
                        vk=value.p()
                        print "       Values:  %s\t->\t%s\t%s" % (vk['keyname'],vk['data']['val_type'],vk['data'])
                except IOError:
                    print "Oops: Cant parse values in %s at offset 0x%08X!" % (path,nk_key.buffer.offset)                    

            ls_r(nk_key,"%s%s/" % (path,nk_key['key_name']))
        except IOError,e:
            print "Oops: Cant parse nk node %s at offset 0x%08X!: The error was %s" % (path,root_key.buffer.offset,e)
            
if __name__ == "__main__":
    fd=open(sys.argv[1],'r')

    buffer = Buffer(fd=fd)
    header = RegF(buffer)
    print header
    root_key = header['root_key_offset'].p()
    print root_key
    ls_r(root_key)
