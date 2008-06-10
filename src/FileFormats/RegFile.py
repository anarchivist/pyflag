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
#  Version: FLAG $Version: 0.87-pre1 Date: Tue Jun 10 13:18:41 EST 2008$
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
from plugins.FileFormats.BasicFormats import *
import sys

## This is where the first page starts
FIRST_PAGE_OFFSET=0x1000

class NK_TYPE(WORD_ENUM):
    """ The different types of NK nodes """
    types = {
        0x20: 'key',
        0x2c: 'ROOT_KEY'
        }

class RegFName(STRING):
    """ A string which does not print NULLs """
    def __str__(self):
        result=[c for c in STRING.__str__(self) if c!='\x00' ]
        return ''.join(result)

class lh_key(SimpleStruct):
    fields = [
        [ 'id',      STRING,{'length':2}],
        [ 'no_keys', WORD ],
        ]

    def read(self):
        result=SimpleStruct.read(self)
#        if result['id']!='lh':
#            raise IOError("lh record expected, but not found at offset 0x%08X" % self.buffer.offset)
        
        no_keys=result['no_keys'].get_value()
        self.add_element(result,'hashes', LF_HashArray(self.buffer[4:],count=no_keys))
        return result

class ri_key(SimpleStruct):
    fields = [
        [ 'id',         STRING,{'length':2}],
        [ 'no_pointers',WORD ],
        ]

    def read(self):
        result=SimpleStruct.read(self)
        if result['id']!='ri':
            raise IOError("ri record expected, but not found at offset 0x%08X" % data.offset)

class Pri_key(POINTER):
    """ This is a pointer to the ri_key struct for a particular nk.

    It is pointing relative to FIRST_PAGE_OFFSET.
    """
    target_class=ri_key

    def calc_offset(self):
        offset = self.data
        if offset>0:
            offset=offset+FIRST_PAGE_OFFSET+4
            data=self.buffer.set_offset(offset)
            
            return data
        else: return None

class Plh_key(Pri_key):
    target_class=lh_key

class KEY_NAME(STRING):
    """ The key names are a 32 bit length followed by data """
    def __init__(self,buffer,*args,**kwargs):
        offset = WORD(buffer)
        kwargs['length']=offset.get_value()
        STRING.__init__(self,buffer[4:], *args, **kwargs)

class NK_key(SimpleStruct):
    """ The main key node """
    fields=[
        [ 'id',                STRING,{'length':2}],
        [ 'Type',              NK_TYPE],
        [ 'WriteTS',           WIN12_FILETIME],
        [ 'parent_offset',     LONG],
        [ 'number_of_subkeys', ULONG],
        [ 'pad',               LONG],
        [ 'offs_lh',           Plh_key],
        [ 'pad',               LONG],
        [ 'no_values',         LONG],
        [ 'offs_vk_list',      LONG],  
        [ 'offs_sk',           LONG],
        [ 'offs_class_name',   LONG],
        [ 'pad',               LONG_ARRAY,{'count':5}],
        [ 'key_name',          KEY_NAME],
        ]
    
    def read(self):
        result=SimpleStruct.read(self)
        if result['id']!='nk':
            raise IOError("nk record expected, but not found at offset %s" % self.buffer.offset)

        ## Find the list of value keys (VKs)
        offs_vk_list = result['offs_vk_list'].get_value()

        data=self.buffer.set_offset(FIRST_PAGE_OFFSET+4+offs_vk_list)
        no_values=result['no_values'].get_value()

        ## Add the list to ourselves
        self.add_element(result,'vk_list', VK_Array(data,count=no_values))

        return result

    def keys(self):
        """ A generator which yields the keys under this node """
        try:
            lh_key=self['offs_lh'].get_value()
        except: return

        if not lh_key: return 

        for lh in lh_key['hashes']:
            try:
                nk_key = lh['ofs_nk'].get_value()
                yield nk_key
            except (KeyError,IOError):
                pass

    def key(self,name):
        """ Find the named child of this node """
        for k in self.keys():
            if k['key_name']==name:
                return k

        raise KeyError("Key %s not found under %s" % (name, self['key_name']))

    def value(self,name):
        """ Find the named child of this node """
        for v in self.values():
            if v['keyname']==name:
                return v

        raise KeyError("Value %s not found under %s" % (name, self['key_name']))

    def values(self):
        """ A Generator which returns all the value nodes of this key """
        if self['no_values'].get_value()>0:
            try:
                for value in self['vk_list']:
                    vk=value.get_value()
                    if vk:
                        yield vk
                        
            except IOError:
                return

class PNK_key(Pri_key):
    target_class=NK_key

class RegF(SimpleStruct):
    """ This is the registry file header """
    def __init__(self,  buffer, *args, **kwargs):
        SimpleStruct.__init__(self, buffer, *args, **kwargs)
        self.root_key = self['root_key_offset'].get_value()

    def get_key(self, path):
        """ Given a path, retrieve the key object stored there """
        p = path.split("/")
        root_key = self.root_key
        while p:
            key = p.pop(0)
            if key:
                root_key = root_key.key(key)
            
        return root_key

    fields = [
        [ 'Magic',          STRING , dict(length=4) ],
        [ 'Unknown1',       LONG_ARRAY, dict(count=2) ],
        [ 'Last Modified',  WIN_FILETIME],
        [ 'Unknown2',       LONG_ARRAY,{'count':4}],
        ##Offset is relative to FIRST_PAGE_OFFSET. This offset is
        ##to the root key's nk record.
        [ 'root_key_offset',PNK_key],
        [ 'filesize',       LONG],
        [ 'Name',           RegFName,{'length':0x1fc-0x2c}],
        [ 'checksum',       ULONG ],
        ]

class DATA_TYPE(LONG_ENUM):
    """ Different types of data stored in the registry """
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
        10:'REG_RESOURCE_REQUIREMENTS_LIST',
        11:'Unknown'
        }

class DATA(SimpleStruct):
    """ This represents the encoded data object.

    The data is encoded using the three vectors len_data,offs_data and val_type. There are many edge cases where these change meanings. This is another example of microsoft stupidity - increasing the complexity for no reason. Most of the code below handles the weird edge cases.
    """
    fields=[
        [ 'len_data',  LONG ],
        [ 'offs_data', LONG ],
        [ 'val_type',  DATA_TYPE ],
        ]
        
    def read(self):
        result=SimpleStruct.read(self)
        
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
            data=self.buffer.set_offset(offs_data+FIRST_PAGE_OFFSET+4)
            self.raw_data=data[:min(size,1024)]
            
        return result

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        """ We display ourselves nicely """
        val_type=self['val_type']
        if self.raw_data==None:
            return 'None'
        
        elif val_type=='REG_SZ' or val_type=='REG_EXPAND_SZ' or val_type=='REG_MULTI_SZ':
            result="%s" % UCS16_STR(self.raw_data, length=len(self.raw_data))
        elif val_type=='REG_DWORD':
            result="0x08%X" % ULONG(self.raw_data).get_value()
        else:
            ## FIXME: This needs to be a hexdump view:
            result="%r" % ("%s" % self.raw_data)
            
        return result

class vk_key(SimpleStruct):
    fields = [
        [ 'id',      STRING,{'length':2}],
        [ 'len_name',WORD ],
        [ 'data',    DATA ],
        [ 'flag',    WORD ],
        [ 'pad',     WORD ],
        ]

    def read(self):
        result=SimpleStruct.read(self)
        if result['id']!='vk':
            raise IOError("vk record expected, but not found at offset 0x%08X" % data.offset)

        strlen=result['len_name'].get_value()
        if strlen>0:
            keyname=STRING(self.buffer[self.offset:],length=strlen)
        else:
            keyname=STRING('@',length=1)

        ## New struct member is keyname:
        self.add_element(result,'keyname',keyname)
        return result

class PNK_key(Pri_key):
    target_class=NK_key

class lf_hash(SimpleStruct):
    fields = [
        [ 'ofs_nk', PNK_key],
        [ 'name',   STRING,{'length':4}],
        ]
    
class LF_HashArray(ARRAY):
    target_class=lf_hash

class Pvk_key(Pri_key):
    target_class=vk_key

class VK_Array(ARRAY):
    target_class=Pvk_key

def print_values(nk_key, path):
    print "%s%s" % (path,nk_key['key_name'])

    if nk_key['no_values'].get_value()>0:
        try:
            for value in nk_key['vk_list']:
                vk=value.get_value()
                if vk:
                    print "       Values:  %s\t->\t%s\t%s" % (vk['keyname'],vk['data']['val_type'],vk['data'])
        except IOError:
            print "Oops: Cant parse values in %s at offset 0x%08X!" % (nk_key['key_name'], nk_key.buffer.offset)                    

def ls_r(root_key,path='', cb=print_values):
    """ Lists all paths under root_key recursively.

    @arg root_key: An NK_key object
    """
    lh_key=root_key['offs_lh'].get_value()

    ## Node has no lf list, therefore no children:
    if not lh_key: return

    ## Iterate over all children:
    for lh in lh_key['hashes']:
        try:
            nk_key=lh['ofs_nk'].get_value()
#            print "%s%s" % (path,nk_key['key_name'])

            cb(nk_key, path=path)
            
            ls_r(nk_key,"%s%s/" % (path,nk_key['key_name']), cb=cb)
        except IOError,e:
            print "Oops: Cant parse nk node %s at offset 0x%08X!: The error was %s" % (path,root_key.buffer.offset,e)

def get_key(root_key, path):
    p = path.split("/")
    while p:
        root_key = root_key.key(p.pop(0))

    return root_key
            
if __name__ == "__main__":
    fd=open(sys.argv[1],'r')

    buffer = Buffer(fd=fd)
    header = RegF(buffer)
    print header
    
    path = 'Software/Microsoft/Windows/CurrentVersion/Explorer/TrayNotify'
    key = header.get_key(path)
    print key

    print "Values for %s" % path
    for v in key.values():
        print v['data']['val_type'],v['data']['len_data'],v['data']

    print "Keys under %s" % path
    for k in key.keys():
        print k

    ls_r(header.root_key)
