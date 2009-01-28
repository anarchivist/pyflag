# Volatility
# Copyright (c) 2008 Volatile Systems
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#

"""
@author:       Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      bdolangavitt@wesleyan.edu
"""

from forensics.object2 import NewObject
from struct import unpack

ROOT_INDEX = 0x20
LH_SIG = "lh"
LF_SIG = "lf"
RI_SIG = "ri"
NK_SIG = "nk"
VK_SIG = "vk"

KEY_FLAGS = {
    "KEY_IS_VOLATILE"   : 0x01,
    "KEY_HIVE_EXIT"     : 0x02,
    "KEY_HIVE_ENTRY"    : 0x04,
    "KEY_NO_DELETE"     : 0x08,
    "KEY_SYM_LINK"      : 0x10,
    "KEY_COMP_NAME"     : 0x20,
    "KEY_PREFEF_HANDLE" : 0x40,
    "KEY_VIRT_MIRRORED" : 0x80,
    "KEY_VIRT_TARGET"   : 0x100,
    "KEY_VIRTUAL_STORE" : 0x200,
}

VALUE_TYPES = dict(enumerate([
    "REG_NONE",
    "REG_SZ",
    "REG_EXPAND_SZ",
    "REG_BINARY",
    "REG_DWORD",
    "REG_DWORD_BIG_ENDIAN",
    "REG_LINK",
    "REG_MULTI_SZ",
    "REG_RESOURCE_LIST",
    "REG_FULL_RESOURCE_DESCRIPTOR",
    "REG_RESOURCE_REQUIREMENTS_LIST",
    "REG_QWORD",
]))
VALUE_TYPES.setdefault("REG_UNKNOWN")

def get_root(address_space,profile,stable=True):
    if stable:
        return NewObject("_CM_KEY_NODE", ROOT_INDEX, address_space, profile=profile)
    else:
        return NewObject("_CM_KEY_NODE", ROOT_INDEX | 0x80000000, address_space, profile=profile)

def open_key(root, key):
    if key == []:
        return root

    if not root.is_valid():
        return None
    
    keyname = key.pop(0)
    for s in subkeys(root):
        if s.Name.upper() == keyname.upper():
            return open_key(s, key)
    print "ERR: Couldn't find subkey %s of %s" % (keyname, root.Name)
    return None

def read_sklist(sk):
    sub_list = []
    if (sk.Signature == LH_SIG or
        sk.Signature == LF_SIG):
        return sk.List
    
    elif sk.Signature == RI_SIG:
        l = []
        for i in range(sk.Count):
            # Read and dereference the pointer
            ptr_off = sk.get_member_offset('List')+(i*4)
            if not self.vm.is_valid_address(ptr_off): continue
            ssk_off = read_value(self.vm, "unsigned int", ptr_off)
            if not self.vm.is_valid_address(ssk_off): continue
            
            ssk = NewObject("_CM_KEY_INDEX", ssk_off, sk.vm, profile=sk.profile)
            l += read_sklist(ssk)
        return l
    else:
        return []

# Note: had to change SubKeyLists to be array of 2 pointers in vtypes.py
def subkeys(key):
    if not key.is_valid(): return []
    sub_list = []
    if key.SubKeyCounts[0] > 0:
        sk_off = key.SubKeyLists[0]
        sk = NewObject("_CM_KEY_INDEX", sk_off, key.vm, profile=key.profile)
        if not sk or not sk.is_valid():
            pass
        else:
            tmp = read_sklist(sk)
            for tmp in tmp:
                sub_list.append(tmp.dereference())
            
    if key.SubKeyCounts[1] > 0:
        sk_off = key.SubKeyLists[1]
        sk = NewObject("_CM_KEY_INDEX", sk_off, key.vm, profile=key.profile)
        if not sk or not sk.is_valid():
            pass
        else:
            tmp = read_sklist(sk)
            for tmp in tmp:
                sub_list.append(tmp.dereference())

    #sub_list = [s.value for s in sub_list]
    return [ s for s in sub_list if 
             s and s.is_valid() and s.Signature == NK_SIG]

def values(key):
    return [ v for v in key.ValueList.List.dereference()
             if v and v.is_valid() and
             v.Signature == VK_SIG ]

def key_flags(key):
    return [ k for k in KEY_FLAGS if key.Flags & KEY_FLAGS[k] ]

def value_data(val):
    valtype = VALUE_TYPES[val.Type]
    inline =  val.DataLength & 0x80000000

    if inline:
        valdata = val.vm.read(val.get_member_offset('Data'), val.DataLength & 0x7FFFFFFF)
    else:
        valdata = val.vm.read(val.Data, val.DataLength)

    if (valtype == "REG_SZ" or valtype == "REG_EXPAND_SZ" or
        valtype == "REG_LINK"):
        valdata = valdata.decode('utf-16-le')
    elif valtype == "REG_MULTI_SZ":
        valdata = valdata.decode('utf-16-le').split('\0')
    elif valtype == "REG_DWORD":
        valdata = unpack("<L", valdata)[0]
    elif valtype == "REG_DWORD_BIG_ENDIAN":
        valdata = unpack(">L", valdata)[0]
    elif valtype == "REG_QWORD":
        valdata = unpack("<Q", valdata)[0]
    return (valtype,valdata)

def walk(root):
    yield root
    for k in subkeys(root):
        for j in walk(k):
            yield j
