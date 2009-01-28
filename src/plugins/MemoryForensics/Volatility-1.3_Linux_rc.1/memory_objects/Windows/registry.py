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

from forensics.object2 import Object
from forensics.object import *
from vtypes import xpsp2types as types

##class _CM_KEY_NODE(Object):
##    """Class representing a _CM_KEY_NODE

##    Adds the following behavior:
##      * Name is read as a string.
##    """

##    def __new__(typ, *args, **kwargs):
##        obj = object.__new__(typ)
##        return obj

##    # Custom Attributes
##    def getName(self):
##        return read_string(self.vm, types, ['_CM_KEY_NODE', 'Name'],
##            self.offset, self.NameLength)
##    Name = property(fget=getName)

##class _CM_KEY_VALUE(Object):
##    """Class representing a _CM_KEY_VALUE

##    Adds the following behavior:
##      * Name is read as a string.
##    """

##    def __new__(typ, *args, **kwargs):
##        obj = object.__new__(typ)
##        return obj

##    # Custom Attributes
##    def getName(self):
##        return read_string(self.vm, types, ['_CM_KEY_VALUE', 'Name'],
##            self.offset, self.NameLength)
##    Name = property(fget=getName)

##class _CHILD_LIST(Object):
##    def __new__(typ, *args, **kwargs):
##        obj = object.__new__(typ)
##        return obj

##    def getList(self):
##        lst = []
##        list_address = read_obj(self.vm, types,
##            ['_CHILD_LIST', 'List'], self.offset)
##        if not self.Count: return []
##        if self.Count > 0x80000000: return []
##        for i in range(self.Count):
##            val_addr = read_value(self.vm, "unsigned int", list_address+(i*4))
##            lst.append(Object("_CM_KEY_VALUE", val_addr, self.vm, profile=self.profile))
##        return lst
##    List = property(fget=getList)

##class _CM_KEY_INDEX(Object):
##    def __new__(typ, *args, **kwargs):
##        obj = object.__new__(typ)
##        return obj

##    def getList(self):
##        lst = []
##        if not self.Count: return []
##        for i in range(self.Count):
##            # we are ignoring the hash value here
##            off,tp = get_obj_offset(types, ['_CM_KEY_INDEX', 'List', i*2])
##            key_addr = read_value(self.vm, "unsigned int", self.offset+off)
##            lst.append(Object("_CM_KEY_NODE", key_addr, self.vm, profile=self.profile))
##        return lst
##    List = property(fget=getList)
