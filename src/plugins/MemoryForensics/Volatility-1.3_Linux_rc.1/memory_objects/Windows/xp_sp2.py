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

from forensics.object2 import CType, NewObject
from forensics.object import *
from vtypes import xpsp2types as types

class _UNICODE_STRING(CType):
    """Class representing a _UNICODE_STRING

    Adds the following behavior:
      * The Buffer attribute is presented as a Python string rather
        than a pointer to an unsigned short.
      * The __str__ method returns the value of the Buffer.
    """

    def __str__(self):
        return self.Buffer

    # Custom Attributes
    def getBuffer(self):
        return read_unicode_string(self.vm, types, [], self.offset)
    
    Buffer = property(fget=getBuffer)
    
class _LIST_ENTRY(CType):
    """ Adds iterators for _LIST_ENTRY types """
    def list_of_type(self, type, member, forward=True):
        if not self.is_valid(): return
        
        ## Get the first element
        if forward:
            lst = self.Flink.dereference()
        else:
            lst = self.Blink.dereference()

        offset = self.profile.get_obj_offset(type ,member)

        seen = set()
        seen.add(lst.offset)
        
        while 1:            
            ## Instantiate the object
            obj = NewObject(type, offset = lst.offset - offset,
                            vm=self.vm,
                            parent=self.parent,
                            profile=self.profile, name=type)


            if forward:
                lst = obj.m(member).Flink.dereference()
            else:
                lst = obj.m(member).Blink.dereference()

            if not lst.is_valid() or lst.offset in seen: return
            seen.add(lst.offset)

            yield obj

    def __iter__(self):
        return self.list_of_type(self.parent, self.name)
