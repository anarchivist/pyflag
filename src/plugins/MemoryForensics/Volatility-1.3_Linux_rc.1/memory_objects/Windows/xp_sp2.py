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

from forensics.object2 import CType, NewObject, NativeType, Curry
from forensics.object import *
from vtypes import xpsp2types as types
from forensics.win32.datetime import *
import vmodules

class _UNICODE_STRING(CType):
    """Class representing a _UNICODE_STRING

    Adds the following behavior:
      * The Buffer attribute is presented as a Python string rather
        than a pointer to an unsigned short.
      * The __str__ method returns the value of the Buffer.
    """
    def v(self):
        try:
            data = self.vm.read(self.Buffer.v(), self.Length.v())
            return data.decode("utf16","ignore")
        except Exception,e:
            return ''

    def __str__(self):
        return self.v()

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
        return self.list_of_type(self.parent.name, self.name)

class String(NativeType):
    def __init__(self, type, offset, vm=None,
                 length=1, parent=None, profile=None, name=None, **args):
        ## Allow length to be a callable:
        try:
            length = length(parent)
        except:
            pass
        
        ## length must be an integer
        NativeType.__init__(self, type, offset, vm, parent=parent, profile=profile,
                            name=name, format_string="%ds" % length)

    def upper(self):
        return self.__str__().upper()

    def lower(self):
        return self.__str__().lower()

    def __str__(self):
        data = self.v()
        ## Make sure its null terminated:
        return data.split("\x00")[0]

class WinTimeStamp(NativeType):
    def __init__(self, type, offset, vm=None,
                 parent=None, profile=None, name=None, **args):
        NativeType.__init__(self, type, offset, vm, parent=parent, profile=profile,
                            name=name, format_string="q")

    def v(self):
        return windows_to_unix_time(NativeType.v(self))

    def __str__(self):
        return vmodules.format_time(self.v())

LEVEL_MASK = 0xfffffff8


class _EPROCESS(CType):
    """ An extensive _EPROCESS with bells and whistles """
    def _Peb(self,attr):
        """ Returns a _PEB object which is using the process address space.

        The PEB structure is referencing back into the process address
        space so we need to switch address spaces when we look at
        it. This method ensure this happens automatically.
        """
        process_ad = self.get_process_address_space()
        if process_ad:
            offset =  self.m("Peb").v()

            peb = NewObject("_PEB",offset, vm=process_ad, profile=self.profile,
                            name = "Peb", parent=self)

            if peb.is_valid():
                return peb
            
    def get_process_address_space(self):
        """ Gets a process address space for a task given in _EPROCESS """
        directory_table_base = self.Pcb.DirectoryTableBase[0].v()

        process_as= self.vm.__class__(self.vm.base, directory_table_base)
        process_as.name = "Process"
        return process_as

    def _make_handle_array(self, offset, level):
        """ Returns an array of _HANDLE_TABLE_ENTRY rooted at offset,
        and iterates over them.

        """
        table = NewObject("Array", offset, self.vm,
                            count=0x200, parent=self, profile=self.profile,
                            target = Curry(NewObject, "_HANDLE_TABLE_ENTRY"))
        for t in table:
            offset = t.dereference_as('unsigned int')
            if not offset.is_valid(): break

            if level > 0:
                ## We need to go deeper:
                for h in self._make_handle_array(offset, level-1):
                    yield h
            else:
                ## OK We got to the bottom table, we just resolve
                ## objects here:
                offset = int(offset) & ~0x00000007;
                obj = NewObject("_OBJECT_HEADER", offset, self.vm,
                                parent=self, profile=self.profile)
                try:
                    if obj.Type.Name.__str__()=='File':
                        file = NewObject("_FILE_OBJECT", obj.Body.offset, self.vm,
                                         parent=self, profile=self.profile)
                        yield file

                except Exception,e:
                    pass
        
    def handles(self):
        """ A generator which yields this process's handles

        _HANDLE_TABLE tables are multi-level tables at the first level
        they are pointers to second level table, which might be
        pointers to third level tables etc, until the final table
        contains the real _OBJECT_HEADER table.

        This generator iterates over all the handles recursively
        yielding all handles. We take care of recursing into the
        nested tables automatically.
        """
        h = self.ObjectTable
        if h.is_valid():
            TableCode = h.TableCode.v() & LEVEL_MASK
            table_levels = h.TableCode.v() & ~LEVEL_MASK
            offset = TableCode

            for h in self._make_handle_array(offset, table_levels):
                yield h

import socket, struct

class _TCPT_OBJECT(CType):
    def _RemoteIpAddress(self, attr):
        return socket.inet_ntoa(struct.pack("<I",self.m(attr).v()))
    
    def _LocalIpAddress(self, attr):
        return socket.inet_ntoa(struct.pack("<I",self.m(attr).v()))

    def _RemotePort(self, attr):
        return socket.ntohs(self.m(attr).v())

    def _LocalPort(self, attr):
        return socket.ntohs(self.m(attr).v())
