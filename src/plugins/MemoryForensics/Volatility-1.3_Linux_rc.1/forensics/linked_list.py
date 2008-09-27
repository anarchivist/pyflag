# Volatility
# Copyright (C) 2007,2008 Volatile Systems
#
# Copyright (C) 2005,2006 4tphi Research
# Author: {npetroni,awalters}@4tphi.net (Nick Petroni and AAron Walters)
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
@author:       AAron Walters
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com
@organization: Volatile Systems
"""

from forensics.object2 import *

def linked_list_iter( profile, first_object, next_field,  iter_func, end_value=0x00000000):
    # Call the function on the first object
    iter_func(first_object)
    #get the next object
    next_vaddr = first_object.get_member(next_field).v()
    while (next_vaddr != end_value):
        next_object = Object(first_object.type, next_vaddr, first_object.vm, \
                    None, profile)
  
        iter_func(next_object)
        next_vaddr = next_object.get_member(next_field).v()


def linked_list_collect(profile, first_object, next_field, end_value=0x00000000):
    collect_list = []
    linked_list_iter(profile, first_object, next_field, \
                     lambda x : collect_list.append(x), end_value)
    return collect_list

## for lists that start with a full object
def list_do(head, next_field_name, iter_func, end_addr=None,profile=None):
    current = head

    next_pointer = current.get_deep_member(next_field_name)
    if end_addr == None:
        end_addr = next_pointer.offset
        
    offset_difference = next_pointer.offset - head.offset

    iter_func(current)
    while (next_pointer.v() != end_addr):
        current = Object(head.type,next_pointer.v() - offset_difference, head.vm,None,profile)
        iter_func(current)
        next_pointer = current.get_deep_member(next_field_name)

def list_do_pointer(pointer_head, objtype, member_name, iter_func, profile=None):

    try:
        offset = profile.cstructs[objtype[0]].get_member_offset(member_name[0])
    except:
        return None

    next_pointer = pointer_head.m(member_name[1])
    if next_pointer.v() == next_pointer.offset:
        return None

    first_object = Object(profile.cstructs[objtype[0]],next_pointer.v() - offset, pointer_head.vm,None,profile)

    list_do(first_object, member_name, iter_func, next_pointer.offset, profile)

