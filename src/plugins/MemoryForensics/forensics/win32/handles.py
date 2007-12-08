# Volatools Basic
# Copyright (C) 2007 Komoku, Inc.
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
@author:       AAron Walters and Nick Petroni
@license:      GNU General Public License 2.0 or later
@contact:      awalters@komoku.com, npetroni@komoku.com
@organization: Komoku, Inc.
"""

from forensics.object import *
from forensics.win32.datetime import *
from forensics.win32.tasks import *

LEVEL_MASK = 0xfffffff8

def handle_process_id(addr_space, types, table_vaddr):
    return read_obj(addr_space, types,
                    ['_HANDLE_TABLE', 'UniqueProcessId'], table_vaddr)


def handle_num_entries(addr_space, types, table_vaddr):
    return read_obj(addr_space, types,
                    ['_HANDLE_TABLE', 'HandleCount'], table_vaddr)

def handle_table_code(addr_space, types, table_vaddr):
    return read_obj(addr_space, types,
                    ['_HANDLE_TABLE', 'TableCode'], table_vaddr) & LEVEL_MASK


def handle_table_levels(addr_space, types, table_vaddr):
    return read_obj(addr_space, types,
                    ['_HANDLE_TABLE', 'TableCode'], table_vaddr) & ~LEVEL_MASK


def handle_table_L1_entry(addr_space, types, table_vaddr, entry_num):
    return handle_table_code(addr_space, types, table_vaddr) + \
           obj_size(types, '_HANDLE_TABLE_ENTRY') * entry_num

def handle_table_L2_entry(addr_space, types, table_vaddr, L1_table, L2):
    if L1_table != 0x0:
        L2_entry = L1_table + obj_size(types, '_HANDLE_TABLE_ENTRY') * L2
        
        return L2_entry
    
    return None

def handle_table_L3_entry(addr_space, types, table_vaddr, L2_table, L3):
    if L2_table != 0x0:
        L3_entry = L2_table = obj_size(types, '_HANDLE_TABLE_ENTRY') * L3
        
        return L3_entry

    return None
                    

def handle_entry_object(addr_space, types, entry_vaddr):
    return read_obj(addr_space, types,
                    ['_HANDLE_TABLE_ENTRY', 'Object'], entry_vaddr) & ~0x00000007


def is_object_file(addr_space, types, obj_vaddr):
    type_vaddr = read_obj(addr_space, types,
                          ['_OBJECT_HEADER', 'Type'], obj_vaddr)

    if not addr_space.is_valid_address(type_vaddr):
        return False

    type_name = read_unicode_string(addr_space, types,
                                    ['_OBJECT_TYPE', 'Name'], type_vaddr)

    return not type_name is None and type_name.find("File") != -1

def object_data(addr_space, types, obj_vaddr):
    (offset, tmp) = get_obj_offset(types, ['_OBJECT_HEADER', 'Body'])
    return obj_vaddr + offset

def file_name(addr_space, types, file_vaddr):
    return read_unicode_string(addr_space, types,
                               ['_FILE_OBJECT', 'FileName'],
                               file_vaddr)

def handle_tables(addr_space, types, symtab):

    htables = []

    all_tasks = process_list(addr_space, types, symtab)

    for task in all_tasks:
        if not addr_space.is_valid_address(task):
            continue
        ObjectTable = process_handle_table(addr_space, types, task)
	
	if addr_space.is_valid_address(ObjectTable):
            htables.append(ObjectTable)
    
    return htables

    
