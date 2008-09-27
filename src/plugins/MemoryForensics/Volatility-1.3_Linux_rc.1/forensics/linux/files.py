# Volatility
# Copyright (C) 2007,2008 Volatile Systems
#
# Original Source:
# Copyright (C) 2004,2005,2006 4tphi Research
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
from forensics.linked_list import list_do

def file_pathname(file, addr_space, theProfile):

    if not file.is_valid():
        return None
 
    f_dentry = file.m('f_dentry').v()
    if not addr_space.is_valid_address(f_dentry):
        return None

    dentry = file.f_dentry

    vfsmnt_addr = file.m('f_vfsmnt').v()
    if vfsmnt_addr == 0:
       return None

    vfsmnt = Object('vfsmount', vfsmnt_addr, addr_space, \
        None, theProfile)
       

    parent = dentry
    tmp_dentry = None

    pathname =""

    while tmp_dentry != parent and parent:
        tmp_pathname = pathname
        tmp_dentry = parent

        name_len = tmp_dentry.get_deep_member(['d_name', 'len']).v()
        name_name = tmp_dentry.get_deep_member(['d_name', 'name']).v()            
        string = addr_space.read(name_name,name_len)
        if tmp_dentry != dentry:
           if (name_len > 1 or (not string == "/")) and (not tmp_pathname[0:1] == "/"):
               pathname = string + "/" + tmp_pathname
           else:
               pathname = string + tmp_pathname
        else:
           pathname = string

        d_parent = tmp_dentry.m('d_parent').v()

        parent = Object('dentry', d_parent, addr_space, \
            None, theProfile)

        if tmp_dentry == parent:
            if vfsmnt_addr:
                if pathname[0:2] == "//":
                    pathname = pathname[1:]
                parent = vfsmnt.mnt_mountpoint
                mnt_parent = vfsmnt.mnt_parent
                if vfsmnt_addr == mnt_parent:
                    break
                else:
                    vfsmnt_addr = mnt_parent
    return pathname
