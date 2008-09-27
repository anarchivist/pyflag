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

# Defines

NO_PROC_ID = 0xFF

_RUNNING_         = 0
_INTERRUPTIBLE_   = 1
_UNINTERRUPTIBLE_ = 2
_STOPPED_         = 4
_TRACED_          = 8
_ZOMBIE_          = 16
_DEAD_            = 32
_NONINTERACTIVE_  = 64

def process_list(addr_space, types, symtab, theProfile):
    
    task_list = []    

    task_start_vaddr = symtab.lookup('init_tasks')

    if task_start_vaddr == None:
        init_task_vaddr = symtab.lookup('init_task')
        if init_task_vaddr == None:
             return []
        init_task = Object('task_struct', init_task_vaddr, addr_space, \
            None, theProfile)       
        list_do(init_task, ['tasks', 'next'], task_list.append, profile=theProfile)
    return task_list

def task_cpu(processor,verbose=False):
    if (processor < NO_PROC_ID):
        return "%d"%processor
    if (processor == NO_PROC_ID):
        if verbose == False:
            return '-'
        else:
            return 'NO_PROC_ID'

def task_to_pid(task_list, task_offset):
     for task in task_list:
         if task_offset == task.offset:
             return task.pid
     return -1
  
def pid_to_task(task_list, pid):
     match_tasks = [] 
     for task in task_list:
         if pid == task.pid:
             match_tasks.append(task)
     return match_tasks
           
def task_state_string(state,verbose=False):
    if state == _RUNNING_:
        return ['TASK_RUNNING', 'RU'][verbose==False]
    elif state == _INTERRUPTIBLE_:
        return ['TASK_INTERRUPTIBLE', 'IN'][verbose==False]
    elif state == _UNINTERRUPTIBLE_:
        return ['TASK_UNINTERRUPTIBLE', 'UN'][verbose==False]
    elif state == _ZOMBIE_:
        return ['TASK_ZOMBIE', 'ZO'][verbose==False]
    elif state == _STOPPED_:
        return ['TASK_STOPPED', 'ST'][verbose==False]
    elif state == _DEAD_:
        return ['TASK_DEAD', 'DE'][verbose==False]
    elif state == _SWAPPING_:
        return ['TASK_SWAPPING', 'SW'][verbose==False] 

def task_rss(task):
    if task.mm.is_valid():
        rss = 0
        if task.mm.has_member('_rss'):
            rss += task.mm._rss
        else:
            if task.mm.has_member('_anon_rss'):
                rss += task.mm._anon_rss
            if task.mm.has_member('_file_rss'):
                rss += task.mm._file_rss
        return rss
    else:
        return None 
        
def task_total_vm(task):
    if task.mm.is_valid():
        return task.mm.total_vm
    else:
        return None

def task_pgd(task):
    if task.mm.is_valid():
        return task.mm.pgd.v()
    else:
        return None


def task_create_addr_space(kaddr_space, pgd):

    try:
	process_address_space = kaddr_space.__class__(kaddr_space.base, pgd)
    except:
        return None

    return process_address_space

def task_fds(task, addr_space, types, symtab, theProfile):
    # Technically we don't need to pass in (addr,types or prof)
    out = []

    if task.m('files').v() != None and task.m('files').v() != 0:
        files_vaddr = task.m('files').v()
        
        files = Object('files_struct', files_vaddr, addr_space, \
                None, theProfile)

	if files == None:
	    return out

        fdt = files.m('fdt').dereference()
	fd  = fdt.m('fd').v()
	max_fds = fdt.m('max_fds').v()
	for i in range(max_fds):
	    filep = (fd+4*i)
	    filep = addr_space.read_long_virt(filep)
            
	    if (filep):
	        fileinfo = Object('file', filep, addr_space, \
                    None, theProfile)

                dentry = fileinfo.m('f_dentry').v()
		if dentry == 0:
		    continue

                dentry = Object('dentry', dentry, addr_space, \
                    None, theProfile)

		if dentry == None:
		    continue
		inode = dentry.m('d_inode').v()

                inode = Object('inode', inode, addr_space, \
                    None, theProfile)

		out.append((i,filep,dentry,inode))
    return out
