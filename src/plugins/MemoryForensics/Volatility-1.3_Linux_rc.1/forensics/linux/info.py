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


def info_systime(addr_space, theProfile, symtab):
    xtime_vaddr = symtab.lookup('xtime')
    timespec = Object('timespec', xtime_vaddr, addr_space, \
                        None, theProfile)
    return timespec

def info_timezone(addr_space, theProfile, symtab):
    sys_tz_vaddr = symtab.lookup('sys_tz')
    sys_tz = Object('timezone', sys_tz_vaddr, addr_space, \
                        None, theProfile)
    return sys_tz

def info_cpus(addr_space, theProfile, symtab):
    smp_num_cpus = symtab.lookup('smp_num_cpus')
    if smp_num_cpus == None:
        num_cpus = 1
    elif symtab.lookup('__per_cpu_offset') == None:
        num_cpus = 1
    else:
        num_cpus = smp_num_cpus
    return num_cpus

def info_system_utsname(addr_space, theProfile, symtab):
    system_utsname_vaddr = symtab.lookup('system_utsname')
    if system_utsname_vaddr != None:
        system_utsname =  Object('new_utsname', system_utsname_vaddr, addr_space, None, theProfile)

    elif symtab.lookup('init_uts_ns') != None:
        init_uts_ns_vaddr = symtab.lookup('init_uts_ns')
        system_utsname =  Object('new_utsname', init_uts_ns_vaddr, addr_space, None, theProfile)
    else:
        system_utsname = None
    return system_utsname