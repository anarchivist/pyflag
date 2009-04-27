# Volatility
# Copyright (C) 2007,2008 Volatile Systems
#
# Copyright (C) 2005,2006,2007 4tphi Research
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
@author:       AAron Walters and Andreas Schuster
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com
"""

"""Address space: windows crash dump
   
"""

from forensics.addrspace import FileAddressSpace
import forensics.x86
from forensics.object import *

page_shift = 12

debug_types = { \
}


class WindowsCrashDumpSpace32:
    def __init__(self, baseAddressSpace,offset,ramsize=0):
        self.runs = []
        self.offset = offset
        self.base = baseAddressSpace
        self.fname = ''
        native_types = forensics.x86.x86_native_types

        self.dump_header = self.base.read(offset,obj_size(debug_types, '_DMP_HEADER'))

        self.number_of_runs = read_obj(self.base, debug_types,
            ['_DMP_HEADER', 'PhysicalMemoryBlockBuffer','NumberOfRuns'], offset)
	
        self.number_of_pages = read_obj(self.base, debug_types,
            ['_DMP_HEADER', 'PhysicalMemoryBlockBuffer','NumberOfPages'], offset)

        (start_run,tmp) = get_obj_offset(debug_types, ['_DMP_HEADER', 'PhysicalMemoryBlockBuffer', 'Run'])

        for cnt in range(0,self.number_of_runs):
            BasePage = read_obj(self.base, debug_types,
                ['_PHYSICAL_MEMORY_RUN', 'BasePage'], start_run+(8*cnt))
            PageCount = read_obj(self.base, debug_types,
                ['_PHYSICAL_MEMORY_RUN', 'PageCount'], start_run+(8*cnt))
            self.runs.append([BasePage,PageCount])

    def get_header(self):
        return self.dump_header

    def get_base(self):
        return self.base

    def get_number_of_runs(self):
        return self.number_of_runs

    def get_number_of_pages(self):
        return self.number_of_pages

    def get_majorversion(self):
        return read_obj(self.base, debug_types,
            ['_DMP_HEADER', 'MajorVersion'], self.offset)
  
    def get_minorversion(self):
        return read_obj(self.base, debug_types,
            ['_DMP_HEADER', 'MinorVersion'], self.offset)      
    
    def get_kdsecondaryversion(self):
        return read_obj(self.base, debug_types,
            ['_DMP_HEADER', 'KdSecondaryVersion'], self.offset)      

    def get_directorytablebase(self):
        return read_obj(self.base, debug_types,
            ['_DMP_HEADER', 'DirectoryTableBase'], self.offset)   

    def get_pfndatabase(self):
        return read_obj(self.base, debug_types,
            ['_DMP_HEADER', 'PfnDataBase'], self.offset)   

    def get_psloadedmodulelist(self):
        return read_obj(self.base, debug_types,
            ['_DMP_HEADER', 'PsLoadedModuleList'], self.offset)   

    def get_psactiveprocesshead(self):
        return read_obj(self.base, debug_types,
            ['_DMP_HEADER', 'PsActiveProcessHead'], self.offset)   

    def get_machineimagetype(self):
        return read_obj(self.base, debug_types,
            ['_DMP_HEADER', 'MachineImageType'], self.offset) 

    def get_numberprocessors(self):
        return read_obj(self.base, debug_types,
            ['_DMP_HEADER', 'NumberProcessors'], self.offset) 

    def get_bugcheckcode(self):
        return read_obj(self.base, debug_types,
            ['_DMP_HEADER', 'BugCheckCode'], self.offset) 

    def get_paeenabled(self):
        return read_obj(self.base, debug_types,
            ['_DMP_HEADER', 'PaeEnabled'], self.offset)

    def get_kddebuggerdatablock(self):
        return read_obj(self.base, debug_types,
            ['_DMP_HEADER', 'KdDebuggerDataBlock'], self.offset)

    def get_dumptype(self):
        return read_obj(self.base, debug_types,
            ['_DMP_HEADER', 'DumpType'], self.offset)

    def get_producttype(self):
        return read_obj(self.base, debug_types,
            ['_DMP_HEADER', 'ProductType'], self.offset)

    def get_suitemask(self):
        return read_obj(self.base, debug_types,
            ['_DMP_HEADER', 'SuiteMask'], self.offset)

    def get_writerstatus(self):
        return read_obj(self.base, debug_types,
            ['_DMP_HEADER', 'WriterStatus'], self.offset)
       
    def get_addr(self, addr):
        page_offset = (addr & 0x00000FFF)
        page = addr >> page_shift
	
        # This is the offset to account for the header file
        offset = 1
        for run in self.runs:
            if ((page >= run[0]) and (page < (run[0] + run[1]))):
                run_offset = page - run[0]
                offset = offset + run_offset
                baseoffset = (offset * 0x1000) + page_offset
                return baseoffset
            offset += run[1]
        return None

    def is_valid_address(self, addr):
        if self.get_addr(addr) == None:
            return False
        return True

    def read(self, addr, len):
        first_block = 0x1000 - addr % 0x1000
        full_blocks = ((len + (addr % 0x1000)) / 0x1000) - 1
        left_over = (len + addr) % 0x1000

        baddr = self.get_addr(addr)
        if baddr == None:
            return None
	
        if len < first_block:
            return self.base.read(baddr,len)

        stuff_read = self.base.read(baddr, first_block)
        new_addr = addr + first_block
        for i in range(0,full_blocks):
            baddr = self.get_addr(new_addr)
            if baddr == None:
                return None
            stuff_read = stuff_read + self.base.read(baddr, 0x1000)
            new_addr = new_addr + 0x1000
	
        if left_over > 0:
            baddr = self.get_addr(new_addr)
            if baddr == None:
                return None
            stuff_read = stuff_read + self.base.read(baddr, left_over)
        return stuff_read    

    def zread(self, vaddr, length):
        first_block = 0x1000 - vaddr % 0x1000
        full_blocks = ((length + (vaddr % 0x1000)) / 0x1000) - 1
        left_over = (length + vaddr) % 0x1000
       
        self.check_address_range(vaddr)

        baddr = self.get_addr(vaddr)

        if baddr == None:
            if length < first_block:
                return ('\0' * length)
            stuff_read = ('\0' * first_block)       
        else:
            if length < first_block:
                return self.base.read(baddr, length)
            stuff_read = self.base.read(baddr, first_block)

        new_vaddr = vaddr + first_block
        for i in range(0,full_blocks):
            baddr = self.get_addr(new_vaddr)
            if baddr == None:
                stuff_read = stuff_read + ('\0' * 0x1000)
            else:
                stuff_read = stuff_read + self.base.read(baddr, 0x1000)

            new_vaddr = new_vaddr + 0x1000

        if left_over > 0:
            baddr = self.get_addr(new_vaddr)
            if baddr == None:
                stuff_read = stuff_read + ('\0' * left_over)
	    else:
                stuff_read = stuff_read + self.base.read(baddr, left_over)
        return stuff_read

    def read_long(self, addr):
        baseaddr = self.get_addr(addr)
        string = self.read(addr, 4)
        (longval, ) = struct.unpack('=L', string)
        return longval

    def get_available_pages(self):
        page_list = []
        for run in self.runs:
            start = run[0]
            for page in range(start,start + run[1]):
                page_list.append([page * 0x1000, 0x1000])
        return page_list

    def get_address_range(self):
        """ This relates to the logical address range that is indexable """
        run = self.runs[-1]
        size = run[0] * 0x1000 + run[1]*0x1000
        return [0,size]

    def get_available_addresses(self):
        """ This returns the ranges  of valid addresses """
        address_list = []
        for run in self.runs:
            address_list.append([run[0] * 0x1000, run[1] * 0x1000])
        return address_list

    def check_address_range(self,addr):
        memrange = self.get_address_range()
        if addr < memrange[0] or addr > memrange[1]:
	    raise IOError

    def close(self):
        self.base.close()
