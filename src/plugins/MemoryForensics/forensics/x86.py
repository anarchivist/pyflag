# Volatility
# Copyright (C) 2007 Volatile Systems
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

"""Module for dealing with x86 architecture stuff
"""
import struct
from forensics.addrspace import FileAddressSpace

x86_native_types = { \
    'int' : [4, 'l'], \
    'long': [4, 'l'], \
    'unsigned long' : [4, 'L'], \
    'unsigned int' : [4, 'I'], \
    'address' : [4, 'L'], \
    'char' : [1, 'c'], \
    'unsigned char' : [1, 'B'], \
    'unsigned short' : [2, 'H'], \
    'short' : [2, 'h'], \
    'long long' : [8, 'q'], \
    'unsigned long long' : [8, 'Q'], \
    }

entry_size = 8
pointer_size = 4
page_shift = 12 
ptrs_per_pte = 1024
ptrs_per_pgd = 1024
ptrs_per_pdpi = 4
pgdir_shift = 22
pdpi_shift = 30
pdptb_shift = 5
pde_shift= 21
ptrs_per_pde = 512
ptrs_page = 2048


class IA32PagedMemory:
    def __init__(self, baseAddressSpace, pdbr):
        self.base = baseAddressSpace
        self.pgd_vaddr = pdbr
	self.pae = False

    def entry_present(self, entry):
        if (entry & (0x00000001)) == 0x00000001:
            return True
        return False

    def page_size_flag(self, entry):
        if (entry & (1 << 7)) == (1 << 7):
            return True
        return False    

    def pgd_index(self, pgd):
        return (pgd >> pgdir_shift) & (ptrs_per_pgd - 1)

    def get_pgd(self, vaddr):
        pgd_entry = self.pgd_vaddr + self.pgd_index(vaddr) * pointer_size
        return self.read_long_phys(pgd_entry)

    def pte_pfn(self, pte):
        return pte >> page_shift

    def pte_index(self, pte):
        return (pte >> page_shift) & (ptrs_per_pte - 1)

    def get_pte(self, vaddr, pgd):
        pgd_val = pgd & ~((1 << page_shift) - 1)
        pgd_val = pgd_val + self.pte_index(vaddr) * pointer_size
        return self.read_long_phys(pgd_val)

    def get_paddr(self, vaddr, pte):
        return (self.pte_pfn(pte) << page_shift) | (vaddr & ((1 << page_shift) - 1))

    def get_four_meg_paddr(self, vaddr, pgd_entry):
        return (pgd_entry & ((ptrs_per_pgd-1) << 22)) | (vaddr & ~((ptrs_per_pgd-1) << 22))

    def vtop(self, vaddr):
        retVal = None
        pgd = self.get_pgd(vaddr)

        if self.entry_present(pgd):
            if self.page_size_flag(pgd):
                retVal =  self.get_four_meg_paddr(vaddr, pgd)
            else:
                pte = self.get_pte(vaddr, pgd)
                if self.entry_present(pte):
                        retVal =  self.get_paddr(vaddr, pte)
        return retVal

    def read(self, vaddr, length):
        first_block = 0x1000 - vaddr % 0x1000
        full_blocks = ((length + (vaddr % 0x1000)) / 0x1000) - 1
        left_over = (length + vaddr) % 0x1000
        
        paddr = self.vtop(vaddr)
        if paddr == None:
            return None
        
        if length < first_block:
            return self.base.read(paddr, length)

        stuff_read = self.base.read(paddr, first_block)
        new_vaddr = vaddr + first_block
        for i in range(0,full_blocks):
            paddr = self.vtop(new_vaddr)
            if paddr == None:
                return None
            stuff_read = stuff_read + self.base.read(paddr, 0x1000)
            new_vaddr = new_vaddr + 0x1000

        if left_over > 0:
            paddr = self.vtop(new_vaddr)
            if paddr == None:
                return None
            stuff_read = stuff_read + self.base.read(paddr, left_over)
        return stuff_read

    def read_long_phys(self, addr):
        string = self.base.read(addr, 4)
        (longval, ) =  struct.unpack('L', string)
        return longval

    def is_valid_address(self, addr):
        phyaddr = self.vtop(addr)
        if phyaddr == None:
            return False
	if not self.base.is_valid_address(phyaddr):
            return False
        return True


class IA32PagedMemoryPae:
    def __init__(self, baseAddressSpace, pdbr):
        self.base = baseAddressSpace
        self.pgd_vaddr = pdbr
        self.pae = True

    def entry_present(self, entry):
        if (entry & (0x00000001)) == 0x00000001:
            return True
        return False

    def page_size_flag(self, entry):
        if (entry & (1 << 7)) == (1 << 7):
            return True
        return False    

    def get_pdptb(self, pdpr):
        return pdpr & 0xFFFFFFE0

    def pgd_index(self, pgd):
        return (pgd >> pgdir_shift) & (ptrs_per_pgd - 1)

    def pdpi_index(self, pdpi):
        return (pdpi >> pdpi_shift)

    def get_pdpi(self, vaddr):
        pdpi_entry = self.get_pdptb(self.pgd_vaddr) + self.pdpi_index(vaddr) * entry_size
	return self.read_long_long_phys(pdpi_entry)

    def pde_index(self, vaddr): 
        return (vaddr >> pde_shift) & (ptrs_per_pde - 1)

    def pdba_base(self, pdpe):
        return pdpe & 0xFFFFFF000

    def get_pgd(self, vaddr, pdpe):
        pgd_entry = self.pdba_base(pdpe) + self.pde_index(vaddr) * entry_size
        return self.read_long_long_phys(pgd_entry)

    def pte_pfn(self, pte):
        return pte & 0xFFFFFF000

    def pte_index(self, vaddr):
        return (vaddr >> page_shift) & (ptrs_per_pde - 1)

    def ptba_base(self, pde):
        return pde & 0xFFFFFF000

    def get_pte(self, vaddr, pgd):
        pgd_val = self.ptba_base(pgd) + self.pte_index(vaddr) * entry_size
        return self.read_long_long_phys(pgd_val)

    def get_paddr(self, vaddr, pte):
        return self.pte_pfn(pte) | (vaddr & ((1 << page_shift) - 1))

    def get_large_paddr(self, vaddr, pgd_entry):
        return (pgd_entry & 0xFFE00000) | (vaddr & ~((ptrs_page-1) << 21))

    def vtop(self, vaddr):
        retVal = None
        pdpe = self.get_pdpi(vaddr)

	if not self.entry_present(pdpe):
	    return retVal

	pgd = self.get_pgd(vaddr,pdpe)

        if self.entry_present(pgd):
		if self.page_size_flag(pgd):
		    retVal = self.get_large_paddr(vaddr, pgd)
		else:
                    pte = self.get_pte(vaddr, pgd)
                    if self.entry_present(pte):
                        retVal =  self.get_paddr(vaddr, pte)
        return retVal

    def read(self, vaddr, length):
        first_block = 0x1000 - vaddr % 0x1000
        full_blocks = ((length + (vaddr % 0x1000)) / 0x1000) - 1
        left_over = (length + vaddr) % 0x1000
        
        paddr = self.vtop(vaddr)
        if paddr == None:
            return None
        
        if length < first_block:
            return self.base.read(paddr, length)

        stuff_read = self.base.read(paddr, first_block)
        new_vaddr = vaddr + first_block
        for i in range(0,full_blocks):
            paddr = self.vtop(new_vaddr)
            if paddr == None:
                return None
            stuff_read = stuff_read + self.base.read(paddr, 0x1000)
            new_vaddr = new_vaddr + 0x1000

        if left_over > 0:
            paddr = self.vtop(new_vaddr)
            if paddr == None:
                return None
            stuff_read = stuff_read + self.base.read(paddr, left_over)
        return stuff_read
        
    def read_long_phys(self, addr):
        string = self.base.read(addr, 4)
        (longval, ) =  struct.unpack('L', string)
        return longval

    def read_long_long_phys(self, addr):
        string = self.base.read(addr,8)
	(longlongval, ) = struct.unpack('Q', string)
	return longlongval

    def is_valid_address(self, addr):
        phyaddr = self.vtop(addr)
        if phyaddr == None:
            return False
	if not self.base.is_valid_address(phyaddr):
            return False
        return True
