""" These are standard address spaces supported by Volatility """
import forensics.addrspace as addrspace
import os, struct
from forensics.object2 import NewObject, Profile
from vsyms import *

class FileAddressSpace(addrspace.BaseAddressSpace):
    """ This is a direct file AS.

    For this AS to be instanitiated, we need

    1) A valid opts.filename

    2) no one else has picked the AS before us
    
    3) base == None (we dont operate on anyone else so we need to be
    right at the bottom of the AS stack.)
    """
    ## We should be the AS of last resort
    order = 100
    def __init__(self, base, opts):
        assert(base == None)
        self.name = opts['filename']
        self.fname = self.name
        self.mode = opts.get('mode','rb')
	self.fhandle = open(self.fname, self.mode)
        self.fsize = os.path.getsize(self.fname)
        self.offset = 0

    def fread(self, len):
        return self.fhandle.read(len)

    def read(self, addr, len):
        self.fhandle.seek(addr)        
        return self.fhandle.read(len)    

    def zread(self, addr, len):
        return self.read(addr, len)

    def read_long(self, addr):
        string = self.read(addr, 4)
        (longval, ) =  struct.unpack('=L', string)
        return longval

    def get_address_range(self):
        return [0,self.fsize-1]

    def get_available_addresses(self):
        return [0,self.get_address_range()]

    def is_valid_address(self, addr):
        if addr == None:
	    return False
        return addr < self.fsize - 1

    def close():
        self.fhandle.close()

BLOCKSIZE = 1024 * 1024 * 10
from struct import unpack

## This stuff needs to go in the profile
entry_size = 8
pointer_size = 4
page_shift = 12 
ptrs_per_pte = 1024
ptrs_per_pgd = 1024
ptrs_per_pae_pte = 512
ptrs_per_pae_pgd = 512
ptrs_per_pdpi = 4
pgdir_shift = 22
pdpi_shift = 30
pdptb_shift = 5
pde_shift= 21
ptrs_per_pde = 512
ptrs_page = 2048

class IA32PagedMemory(addrspace.BaseAddressSpace):
    """ We accept an optional arg called dtb to force us to use a
    specific dtb. If not provided, we try to find it from our base
    AS, and failing that we search for it.
    """
    order = 90
    def __init__(self, baseAddressSpace, opts):
        ## We must be stacked on someone else:
        assert(baseAddressSpace != None)
        
        ## We can not stack on someone with a page table
        assert(not hasattr(baseAddressSpace, 'pgd_vaddr'))
        
        self.base = baseAddressSpace
        self.profile = Profile()
        self.pgd_vaddr = self.load_dtb()
	self.pae = False

        ## Finally we have to have a valid PsLoadedModuleList
        assert(self.is_valid_address(nopae_syms.lookup('PsLoadedModuleList')))

    def load_dtb(self):
        try:
            ## Try to be lazy and see if someone else found dtb for
            ## us:
            return self.base.dtb
        except AttributeError:
            ## Ok so we need to find our dtb ourselves:
            dtb = self._find_dtb()
            if dtb:
                ## Make sure to save dtb for other AS's
                self.base.dtb = dtb
                return dtb

    def _find_dtb(self):
        offset = 0
        while 1:
            data = self.base.read(offset, BLOCKSIZE)
            found = 0
            if not data:
                break

            while 1:
                found = data.find("\x03\x00\x1b\x00", found+1)
                if found >= 0:
                    (type,size) = unpack('=HH',data[found:found+4])
                    proc = NewObject("_EPROCESS", offset+found, self.base,
                                     profile = self.profile)
                    if 'Idle' in proc.ImageFileName.v():
                        return proc.Pcb.DirectoryTableBase[0]
                else:
                    break

            offset+=len(data)

        return None

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
		if not pte: return None
                if self.entry_present(pte):
                        retVal =  self.get_paddr(vaddr, pte)
        return retVal

    def read(self, vaddr, length):
        length = int(length)
        vaddr = int(vaddr)

        first_block = 0x1000 - vaddr % 0x1000
        full_blocks = ((length + (vaddr % 0x1000)) / 0x1000) - 1
        left_over = (length + vaddr) % 0x1000
        
        paddr = self.vtop(vaddr)
        if paddr == None:        
            return None
        
        if length < first_block:
	    stuff_read = self.base.read(paddr, length)
	    if stuff_read == None:
	        return None
            return stuff_read

        stuff_read = self.base.read(paddr, first_block)
        if stuff_read == None:
	    return None

        new_vaddr = vaddr + first_block
        for i in range(0,full_blocks):
            paddr = self.vtop(new_vaddr)
            if paddr == None:
                return None
            new_stuff = self.base.read(paddr, 0x1000)
	    if new_stuff == None:
	        return None
            stuff_read = stuff_read + new_stuff
            new_vaddr = new_vaddr + 0x1000

        if left_over > 0:
            paddr = self.vtop(new_vaddr)
            if paddr == None:
                return None
            new_stuff = self.base.read(paddr, left_over)
	    if new_stuff == None:
	        return None
            stuff_read = stuff_read + new_stuff
        return stuff_read

    def zread(self, vaddr, length):
        first_block = 0x1000 - vaddr % 0x1000
        full_blocks = ((length + (vaddr % 0x1000)) / 0x1000) - 1
        left_over = (length + vaddr) % 0x1000
        
        paddr = self.vtop(vaddr)

        if paddr == None:
            if length < first_block:
                return ('\0' * length)
            stuff_read = ('\0' * first_block)       
        else:
            if length < first_block:
                return self.base.zread(paddr, length)
            stuff_read = self.base.zread(paddr, first_block)

        new_vaddr = vaddr + first_block
        for i in range(0,full_blocks):
            paddr = self.vtop(new_vaddr)
            if paddr == None:
                stuff_read = stuff_read + ('\0' * 0x1000)
	    else:
                stuff_read = stuff_read + self.base.zread(paddr, 0x1000)

            new_vaddr = new_vaddr + 0x1000

        if left_over > 0:
            paddr = self.vtop(new_vaddr)
            if paddr == None:
                stuff_read = stuff_read + ('\0' * left_over)
            else:
                stuff_read = stuff_read + self.base.zread(paddr, left_over)
        return stuff_read

    def read_long_phys(self, addr):
        string = self.base.read(addr, 4)
	if not string:
	    return None
        (longval, ) =  struct.unpack('=L', string)
        return longval

    def is_valid_address(self, addr):
        if addr == None:
	    return False
	try:    
            phyaddr = self.vtop(addr)
	except:
	    return False
        if phyaddr == None:
            return False
	if not self.base.is_valid_address(phyaddr):
            return False
        return True

    def get_available_pages(self):
        page_list = []
        pgd_curr = self.pgd_vaddr
        for i in range(0,ptrs_per_pgd):
            start = (i * ptrs_per_pgd * ptrs_per_pte * 4)
            entry = self.read_long_phys(pgd_curr)
            pgd_curr = pgd_curr + 4
            if self.entry_present(entry) and self.page_size_flag(entry):
                page_list.append([start, 0x400000])
            elif self.entry_present(entry):
                pte_curr = entry & ~((1 << page_shift)-1)                
                for j in range(0,ptrs_per_pte):
                    pte_entry = self.read_long_phys(pte_curr)
                    pte_curr = pte_curr + 4
                    if self.entry_present(pte_entry):
                        page_list.append([start + j * 0x1000, 0x1000])
        return page_list        

    def read_long_virt(self, addr):
        string = self.read(addr, 4)
	if string == None:
	    return None
        (longval, ) =  struct.unpack('=L', string)
        return longval


class IA32PagedMemoryPae(IA32PagedMemory):
    order = 80
    def __init__(self, baseAddressSpace, opts):
        """ We accept an optional arg called dtb to force us to use a
        specific dtb. If not provided, we try to find it from our base
        AS, and failing that we search for it.
        """
        assert(baseAddressSpace != None)

        ## We can not stack on someone with a page table
        assert(not hasattr(baseAddressSpace, 'pgd_vaddr'))
        
        self.base = baseAddressSpace
        self.profile = Profile()
        try:
            self.pgd_vaddr = opts['dtb']
        except KeyError:
            self.pgd_vaddr = self.load_dtb()
        self.pae = True

        ## Finally we have to have a valid PsLoadedModuleList
        assert(self.is_valid_address(nopae_syms.lookup('PsLoadedModuleList')))
        
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
        length = int(length)
        vaddr = int(vaddr)
        first_block = 0x1000 - vaddr % 0x1000
        full_blocks = ((length + (vaddr % 0x1000)) / 0x1000) - 1
        left_over = (length + vaddr) % 0x1000
        
        paddr = self.vtop(vaddr)
        if paddr == None:
            return None
        
        if length < first_block:
	    stuff_read = self.base.read(paddr, length)
	    if stuff_read == None:
	        return None
            return stuff_read

        stuff_read = self.base.read(paddr, first_block)
        if stuff_read == None:
	    return None

        new_vaddr = vaddr + first_block
        for i in range(0,full_blocks):
            paddr = self.vtop(new_vaddr)
            if paddr == None:
                return None
            new_stuff = self.base.read(paddr, 0x1000)
	    if new_stuff == None:
	        return None
            stuff_read = stuff_read + new_stuff
            new_vaddr = new_vaddr + 0x1000

        if left_over > 0:
            paddr = self.vtop(new_vaddr)
            if paddr == None:
                return None
            new_stuff = self.base.read(paddr, left_over)
	    if new_stuff == None:
                return None
            stuff_read = stuff_read + new_stuff
        return stuff_read

    def zread(self, vaddr, length):
        length=int(length)
        vaddr=int(vaddr)
        first_block = 0x1000 - vaddr % 0x1000
        full_blocks = ((length + (vaddr % 0x1000)) / 0x1000) - 1
        left_over = (length + vaddr) % 0x1000
        
        paddr = self.vtop(vaddr)

        if paddr == None:
            if length < first_block:
                return ('\0' * length)
            stuff_read = ('\0' * first_block)       
        else:
            if length < first_block:
                return self.base.zread(paddr, length)
            stuff_read = self.base.zread(paddr, first_block)

        new_vaddr = vaddr + first_block
        for i in range(0,full_blocks):
            paddr = self.vtop(new_vaddr)
            if paddr == None:
                stuff_read = stuff_read + ('\0' * 0x1000)
            else:
                stuff_read = stuff_read + self.base.zread(paddr, 0x1000)

            new_vaddr = new_vaddr + 0x1000

        if left_over > 0:
            paddr = self.vtop(new_vaddr)
            if paddr == None:
                stuff_read = stuff_read + ('\0' * left_over)
	    else:
                stuff_read = stuff_read + self.base.zread(paddr, left_over)
        return stuff_read
        
    def read_long_phys(self, addr):
        string = self.base.read(addr, 4)
	if string == None:
	    return None
        (longval, ) =  struct.unpack('=L', string)
        return longval

    def read_long_virt(self, addr):
        string = self.read(addr, 4)
	if string == None:
	    return None
        (longval, ) =  struct.unpack('=L', string)
        return longval

    def read_long_long_phys(self, addr):
        string = self.base.read(addr,8)
	if string == None:
	    return None
	(longlongval, ) = struct.unpack('=Q', string)
	return longlongval

    def is_valid_address(self, addr):
        if addr == None:
	    return False
	try:    
            phyaddr = self.vtop(addr)
	except:
	    return False
        if phyaddr == None:
            return False
	if not self.base.is_valid_address(phyaddr):
            return False
        return True

    def get_available_pages(self):
        page_list = []
       
        pdpi_base = self.get_pdptb(self.pgd_vaddr)

        for i in range(0,ptrs_per_pdpi): 

	    start = (i * ptrs_per_pae_pgd * ptrs_per_pae_pgd * ptrs_per_pae_pte * 8)
            pdpi_entry  = pdpi_base + i * entry_size        
            pdpe = self.read_long_long_phys(pdpi_entry)

            if not self.entry_present(pdpe):
                continue
          
            pgd_curr = self.pdba_base(pdpe)          
                  
            for j in range(0,ptrs_per_pae_pgd):
	      soffset = start + (j * ptrs_per_pae_pgd * ptrs_per_pae_pte * 8)
              entry = self.read_long_long_phys(pgd_curr)
              pgd_curr = pgd_curr + 8
              if self.entry_present(entry) and self.page_size_flag(entry):
		  page_list.append([soffset, 0x200000])
              elif self.entry_present(entry):
                  pte_curr = entry & ~((1 << page_shift)-1)                
                  for k in range(0,ptrs_per_pae_pte):
                        pte_entry = self.read_long_long_phys(pte_curr)
                        pte_curr = pte_curr + 8
                        if self.entry_present(pte_entry):
			    page_list.append([soffset + k * 0x1000, 0x1000])
        return page_list
