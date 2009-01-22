""" An impelentation of a Core file address space for memory analysis
of core files.
"""
from forensics.object import *
from forensics.object2 import Profile,NewObject
from forensics.addrspace import FileAddressSpace
import sys
import forensics.registry as MemoryRegistry

## For now use filenames:
#address_space = FileAddressSpace(sys.argv[1])

elf_types = {
    'Elf32_Ehdr' : [ 0x34, {
    'e_ident': [ 0x00 , ['array', 16, ['unsigned char']]],
    'e_type': [ 0x10 , [ 'unsigned short int' ]],
    'e_machine': [ 0x12 , [ 'unsigned short int' ]],
    'e_version': [ 0x14 , [ 'unsigned int' ]],
    'e_entry': [ 0x18 , [ 'unsigned int' ]],
    'e_phoff': [ 0x1C , [ 'unsigned int' ]],
    'e_shoff': [ 0x20 , [ 'unsigned int' ]],
    'e_flags': [ 0x24 , [ 'unsigned int' ]],
    'e_ehsize': [ 0x28 , [ 'unsigned short int' ]],
    'e_phentsize': [ 0x2A , [ 'unsigned short int' ]],
    'e_phnum': [ 0x2C , [ 'unsigned short int' ]],
    'e_shentsize': [ 0x2E , [ 'unsigned short int' ]],
    'e_shnum': [ 0x30 , [ 'unsigned short int' ]],
    'e_shstrndx': [ 0x32 , [ 'unsigned short int' ]],
    'sections' : [ (lambda x: x.e_phoff),
                   [ 'array', lambda x: x.e_phnum.v(), ["Elf32_Phdr" ]]],
    } ],
'Elf32_Shdr' : [ 0x28, {
    'sh_name': [ 0x00 , [ 'unsigned int' ]],
    'sh_type': [ 0x04 , [ 'unsigned int' ]],
    'sh_flags': [ 0x08 , [ 'unsigned int' ]],
    'sh_addr': [ 0x0C , [ 'unsigned int' ]],
    'sh_offset': [ 0x10 , [ 'unsigned int' ]],
    'sh_size': [ 0x14 , [ 'unsigned int' ]],
    'sh_link': [ 0x18 , [ 'unsigned int' ]],
    'sh_info': [ 0x1C , [ 'unsigned int' ]],
    'sh_addralign': [ 0x20 , [ 'unsigned int' ]],
    'sh_entsize': [ 0x24 , [ 'unsigned int' ]],
    } ],
'Elf32_Sym' : [ 0x10, {
    'st_name': [ 0x00 , [ 'unsigned int' ]],
    'st_value': [ 0x04 , [ 'unsigned int' ]],
    'st_size': [ 0x08 , [ 'unsigned int' ]],
    'st_info': [ 0x0C , [ 'unsigned char' ]],
    'st_other': [ 0x0D , [ 'unsigned char' ]],
    'st_shndx': [ 0x0E , [ 'unsigned short int' ]],
    } ],
'Elf32_Phdr' : [ 0x20, {
    'p_type': [ 0x00 , [ 'unsigned int' ]],
    'p_offset': [ 0x04 , [ 'unsigned int' ]],
    'p_vaddr': [ 0x08 , [ 'unsigned int' ]],
    'p_paddr': [ 0x0C , [ 'unsigned int' ]],
    'p_filesz': [ 0x10 , [ 'unsigned int' ]],
    'p_memsz': [ 0x14 , [ 'unsigned int' ]],
    'p_flags': [ 0x18 , [ 'unsigned int' ]],
    'p_align': [ 0x1C , [ 'unsigned int' ]],
    } ],
}

class CoreAddressSpace(FileAddressSpace):
    offset_index = 0
    
    def __init__(self, fname, mode='rb', fast=False):
        FileAddressSpace.__init__(self, fname, mode=mode, fast=fast)
        
        ## Parse the headers:
        address_space = FileAddressSpace(fname)
        profile = Profile(abstract_types=elf_types)
        header = NewObject('Elf32_Ehdr', 0, address_space, profile=profile)

        ## Create a sorted list of virtual offsets
        self.offsets = []
        for i in header.sections:
            if i.p_filesz.v() > 0:
                self.offsets.append((i.p_vaddr.v(), ## Vaddr start
                                     i.p_vaddr.v() + i.p_filesz.v(), ## Vaddr end
                                     i.p_offset.v()))

        def comp(x,y):
            if x[0]<y[0]: return -1
            return 1

        self.offsets.sort(comp)
        print self.offsets

    def test_physical_offset(self, offset, addr):
        vaddr_start, vaddr_end, paddr = self.offsets[offset]
        if vaddr_start <= addr and vaddr_end >= addr:
            physical_offset = addr - vaddr_start + paddr
            return physical_offset
        
    def find_physical_offset(self, addr):
        ## Check if we are in the same section as before:
        physical_offset = self.test_physical_offset(self.offset_index, addr)
        if physical_offset: return physical_offset
        
        for i in range(len(self.offsets)):
            physical_offset = self.test_physical_offset(i, addr)
            if physical_offset:
                ## Cache it for next time
                self.offset_index = i
                return physical_offset
            
        raise RuntimeError("Address 0x%08X is not contained in Core file" % addr)

    def read(self, addr, len):
        physical_offset = self.find_physical_offset(addr)
        self.fhandle.seek(physical_offset)
        return self.fhandle.read(len)

    def get_address_range(self):
        return [self.offsets[0][0], self.offsets[-1][1] ]

    def is_valid_address(self, addr):
        try:
            self.read(addr, 1)

            return True
        except RuntimeError:
            return False
        

c = CoreAddressSpace(sys.argv[1])
print "%r" % c.read(0xb7ed5e12,4)
