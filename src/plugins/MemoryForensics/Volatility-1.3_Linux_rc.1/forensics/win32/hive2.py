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

from forensics.object import *
from forensics.win32.scan2 import *
from forensics.win32.info import *
from forensics.win32.datetime import windows_to_unix_time
from forensics.addrspace import FileAddressSpace
from time import ctime
import os.path

FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])

def dump(src, length=8):
    N=0; result=''
    while src:
       s,src = src[:length],src[length:]
       hexa = ' '.join(["%02X"%ord(x) for x in s])
       s = s.translate(FILTER)
       result += "%04X   %-*s   %s\n" % (N, length*3, hexa, s)
       N+=length
    return result

class PoolScanHiveFast2(GenMemScanObject):
    """ Scan for _CMHIVE objects """
    def __init__(self,addr_space):
        GenMemScanObject.__init__(self, addr_space)
        self.pool_tag = "CM10"
        self.pool_size = 0x4a8

    class Scan(PoolScanner):
        def __init__(self, poffset, outer):
            PoolScanner.__init__(self, poffset, outer)
            self.add_constraint(self.check_blocksize_equal)
            self.add_constraint(self.check_pagedpooltype)
            #self.add_constraint(self.check_poolindex)
            self.add_constraint(self.check_hive_sig)

        def check_pagedpooltype(self, buff, found):
            data_types = meta_info.DataTypes
            pool_hdr_val = read_obj_from_buf(buff,self.data_types, \
                ['_POOL_HEADER', 'Ulong1'],found-4)
            if pool_hdr_val == None:
                return False           
 
            PoolType = (pool_hdr_val >> 16) & 0xFFFF
            PoolType = (PoolType & 0xFE00) >> 9 

            if ((PoolType == 0) or ((PoolType % 2) == 0)):
                return True
            
            return False	    

        def check_hive_sig(self, buff, found):
            sig = read_obj_from_buf(buff, self.data_types, 
                    ['_HHIVE', 'Signature'], found+4)
            if sig != 0xbee0bee0:
                return False
            else:
                return True

        def object_action(self,buff,object_offset):
            address = self.as_offset+object_offset
            print "%-15d %#-15x" % (address,address)

CI_TYPE_MASK   = 0x80000000
CI_TYPE_SHIFT  = 0x1F
CI_TABLE_MASK  = 0x7FE00000
CI_TABLE_SHIFT = 0x15
CI_BLOCK_MASK  = 0x1FF000
CI_BLOCK_SHIFT = 0x0C
CI_OFF_MASK    = 0x0FFF
CI_OFF_SHIFT   = 0x0

BLOCK_SIZE = 0x1000

class HiveAddressSpace:
    def __init__(self, baseAddressSpace, profile, hive_addr):
        self.base = baseAddressSpace
        self.profile = profile
        self.hive = NewObject("_HHIVE", hive_addr, baseAddressSpace, profile=profile)
        self.baseblock = self.hive.BaseBlock.v()
        self.flat = self.hive.Flat.v() > 0

    def vtop(self, vaddr):
        # If the hive is listed as "flat", it is all contiguous in memory
        # so we can just calculate it relative to the base block.
        if self.flat:
            return self.baseblock + vaddr + BLOCK_SIZE + 4

        ci_type = (vaddr & CI_TYPE_MASK) >> CI_TYPE_SHIFT
        ci_table = (vaddr & CI_TABLE_MASK) >> CI_TABLE_SHIFT
        ci_block = (vaddr & CI_BLOCK_MASK) >> CI_BLOCK_SHIFT
        ci_off = (vaddr & CI_OFF_MASK) >> CI_OFF_SHIFT

        block = self.hive.Storage[ci_type].Map.Directory[ci_table].Table[ci_block].BlockAddress

        return block + ci_off + 4

    #def hentry(self, vaddr):
    #    ci_type = (vaddr & CI_TYPE_MASK) >> CI_TYPE_SHIFT
    #    ci_table = (vaddr & CI_TABLE_MASK) >> CI_TABLE_SHIFT
    #    ci_block = (vaddr & CI_BLOCK_MASK) >> CI_BLOCK_SHIFT
    #    ci_off = (vaddr & CI_OFF_MASK) >> CI_OFF_SHIFT

    #    dir_map = read_obj(self.base, self.types, ['_HHIVE', 'Storage', ci_type, 'Map'],
    #        self.hive)
    #    if not dir_map:
    #        return None
    #    table = read_obj(self.base, self.types, ['_HMAP_DIRECTORY', 'Directory', ci_table],
    #        dir_map)
    #    if not table:
    #        return None
    #    #block = read_obj(self.base, self.types, ['_HMAP_TABLE', 'Table', ci_block, 'BlockAddress'],
    #    #    table)
    #    
    #    return Obj("_HMAP_ENTRY", table, self.base)

    def read(self, vaddr, length, zero=False):
        first_block = BLOCK_SIZE - vaddr % BLOCK_SIZE
        full_blocks = ((length + (vaddr % BLOCK_SIZE)) / BLOCK_SIZE) - 1
        left_over = (length + vaddr) % BLOCK_SIZE
        
        paddr = self.vtop(vaddr)
        if paddr == None and zero:
            if length < first_block:
                return "\0" * length
            else:
                stuff_read = "\0" * first_block
        elif paddr == None:
            return None
        else:
            if length < first_block:
                stuff_read = self.base.read(paddr, length)
                if not stuff_read and zero:
                    return "\0" * length
                else:
                    return stuff_read

            stuff_read = self.base.read(paddr, first_block)
            if not stuff_read and zero:
                stuff_read = "\0" * first_block

        new_vaddr = vaddr + first_block
        for i in range(0,full_blocks):
            paddr = self.vtop(new_vaddr)
            if paddr == None and zero:
                stuff_read = stuff_read + "\0" * BLOCK_SIZE
            elif paddr == None:
                return None
            else:
                new_stuff = self.base.read(paddr, BLOCK_SIZE)
                if not new_stuff and zero:
                    new_stuff = "\0" * BLOCK_SIZE
                elif not new_stuff:
                    return None
                else:
                    stuff_read = stuff_read + new_stuff
            new_vaddr = new_vaddr + BLOCK_SIZE

        if left_over > 0:
            paddr = self.vtop(new_vaddr)
            if paddr == None and zero:
                stuff_read = stuff_read + "\0" * left_over
            elif paddr == None:
                return None
            else:
                stuff_read = stuff_read + self.base.read(paddr, left_over)
        return stuff_read

    def read_long_phys(self, addr):
        string = self.base.read(addr, 4)
        (longval, ) =  struct.unpack('L', string)
        return longval

    def is_valid_address(self, addr):
        if not addr:
            return False
        vaddr = self.vtop(addr)
        if not vaddr:
            return False
        return self.base.is_valid_address(vaddr) 

    def save(self, outf):
        baseblock = self.base.read(self.baseblock, BLOCK_SIZE)
        if baseblock:
            outf.write(baseblock)
        else:
            outf.write("\0" * BLOCK_SIZE)

        length = self.hive.Storage[0].Length.v()
        for i in range(0, length, BLOCK_SIZE):
            data = None

            paddr = self.vtop(i)
            if paddr:
                paddr = paddr - 4
                data = self.base.read(paddr, BLOCK_SIZE)
            else:
                print "No mapping found for index %x, filling with NULLs" % i

            if not data:
                print "Physical layer returned None for index %x, filling with NULL" % i
                data = '\0' * BLOCK_SIZE

            outf.write(data)
    
    def stats(self, stable=True):
        if stable:
            stor = 0
            ci = lambda x: x
        else:
            stor = 1
            ci = lambda x: x | 0x80000000

        length = self.hive.Storage[stor].Length.v()
        total_blocks = length / BLOCK_SIZE
        bad_blocks_reg = 0
        bad_blocks_mem = 0
        for i in range(0, length, BLOCK_SIZE):
            i = ci(i)
            data = None
            paddr = self.vtop(i) - 4

            if paddr:
                data = self.base.read(paddr, BLOCK_SIZE)
            else:
                bad_blocks_reg += 1
                continue
            
            if not data:
                bad_blocks_mem += 1

        print "%d bytes in hive." % length
        print "%d blocks not loaded by CM, %d blocks paged out, %d total blocks." % (bad_blocks_reg, bad_blocks_mem, total_blocks)
        if total_blocks:
            print "Total of %.2f%% of hive unreadable." % (((bad_blocks_reg+bad_blocks_mem)/float(total_blocks))*100)
        
        return (bad_blocks_reg, bad_blocks_mem, total_blocks)


class HiveFileAddressSpace:
    def __init__(self, base):
        self.base = base

    def vtop(self, vaddr):
        return vaddr + BLOCK_SIZE + 4

    def read(self, vaddr, length, zero=False):
        first_block = BLOCK_SIZE - vaddr % BLOCK_SIZE
        full_blocks = ((length + (vaddr % BLOCK_SIZE)) / BLOCK_SIZE) - 1
        left_over = (length + vaddr) % BLOCK_SIZE
        
        paddr = self.vtop(vaddr)
        if paddr == None and zero:
            if length < first_block:
                return "\0" * length
            else:
                stuff_read = "\0" * first_block
        elif paddr == None:
            return None
        else:
            if length < first_block:
                stuff_read = self.base.read(paddr, length)
                if not stuff_read and zero:
                    return "\0" * length
                else:
                    return stuff_read

            stuff_read = self.base.read(paddr, first_block)
            if not stuff_read and zero:
                stuff_read = "\0" * first_block

        new_vaddr = vaddr + first_block
        for i in range(0,full_blocks):
            paddr = self.vtop(new_vaddr)
            if paddr == None and zero:
                stuff_read = stuff_read + "\0" * BLOCK_SIZE
            elif paddr == None:
                return None
            else:
                new_stuff = self.base.read(paddr, BLOCK_SIZE)
                if not new_stuff and zero:
                    new_stuff = "\0" * BLOCK_SIZE
                elif not new_stuff:
                    return None
                else:
                    stuff_read = stuff_read + new_stuff
            new_vaddr = new_vaddr + BLOCK_SIZE

        if left_over > 0:
            paddr = self.vtop(new_vaddr)
            if paddr == None and zero:
                stuff_read = stuff_read + "\0" * left_over
            elif paddr == None:
                return None
            else:
                stuff_read = stuff_read + self.base.read(paddr, left_over)
        return stuff_read

    def read_long_phys(self, addr):
        string = self.base.read(addr, 4)
        (longval, ) =  struct.unpack('L', string)
        return longval

    def is_valid_address(self, vaddr):
        paddr = self.vtop(vaddr)
        if not paddr: return False
        return self.base.is_valid_address(paddr)

def hive_list(flat_address_space, process_address_space, types, start):
    """
    Get the virtual addresses of all hives
    """
    
    hives_list = []

    (offset, _)  = get_obj_offset(types, ['_CMHIVE', 'HiveList'])

    head = read_obj(flat_address_space, types, ['_CMHIVE', 'HiveList', 'Flink'], start) - offset
    next = read_obj(process_address_space, types, ['_CMHIVE', 'HiveList', 'Flink'], head) - offset
    print hex(head), hex(next)
    while next != head:
        if not next or not process_address_space.is_valid_address(next):
            print "Hive list truncated"
            return hives_list

        sig = hive_sig(process_address_space, types, next)
        if sig == 0xbee0bee0:
            # If the signature doesn't match, probably the list head
            hives_list.append(next)
            
        next = read_obj(process_address_space, types, ['_CMHIVE', 'HiveList', 'Flink'], next) - offset

    sig = hive_sig(process_address_space, types, next)
    if sig == 0xbee0bee0:
        hives_list.append(next)
    return hives_list
    
def hive_fname(addr_space, types, addr):
    """Read the hive file name from its File Object"""
    fobjaddr = read_obj(addr_space, types, ['_CMHIVE', 'FileObject'], addr)
    if fobjaddr: fname = read_unicode_string(addr_space, types, ['_FILE_OBJECT', 'FileName'], fobjaddr)
    else: fname = ''
    return fname

def hive_fname2(addr_space, types, addr):
    """Read the hive file name from its FileFullPath member"""
    return read_unicode_string(addr_space, types, ['_CMHIVE', 'FileFullPath'], addr)

def hive_username(addr_space, types, addr):
    """Get the FileUserName string for a hive"""
    return read_unicode_string(addr_space, types, ['_CMHIVE', 'FileUserName'], addr)

def hive_sig(addr_space, types, addr): 
    """Return the signature for a hive. Should always be 0xbee0bee0"""
    return read_obj(addr_space, types, ['_HHIVE', 'Signature'], addr)

def find_first_hive(flat_address_space):
    sig = "CM10\xe0\xbe\xe0\xbe"
    i = 0
    while flat_address_space.is_valid_address(i):
        if flat_address_space.read(i,len(sig)) == sig: return i+4
        i += 4
