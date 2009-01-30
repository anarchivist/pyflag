""" An AS for processing crash dumps """
import standard
from forensics.object2 import NewObject, Profile

page_shift = 12

class WindowsCrashDumpSpace32(standard.FileAddressSpace):
    """ This AS supports windows Crash Dump format """
    order = 30
    def __init__(self, baseAddressSpace, opts):
        ## We must have an AS below us
        assert(baseAddressSpace)

        ## Must start with the magic PAGEDUMP
        assert(baseAddressSpace.read(0,8) == 'PAGEDUMP')

        self.runs = []
        self.offset = opts.get('offset',0)
        self.base = baseAddressSpace
        self.fname = ''
        self.profile = Profile()

        self.header = NewObject("_DMP_HEADER", self.offset, baseAddressSpace,
                                profile = self.profile)

        self.runs = [ (x.BasePage.v(), x.PageCount.v()) \
                      for x in self.header.PhysicalMemoryBlockBuffer.Run ]

        self.dtb = self.header.DirectoryTableBase.v()

    def get_header(self):
        return self.dump_header

    def get_base(self):
        return self.base

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
            stuff_read = self.base.read(baddr,len)
            return stuff_read

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
