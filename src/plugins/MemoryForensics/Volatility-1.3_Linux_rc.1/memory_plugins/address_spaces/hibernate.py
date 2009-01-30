""" A Hiber file Address Space """
import standard
from forensics.object2 import NewObject, Profile
from forensics.win32.xpress import xpress_decode
import time,sys
import cPickle as pickle

PAGE_SIZE = 0x1000
page_shift = 12

class Store:
    def __init__(self, limit=50):
        self.limit = limit
        self.cache = {}
        self.seq = []
        self.size = 0

    def put(self, key, obj):
        self.cache[key] = obj
        self.size += len(obj)
        
        self.seq.append(key)
        if len(self.seq) >= self.limit:
            key = self.seq.pop(0)
            self.size -= len(self.cache[key])
            del self.cache[key]

    def get(self, key):
        return self.cache[key]
    
class WindowsHiberFileSpace32(standard.FileAddressSpace):
    """ This is a hibernate address space for windows hibernation files.

    In order for us to work we need to:
    1) have a valid baseAddressSpace
    2) the first 4 bytes must be 'hibr'
    """
    order = 10
    def __init__(self, baseAddressSpace, opts):
        assert(baseAddressSpace)
        self.runs = []
        self.base = baseAddressSpace
	self.PageDict = {}
        self.HighestPage = 0
	self.PageIndex = 0
        self.AddressList = []
        self.LookupCache = {}
        self.PageCache = Store(10)
        self.MemRangeCnt = 0
        self.offset = 0
        # Extract header information
        self.profile = Profile()
        self.header = NewObject('_IMAGE_HIBER_HEADER', 0, baseAddressSpace,
                                profile=self.profile)
        
        ## Is the signature right?
        assert(self.header.Signature.v() == 'hibr')
        
        # Extract processor state
        self.ProcState = NewObject("_KPROCESSOR_STATE", 2 * 4096, baseAddressSpace,
                                   profile=self.profile)

        ## This is a pointer to the page table - any ASs above us dont
        ## need to search for it.
        self.dtb = self.ProcState.SpecialRegisters.Cr3.v()

        try:
            fd = open("/tmp/cache.bin",'rb')
            data = pickle.load(fd)
            self.PageDict , self.LookupCache = data
            fd.close()
        except (IOError, EOFError):
            self.build_page_cache()
            fd = open("/tmp/cache.bin",'wb')
            pickle.dump((self.PageDict , self.LookupCache), fd, -1)
            fd.close()
            
    def build_page_cache(self):
        XpressIndex = 0    
        XpressHeader = NewObject("_IMAGE_XPRESS_HEADER",
                                 (self.header.FirstTablePage + 1) * 4096, \
                                 self.base, profile=self.profile)
        
        XpressBlockSize = self.get_xpress_block_size(XpressHeader)

        MemoryArrayOffset = self.header.FirstTablePage * 4096

        while MemoryArrayOffset:
            MemoryArray = NewObject('_MEMORY_RANGE_ARRAY', MemoryArrayOffset, self.base,
                                    profile = self.profile)

            EntryCount = MemoryArray.MemArrayLink.EntryCount.v()
            for i in MemoryArray.RangeTable:
                start = i.StartPage.v()
                end = i.EndPage.v()
                LocalPageCnt = end - start

                if end > self.HighestPage:
                    self.HighestPage = end

                tmp = [start * 0x1000, \
                       LocalPageCnt * 0x1000]
                self.AddressList.append(tmp)

                for j in range(0,LocalPageCnt):
                    if (XpressIndex and ((XpressIndex % 0x10) == 0)):
                        XpressHeader, XpressBlockSize = \
                                      self.next_xpress(XpressHeader, XpressBlockSize)

                    PageNumber = start + j
                    XpressPage = XpressIndex % 0x10
                    #print [(PageNumber,XpressBlockSize,XpressPage)]
                    if XpressHeader.offset not in self.PageDict:
                        self.PageDict[XpressHeader.offset] = \
                            [(PageNumber,XpressBlockSize,XpressPage)]
                    else:
                        self.PageDict[XpressHeader.offset].append(
                            (PageNumber, \
                             XpressBlockSize, XpressPage))
                        
                    ## Update the lookup cache
                    self.LookupCache[PageNumber] = (
                        XpressHeader.offset,XpressBlockSize,XpressPage)

                    self.PageIndex += 1
                    XpressIndex += 1

            NextTable = MemoryArray.MemArrayLink.NextTable.v()

            if (NextTable and (EntryCount == 0xFF)):
                MemoryArrayOffset = NextTable * 0x1000
                self.MemRangeCnt+=1
                XpressHeader,XpressBlockSize = \
                                             self.next_xpress(XpressHeader, XpressBlockSize)
                     
                XpressIndex = 0
            else:
                MemoryArrayOffset = 0
                    
    def convert_to_raw(self,ofile):
        nb = len(self.PageDict)
	num_pages = self.get_number_of_pages()
        widgets = ['Convert: ', Percentage(), ' ', \
            Bar(marker=RotatingMarker()),' ', ETA()]
        pbar = ProgressBar(widgets=widgets, maxval=num_pages).start()

        page_count = 0
        for i,xb in enumerate(self.PageDict.keys()):
            nb = len(self.PageDict)
            size = self.PageDict[xb][0][1]
            data_z = self.base.read(xb+0x20,size)
            if size == 0x10000:
                data_uz = data_z
            else:
                data_uz = xpress_decode(data_z)
            for page,size,offset in self.PageDict[xb]:
	        pbar.update(page_count)
                ofile.seek(page*0x1000)
                ofile.write(data_uz[offset*0x1000:offset*0x1000+0x1000])
		page_count+=1

            del data_z,data_uz
        pbar.finish() 

    def next_xpress(self, XpressHeader, XpressBlockSize):
        XpressHeaderOffset = XpressBlockSize + XpressHeader.offset + \
                             XpressHeader.size()

        ## We only search this far
        BLOCKSIZE = 1024
        original_offset = XpressHeaderOffset
        while 1:
            data = self.base.read(XpressHeaderOffset, BLOCKSIZE)
            Magic_offset = data.find("\x81\x81xpress")
            if Magic_offset >= 0:
                XpressHeaderOffset += Magic_offset
                break
            else:
                XpressHeaderOffset += len(data)
             
            ## Only search this far in advance
            if XpressHeaderOffset - original_offset > 10240:
                return None,None

        XpressHeader = NewObject("_IMAGE_XPRESS_HEADER", XpressHeaderOffset, self.base,
                                 profile=self.profile)
        XpressBlockSize = self.get_xpress_block_size(XpressHeader)
        
        return XpressHeader,XpressBlockSize

    def get_xpress_block_size(self, xpress_header):
        u0B = xpress_header.u0B.v() << 24
        u0A = xpress_header.u0A.v() << 16
        u09 = xpress_header.u09.v() << 8

        Size = u0B + u0A + u09
        Size = Size >> 10
        Size = Size + 1

        if ((Size % 8) == 0):
            return Size
        return (Size & ~7) + 8

    def get_header(self):
        return self.header

    def get_base(self):
        return self.base

    def get_signature(self):
        return self.header.Signature

    def get_system_time(self):
        return self.header.SystemTime

    def is_paging(self):
        return (self.ProcState.SpecialRegisters.Cr0.v() >> 31) & 1

    def is_pse(self):
        return (self.ProcState.SpecialRegisters.Cr4.v() >> 4) & 1

    def is_pae(self):
        return (self.ProcState.SpecialRegisters.Cr4.v() >> 5) & 1

    def get_number_of_memranges(self):
        return self.MemRangeCnt

    def get_number_of_pages(self):
        return self.PageIndex

    def get_addr(self, addr):
        page_offset = (addr & 0x00000FFF)
        page = addr >> page_shift
        if page in self.LookupCache:
            (hoffset,size,pageoffset) = self.LookupCache[page]
            return hoffset, size, pageoffset	
        return None, None, None

    def get_block_offset(self,xb,addr):
        page = addr >> page_shift
        if page in self.LookupCache:
            (hoffset,size,pageoffset) = self.LookupCache[page]
            return pageoffset	
        return None                
        
    def is_valid_address(self, addr):
        XpressHeaderOffset, XpressBlockSize, XpressPage = self.get_addr(addr)
        return XpressHeaderOffset != None

    def read_xpress(self,baddr,BlockSize):
        try:
            return self.PageCache.get(baddr)
        except KeyError:
            data_read = self.base.read(baddr,BlockSize)
            if BlockSize == 0x10000:
                data_uz = data_read
            else:
                data_uz = xpress_decode(data_read)

                self.PageCache.put(baddr, data_uz)
                
            return data_uz

    def fread(self, length):
        data = self.read(self.offset, length)
        self.offset += len(data)
        return data

    def _partial_read(self, addr, len):
        """ A function which reads as much as possible from the current page.

        May return a short read.
        """
        ## The offset within the page where we start
        page_offset = (addr & 0x00000FFF)

        ## How much data can we satisfy?
        available = min(PAGE_SIZE - page_offset, len)

        ImageXpressHeader, BlockSize, XpressPage = self.get_addr(addr)
        if not ImageXpressHeader: return None
        
        baddr = ImageXpressHeader + 0x20

        data = self.read_xpress(baddr, BlockSize)

        ## Each block decompressed contains 2**page_shift pages. We
        ## need to know which page to use here.
        offset = XpressPage * 0x1000 + page_offset
        
        return data[offset:offset + available]

    def read(self, addr, length):
        result = ''
        while length > 0:
            data = self._partial_read(addr, length)
            if not data: break
            
            addr += len(data)
            length -= len(data)
            result += data

        return result

    def zread(self, addr, len):
        raise RuntimeError("Unimplemented")
        page_offset = (addr & 0x00000FFF)
        first_block = 0x1000 - addr % 0x1000
        full_blocks = ((len + (addr % 0x1000)) / 0x1000) - 1
        left_over = (len + addr) % 0x1000

        self.check_address_range(addr)

        ImageXpressHeader = self.get_addr(addr)
        if ImageXpressHeader == None:
            if len < first_block:
                return ('\0' * length)
            stuff_read = ('\0' * first_block) 
        else:
            if len < first_block:
                return self.read(addr, len)
            stuff_read = self.read(addr, first_block)
       
        new_addr = addr + first_block

        for i in range(0,full_blocks):
            ImageXpressHeader = self.get_addr(new_addr)
            if ImageXpressHeader == None:
                stuff_read = stuff_read + ('\0' * 0x1000)
            else:
                stuff_read = stuff_read + self.read(new_addr, 0x1000)
            new_addr = new_addr + 0x1000
	

        if left_over > 0:
            ImageXpressHeader = self.get_addr(new_addr)
            if ImageXpressHeader == None:
                stuff_read = stuff_read + ('\0' * left_over)
            else:
                stuff_read = stuff_read + self.read(new_addr, left_over)

        return stuff_read    

    def read_long(self, addr):
        baseaddr = self.get_addr(addr)
        string = self.read(addr, 4)
        (longval, ) = struct.unpack('=L', string)
        return longval

    def get_available_pages(self):
        page_list = []
        for i,xb in enumerate(self.PageDict.keys()):
            for page,size,offset in self.PageDict[xb]:
                page_list.append([page*0x1000, 0x1000])
        return page_list

    def get_address_range(self):
        """ This relates to the logical address range that is indexable """
	size = self.HighestPage*0x1000+0x1000
        return [0,size]

    def check_address_range(self,addr):
        memrange = self.get_address_range()
        if addr < memrange[0] or addr > memrange[1]:
            raise IOError

    def get_available_addresses(self):
        """ This returns the ranges  of valid addresses """
        return self.AddressList

    def close(self):
        self.base.close()

    def get_version(self):

        if self.is_pae() == 1:
            addr_space = IA32PagedMemoryPae(self, self.ProcState.SpecialRegisters.Cr3.v())
        else:
            addr_space = IA32PagedMemory(self, self.ProcState.SpecialRegisters.Cr3.v())

        if addr_space == None:
            return (None,None,None)

        GdtIndex = (0x3B >> 3)
        GdtrBase = read_obj(self.base, types,
	     ['_KPROCESSOR_STATE', 'SpecialRegisters','Gdtr','Base'], \
             self.ProcStateOffset)

        NtTibAddr = GdtrBase + GdtIndex * obj_size(hiber_types,'_KGDTENTRY')

        BaseLow = read_obj(addr_space, hiber_types,
	     ['_KGDTENTRY','BaseLow'], NtTibAddr)

        BaseMid = read_obj(addr_space, hiber_types,
	     ['_KGDTENTRY','BaseMid'], NtTibAddr)

        BaseHigh = read_obj(addr_space, hiber_types,
	     ['_KGDTENTRY','BaseHigh'], NtTibAddr)

        NtTibAddress = (BaseLow) | (BaseMid << (2 * 8)) | (BaseHigh << (3 * 8));

        if ((NtTibAddress == 0) or (NtTibAddress > 0x80000000)):
            return (None,None,None)

        ProcessEnvironmentBlock =  read_obj(addr_space, types,
	     ['_TEB', 'ProcessEnvironmentBlock'], NtTibAddress)

        OSMajorVersion = read_obj(addr_space, types,
	     ['_PEB', 'OSMajorVersion'], ProcessEnvironmentBlock)

        OSMinorVersion = read_obj(addr_space, types,
	     ['_PEB','OSMinorVersion'], ProcessEnvironmentBlock)

        OSBuildNumber = read_obj(addr_space, types,
	     ['_PEB','OSBuildNumber'],ProcessEnvironmentBlock)

        return (OSMajorVersion,OSMinorVersion,OSBuildNumber)
