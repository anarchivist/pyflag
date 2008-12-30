""" This is a raid IO Source implementation. """
import plugins.Images as Images
import pyflag.FlagFramework as FlagFramework

class RAIDFD(Images.OffsettedFDFile):
    """ A RAID file like object - must be initialised with the correct parameters """
    def __init__(self, fds, blocksize, map, offset):
        self.readptr = 0
        self.fds = fds
        ## The number of disks in the set
        self.disks = len(fds)
        self.blocksize = blocksize
        self.parse_map(map)
        self.offset = offset
        ## We estimate the size:
        fds[0].seek(0,2)
        self.size = fds[0].tell() * self.physical_period

    def seek(self, offset, whence=0):
        """ fake seeking routine """
        readptr = self.readptr
        if whence==0:
            readptr = offset + self.offset
        elif whence==1:
            readptr += offset
        elif whence==2:
            readptr = self.size

        if readptr < self.offset:
            raise IOError("Seek before start of file")

        self.readptr = readptr

    def parse_map(self, map):
        elements = map.split(".")
        ## The physical period is the number of blocks before the map
        ## repeats in each disk
        self.physical_period = len(elements)/len(self.fds)

        self.map = []
        while len(elements)>0:
            self.map.append([])
            for i in range(self.disks):
                try:
                    disk_number = int(elements.pop(0))
                except: disk_number=None
                
                self.map[-1].append(disk_number)

        self.period_map = []
        for i in range((self.physical_period -1) * self.disks):
            found = False
            ## Find the required disk in the map:
            for period_index in range(len(self.map)):
                try:
                    d = self.map[period_index].index(i)
                    self.period_map.append((period_index,d))
                    found = True
                    break
                except: pass

            if not found:
                print "position %s not found" % i
            
        self.logical_period_size = len(self.period_map)
        
    def partial_read(self, length):
        ## calculate the current position within the logical
        ## image. Logical blocks refer to the reconstituted image,
        ## physical to the raw disks
        logical_block_number = self.readptr / self.blocksize
        logical_block_offset = self.readptr % self.blocksize

        ## Our logical block position within the period
        logical_period_position = logical_block_number % self.logical_period_size
        logical_period_number = logical_block_number / self.logical_period_size

        ## Now work out which disk is needed.
        physical_period_number, disk_number = self.period_map[logical_period_position]

        ## Now the physical block within the disk:
        physical_block_number = logical_period_number * self.physical_period \
                                + physical_period_number

        ## Now fetch the data
        to_read = min(self.blocksize - logical_block_offset, length)

        self.fds[disk_number].seek(self.blocksize * physical_block_number \
                                   + logical_block_offset)
        data = self.fds[disk_number].read(to_read)
        self.readptr += to_read
        
        return data


class RAID(Images.Standard):
    """ RAID image sets """
    types = [ ["5","Raid 5 - 1 Parity disk" ] ]
    
    def form(self, query, result):
        keys = []
        values = []
        for x,y in self.types:
            keys.append(x)
            values.append(y)
        result.const_selector("Raid Type", 'type', keys,values)
        result.fileselector("Disks", name='filename')
        result.textfield("Block size",'blocksize')
        result.textfield("Period",'period')
        result.textarea("Map",'map')
        self.calculate_partition_offset(query, result)

    def create(self, name,case, query):
        offset = FlagFramework.calculate_offset_suffix(query.get('offset','0'))
        filenames = self.glob_filenames(query.getarray('filename'))
        ## FIXME - allow arbitrary IO Source URLs here
        fds = [ open(f) for f in filenames ]
        blocksize = FlagFramework.calculate_offset_suffix(query.get('blocksize','32k'))
        return RAIDFD(fds, blocksize, query['map'], offset)
