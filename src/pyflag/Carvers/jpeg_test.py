import struct, sys
import Carver, jpeg

SECTOR_SIZE=512

c = Carver.Reassembler(open("dfrws-2007-challenge.img"))
#c = Carver.Reassembler(open("dfrws-2006-challenge.img"))
## Target a specific jpeg in it:
x = 12
if x==1:
    c.add_point(0, 5948928, "File header")
#    c.add_point(30 * SECTOR_SIZE, 48561152 + 50 * SECTOR_SIZE, "Forced")
#    c.add_point(202 * SECTOR_SIZE, 6065663, "Forced")
#    c.add_point(203 * SECTOR_SIZE, 6066175, "Forced")
#    c.add_point(204 * SECTOR_SIZE, 6066687, "Forced")
#    c.add_point(204 * SECTOR_SIZE, 6066687, "Forced")
#    c.add_point(190720, 6152959, "EOF")
elif x==2:
    c.add_point(0, 44910592, "File header")
#    c.add_point(243 * SECTOR_SIZE, 87677  * SECTOR_SIZE, "Force")
#    c.add_point(251 * SECTOR_SIZE, 87538  * SECTOR_SIZE, "Force")
#    c.add_point(295 * SECTOR_SIZE, 44910592, "EOF")
elif x==3:
    c.add_point(0, 23329792, "File header")
#    c.add_point(573499, 23974970, "EOF")
elif x==4:
    c.add_point(0, 48561152, "File header")
#    c.add_point(924877, 49486541, "EOF")
elif x==5:
    c.add_point(0, 41611 * SECTOR_SIZE, "File header")
#    c.add_point(100 * SECTOR_SIZE, 41564 * SECTOR_SIZE, "File header")
#    c.add_point(1021085, 22630556, "EOF")
elif x==6:
    c.add_point(0, 90377 * SECTOR_SIZE, "File header")
#    c.add_point(675 * SECTOR_SIZE, 93669 * SECTOR_SIZE, "Forced")
    
elif x==7:
    c.add_point(0, 93780 * SECTOR_SIZE, "File header")

elif x==12:
    c.add_point(0, 87716 * SECTOR_SIZE, "File header")

d = jpeg.decoder(c)
def best_sector(d):
    start = d.decode() or 0
    print start
    
    print "Discontinuity detected after %s" % d.last_good_sector()
    for sector in range(d.last_good_sector(), d.last_good_sector()+30):
        print "Trying to decompress %s" % sector
        d.decode(sector)
        print "Errors %s - best sector so far %s" % (d.warnings(), d.last_sector())
        #d.save(open("output_test%s.ppm" % sector,'w'))
        if d.warnings()>0:
            return sector-2

        print "Last sector %s" % d.last_sector()
        if d.last_sector() < sector:
            return d.last_sector()

def brute_force(c,d, generator):
    first_row = d.last_good_row()
    print "Will test from row %s" % first_row
    
    for file_offset,sector_offset in generator:
        print "Testing sector %s at %s Row %s" % (sector_offset,file_offset, first_row)
        c.seek(0)
        c.add_point(file_offset * SECTOR_SIZE,sector_offset * SECTOR_SIZE,"Forced")
        d.decode((file_offset+5))
        if d.warnings()==0:
            print "Last good row %s" % (d.last_good_row()-16)
            estimate = d.find_discontinuity(d.last_good_row()-16)
            print "Integral is row: %s, value %s" % estimate
            print "Found a possible hit"
            #d.save(open("output_test%s-%s.ppm" % (sector_offset,file_offset),'w'))
            if estimate[1] < 300:
                return
        
        c.del_point(file_offset * SECTOR_SIZE)

def generator_backwards(c,d):
    b = best_sector(d)

    ## Sector before the header:
    sector = c.interpolate(0)[0]/SECTOR_SIZE - 1
    sector = 87678

    while 1:
        for x in range(b,b+2):
            yield x,sector
        sector-=1

def generate_forward(c,d, start):
    b = best_sector(d)

    ## Thats the image sector where the header is plus the position of
    ## the discontinuety
    #sector = c.interpolate(0)[0]/SECTOR_SIZE + b
    #sector = 93660
    #sector = 99654
    sector = start
    
    while 1:
        for x in range(b,b+5):
            yield x,sector
        sector +=1

open("output_test.jpg","w").write(c.read(1000 * SECTOR_SIZE))
d.decode()
#print d.warnings(), d.last_good_sector()
#print d.find_discontinuity(10)

#brute_force(c,d, generate_forward(c,d, 93660))
#brute_force(c,d, generate_forward(c,d, 100045))
brute_force(c,d, generator_backwards(c,d))
c.seek(0)
open("output_test.jpg","w").write(c.read(c.size()))

brute_force(c,d, generator_backwards(c,d))
#brute_force(c,d, generate_forward(c,d, 99654))
c.seek(0)
open("output_test2.jpg","w").write(c.read(c.size()))

#brute_force(c,d, generate_forward(c,d, 99654))
#c.seek(0)
#open("output_test3.jpg","w").write(c.read(c.size()))

sys.exit(0)



#fd = open(sys.argv[1])

## Read marker:
def read_marker(fd):
    ## Markers are 2 bytes long:
    x = fd.read(2)
    try:
        marker = struct.unpack(">H",x)[0]
    except struct.error:
        return 0
    
    print "Marker is 0x%X" % marker
    if marker==0xFFD8:
        print "Start of frame marker"
        return 2

    elif marker==0xFFDA:
        print "Unsized section 0x%X, searching for next marker" % marker
        length = 1
        while 1:
            data = fd.read(1)
            if len(data)==0: break
            
            if data=='\xff':
                tmp  = fd.read(1)
                if tmp=='\x00': continue
                fd.seek(-1,1)
                break
            length+=1
            
        return length
    
    elif marker==0xFFD9:
        print "End of file"
        return 0

    elif marker >= 0xFF00 and marker <= 0xFFFF:
        x = fd.read(2)
        length = struct.unpack(">H",x)[0] - 2
        print "Found section length of %s - skipping" % length
        fd.read(length)
        return length

    else:
        return 1

c.seek(0)
while read_marker(c):
    pass
