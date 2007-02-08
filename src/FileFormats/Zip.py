""" This is an implementation of a Zip parser. This is very much more
looser than the python implementation, because we mostly want to find
carved zip files so we proceed with errors.
"""
from format import *
from plugins.FileFormats.BasicFormats import *
import sys, zlib

## We dont bother checking the CRC here at all because we might lose
## sync sometime through the file
def decompress_data(data):
    dc = zlib.decompressobj(-15)
    bytes = dc.decompress(data)
    ex = dc.decompress('Z') + dc.flush()
    if ex:
        bytes += ex
        
    return bytes

class ZipPayload(STRING):
    def read(self):
        data = STRING.read(self)
        return decompress_data(data)
    
class ZipFileHeader(SimpleStruct):
    fields = [
        ['magic', ULONG_CONSTANT, dict(expected = 0x04034b50) ],
        ['version', USHORT, {}],
        ['flags', USHORT, {}],
        ['compression_method', USHORT, {}],
        ['lastmodtime', USHORT, {}],
        ['lastmoddate', USHORT, {}],
        ['crc32', ULONG, {}],
        ['compr_size', ULONG, {}],
        ['uncompr_size', ULONG, {}],
        ['name_len', USHORT, {}],
        ['extra_field_len', USHORT, {}],
        ['zip_path', STRING, dict(length = lambda x: int(x['name_len']))],
        ['extra_field', STRING, dict(length = lambda x: int(x['extra_field_len']))],
        ## This is only a byte so we can find out its offet. We want
        ## to decompress the data in chunks rather than read it all at
        ## once to ensure that we dont overflow.
        ['data' , STRING, dict(length=5) ],
        #['data' , ZipPayload, dict(length = lambda x: int(x['compr_size']))],
        ]

ZIP_STORED = 0
ZIP_DEFLATED = 8

if __name__ == "__main__":
    fd=open(sys.argv[1],'r')
    ## Search the buffer for the magic:
    offset = 0
    while 1:
        data = fd.read(1024)
        if len(data)==0: sys.exit(0)
        pos = data.find("\x50\x4B\x03\x04")
        if pos >= 0:
            b = Buffer(fd=fd)[offset + pos:]
            break

        offset+=len(data)

    ## Now we read the buffer:
    h = ZipFileHeader(b, endianess='little')
    print h
    offset = h['data'].buffer.offset
    print hex(offset)
    fd.seek(offset)
    data = fd.read(100)
    print "%r" % data
    print "%r" % decompress_data(data)
    
