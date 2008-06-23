#!/usr/bin/env python
# ******************************************************
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.87-pre1 Date: Thu Jun 12 00:48:38 EST 2008$
# ******************************************************
#
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# *
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
# ******************************************************

""" This is an implementation of a Zip parser. This is very much more
looser than the python implementation, because we mostly want to find
carved zip files so we proceed with errors.

The file format specification is given here:

http://www.pkware.com/documents/casestudies/APPNOTE.TXT

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
        #['data' , STRING, dict(length=5) ],
        #['data' , ZipPayload, dict(length = lambda x: int(x['compr_size']))],
        ]

class EndCentralDirectory(SimpleStruct):
    fields = [
        ['magic' , ULONG_CONSTANT, dict(expected = 0x06054b50) ],
        ['number_of_this_disk', USHORT ],
        ['disk_with_cd',USHORT],
        ['total_entries_in_cd_on_disk',USHORT],
        ['total_entries_in_cd',USHORT],
        ['size_of_cd', ULONG],
        ['offset_of_cd',ULONG],
        ['comment_len', USHORT],
        ['comment', STRING, dict(length = lambda x: int(x['comment_len']))],
        ]

class CDFileHeader(SimpleStruct):
    fields = [
        ['magic' , ULONG_CONSTANT, dict(expected = 0x02014b50) ],
        ['version_made_by', USHORT],
        ['version_needed', USHORT],
        ['flags' , USHORT],
        ['compression',USHORT],
        ['lastmodtime',USHORT],
        ['lastmoddate',USHORT],
        ['crc-32',ULONG],
        ['compressed_size',ULONG],
        ['uncompr_size',ULONG],
        ['file_name_length', USHORT],
        ['extra_field_length', USHORT],
        ['file_comment_length',USHORT],
        ['disk_number_start', USHORT],
        ['internal_file_attr', USHORT],
        ['external_file_attr',ULONG],
        ['relative_offset_local_header', ULONG],
        ['filename', STRING, dict(length = lambda x: int(x['file_name_length']))],
        ['extra_field', STRING, dict(length = lambda x: int(x['extra_field_length']))],
        ['file_comment', STRING, dict(length = lambda x: int(x['file_comment_length']))],
        ]

class CD(StructArray):
    target_class = CDFileHeader

ZIP_STORED = 0
ZIP_DEFLATED = 8

if __name__ == "__main__":

    def process_header(fd, offset):
        b = Buffer(fd=fd)[offset:]
        
        ## Now we read the buffer:
        h = ZipFileHeader(b, endianess='little')
        path = h['zip_path'].get_value()

        if len(path)==0: return
        
        ## Make sure the zip path is all ascii:
        for c in path:
            if ord(c)<32 or ord(c)>128:
                return
        
        print h
        offset = h['extra_field'].buffer.offset + h['extra_field_length'].get_value()
        print hex(offset)

        ## Extract the file out
        return
    
        fd.seek(offset)
        data = fd.read(100)
        print "%r" % data
        print "%r" % decompress_data(data)
        

    fd=open(sys.argv[1],'r')
    fd2 = open(sys.argv[1])
    ## Search the buffer for the magic:
    offset = 0
    while 1:
        data = fd2.read(1024 * 1024)
        if len(data)==0: sys.exit(0)

        data_offset = 0
        while 1:
            data_offset=data.find("\x50\x4B\x03\x04", data_offset+1)
            if data_offset < 0:
                break
                
            process_header(fd, offset + data_offset)
            
        offset+=len(data)

