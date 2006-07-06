# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.82 Date: Sat Jun 24 23:38:33 EST 2006$
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
""" A Library to read PE executable files

Note that this file format although very well documented has evolved over the years so it contain a lot of strange fields which are no longer used.
"""
from format import *
from plugins.FileFormats.BasicFormats import *
import sys

class IMAGE_DOS_HEADER(SimpleStruct):
    """ The simple Dos header at the begining of the file """
    def init(self):
        self.fields = [
            [ "e_magic", STRING,{'length':2},"Magic number", ],
            [ "e_cblp",  WORD,  {},        "Bytes on last page of file",],
            [ "e_cp",    WORD,  {},        "Pages in file",],
            [ "e_crlc",  WORD,  {},        "Relocations",],
            [ "e_cparhdr",WORD, {},        "Size of header in paragraphs",],
            [ "e_minalloc",WORD,{},        "Minimum extra paragraphs needed",],
            [ "e_maxalloc",WORD,{},        "Maximum extra paragraphs needed",],
            [ "e_ss",    WORD,  {},        "Initial (relative) SS value",],
            [ "e_sp",    WORD,  {},        "Initial SP value",],
            [ "e_csum",  WORD,  {},        "Checksum",],
            [ "e_ip",    WORD,  {},        "Initial IP value",],
            [ "e_cs",    WORD,  {},        "Initial (relative) CS value",],
            [ "e_lfarlc",WORD,  {},        "File address of relocation table",],
            [ "e_ovno",  WORD,  {},        "Overlay number",],
            [ "e_res",   WORD_ARRAY, {'count':4},"Reserved words",],
            [ "e_oemid", WORD,  {},        "OEM identifier (for e_oeminfo)",],
            [ "e_oeminfo",WORD, {},        "OEM information- e_oemid specific",],
            [ "e_res2",  WORD_ARRAY,{'count':10},"Reserved words",],
            [ "e_lfanew",P_IMAGE_FILE_HEADER,{},"File address of new exe header",],
            ]

    def read(self):
        result=SimpleStruct.read(self)
        if result['e_magic']!='MZ':
            raise IOError("File does not appear to have the right magic (MZ)")

        return result

class IMAGE_FILE_HEADER(SimpleStruct):
    """ The PE header pointed to by the Dos header """
    def init(self):
        self.fields = [
            [ "e_magic", STRING,{'length':4},"Magic",],
            [ "Machine", WORD ],
            [ "NumberOfSections", WORD ],
            [ "TimeDateStamp", TIMESTAMP],
            [ "PointerToSymbolTable", DWORD,],
            [ "NumberOfSymbols", DWORD, ],
            [ "SizeOfOptionalHeader", WORD, ],
            [ "Characteristics", WORD, ],
            ]

    def read(self):
        result=SimpleStruct.read(self)
        if result['e_magic']!='PE\x00\x00':
            raise IOError("File does not appear to be a PE executable, magic is not correct (PE %s)" % result['e_magic'] )

        self.add_element(result, "OptionalHeader",
                         IMAGE_OPTIONAL_HEADER(
                               self.buffer[self.offset:],
                               no_sections=result['NumberOfSections'].get_value()
                               ))
        
        return result
        
class P_IMAGE_FILE_HEADER(POINTER):
    target_class = IMAGE_FILE_HEADER

class IMAGE_OPTIONAL_HEADER(SimpleStruct):
    """ An optional header pointed to by the PE header.

    This is not really optional at all - I guess its called optional in a cynical manner, just as the P in PE executable stands for Portable (can you even use the word portable and windows in the same sentence?).
    """
    def init(self):
        self.fields = [
            ["Magic",                   WORD,],
            ["MajorLinkerVersion",      BYTE,],
            ["MinorLinkerVersion",      BYTE,],
            ["SizeOfCode",              DWORD,],
            ["SizeOfInitializedData",   DWORD,],
            ["SizeOfUninitializedData", DWORD,],
            ["AddressOfEntryPoint",     DWORD,],
            ["BaseOfCode",              DWORD,],
            ["BaseOfData",              DWORD,],
            ["ImageBase",               DWORD,],
            ["SectionAlignment",        DWORD,],
            ["FileAlignment",           DWORD,],
            ["MajorOperatingSystemVersion", WORD,],
            ["MinorOperatingSystemVersion", WORD,],
            ["MajorImageVersion",       WORD,],
            ["MinorImageVersion",       WORD,],
            ["MajorSubsystemVersion",   WORD,],
            ["MinorSubsystemVersion",   WORD,],
            ["Win32VersionValue",       DWORD,],
            ["SizeOfImage",             DWORD,],
            ["SizeOfHeaders",           DWORD,],
            ["CheckSum",                DWORD,],
            ["Subsystem",               WORD,],
            ["DllCharacteristics",      WORD,],
            ["SizeOfStackReserve",      DWORD,],
            ["SizeOfStackCommit",       DWORD,],
            ["SizeOfHeapReserve",       DWORD,],
            ["SizeOfHeapCommit",        DWORD,],
            ["LoaderFlags",             DWORD,],
            ["NumberOfRvaAndSizes",     DWORD,],
            ["Data Directory",          IMAGE_DATA_DIRECTORY_Table,],
            ]

    def read(self):
        result = SimpleStruct.read(self)
        NumberOfSections=self.parameters['no_sections']
        self.add_element(result,'Sections',
                         IMAGE_SECTION_HEADER_ARRAY(
            self.buffer[self.calculate_struct_size(result):],
            count=NumberOfSections),
                         )

        return result

class IMAGE_SECTION_HEADER(SimpleStruct):
    """ These are headers describing each section in the file """
    def init(self):
        self.fields=[
            ["Name",                        STRING,dict(length=8),],
            ["PhysicalAddress/VirtualSize", DWORD,],
            ["VirtualAddress",              DWORD,],
            ["SizeOfRawData",               DWORD,],
            ["PointerToRawData",            DWORD,],
            ["PointerToRelocations",        DWORD,],
            ["PointerToLinenumbers",        DWORD,],
            ["NumberOfRelocations",         WORD,],
            ["NumberOfLinenumbers",         WORD,],
            ["Characteristics",             DWORD,],
            ]

class IMAGE_SECTION_HEADER_ARRAY(StructArray):
    target_class=IMAGE_SECTION_HEADER

class IMAGE_DATA_DIRECTORY(SimpleStruct):
    """ The data directory points to the start of each section """
    def init(self):
        self.fields=[
            ["VirtualAddress", DWORD,],
            ["Size", DWORD,],
            ]

class IMAGE_DATA_DIRECTORY_ARRAY(ARRAY):
    target_class=IMAGE_DATA_DIRECTORY

class IMAGE_DATA_DIRECTORY_Table(SimpleStruct):
    """ The IMAGE_DATA_DIRECTORY_Table is an array of directories.

    The position in the array refers to which type of directory it is, so we represent it in a struct.
    """
    def init(self):
        self.fields = [
            [ 'Export Directory',   IMAGE_DATA_DIRECTORY,],
            [ 'Import Directory',   IMAGE_DATA_DIRECTORY,],
            [ 'Resource Directory', IMAGE_DATA_DIRECTORY,],
            [ 'Exception Directory',IMAGE_DATA_DIRECTORY,],
            [ 'Security Directory', IMAGE_DATA_DIRECTORY,],
            [ 'Basereloc Directory',IMAGE_DATA_DIRECTORY,],
            [ 'Debug Directory',    IMAGE_DATA_DIRECTORY,],
            [ 'Copyright Directory',IMAGE_DATA_DIRECTORY,],
            [ 'Global Ptr Directory',IMAGE_DATA_DIRECTORY,],
            [ 'TLS',                IMAGE_DATA_DIRECTORY,{},'Thread Local Storage Directory'],
            [ 'Load Config Directory', IMAGE_DATA_DIRECTORY,],
            [ 'Bound Import Directory', IMAGE_DATA_DIRECTORY,],
            [ 'Entry Address Table Directory', IMAGE_DATA_DIRECTORY,],
            [ 'Unknown',            IMAGE_DATA_DIRECTORY_ARRAY, {'count':3},],
            ]

class RSRCDirectory(SimpleStruct):
    def init(self):
        self.fields = [
            [ "Type", ULONG ],
            ]

    def read(self):
        result = SimpleStruct.read(self)

        offset = ULONG(self.buffer[self.offset:])
        offset.data &= 0x7FFFFFFF
        
        self.add_element(result, "Offset",
                         offset ),

        return result

class RSRCDir_ARRAY(StructArray):
    target_class = RSRCDirectory

    def __getitem__(self,key):
        for i in self:
            if i['Type']==key:
                return i

        raise IndexError("Type %s not found in directory array" % key)
    

class RSRCDataEntry(SimpleStruct):
    """ A Resource Data entry """
    def init(self):
        self.fields = [
            [ "RVA",      ULONG ],
            [ "Size",     ULONG ],
            [ "Codepage", ULONG ],
            [ "Reserved", ULONG ],
            ]

class RSRC(SimpleStruct):
    """ Parses the resource section of the PE executable """
    def init(self):
        self.fields = [
            [ "flags",         ULONG ],
            [ "date",          TIMESTAMP ],
            [ "majver",        WORD ],
            [ "minver",        WORD ],
            [ "num_dir_names", WORD],
            [ "num_dir_ids",   WORD]
            ]

    def read(self):
        result = SimpleStruct.read(self)

        self.add_element(result, "Directories",
                         RSRCDir_ARRAY(self.buffer[self.offset:],
                                         count=result['num_dir_ids'].get_value())
                         )
        return result

class Chunk(SimpleStruct):
    """ Messages are written in chunks of messages from a certain ID to a certain ID """
    def init(self):
        self.fields = [
            [ 'From',    ULONG ],
            [ 'To' ,     ULONG ],
            [ 'Offset' , ULONG],
            ]

class ChunkArray(ARRAY):
    target_class = Chunk

class Message(SimpleStruct):
    """ An individual message is written in UCS16 """
    def init(self):
        self.fields = [
            [ 'Length',  WORD],
            [ 'Unknown', WORD]
            ]

    def read(self):
        result = SimpleStruct.read(self)
        self.add_element(result, 'Message',
                         UCS16_STR(self.buffer[self.offset:],
                                   length=result['Length'].get_value()-4))

        return result

class Messages(SimpleStruct):
    def init(self):
        self.fields = [
            ['Chunks Count', ULONG ],
            ]

    def read(self):
        result = SimpleStruct.read(self)
        self.messages = {}

        a=ChunkArray(self.buffer[self.offset:],
                     count = result['Chunks Count'].get_value())

        for chunk in a:
            data = self.buffer[chunk['Offset'].get_value():]
            for i in range(chunk['From'].get_value(),
                           chunk['To'].get_value()):
                m=Message(data)
                self.messages[i] = m
                data = data[m.size():]

        return result

    def __str__(self):
        result = []
        for k,v in self.messages.items():
            result.append( "%X - %s" % (k,v['Message']))

        return '\r\n'.join(result)
    
def get_messages(buffer):
    """ opens the PE executable in buffer and returns a Messages object containing all the event log messages within it. If there are no messages, raise an IndexError.
    """
    header = IMAGE_DOS_HEADER(buffer)
    
    optional_header = header['e_lfanew'].get_value()['OptionalHeader']
    for s in optional_header['Sections']:
        if s['Name']=='.rsrc\0\0\0':
            section_offset=s['PointerToRawData'].get_value() 
            r = RSRC(buffer[section_offset:])

            ## First level is resource type - we need RT_MESSAGE
            e = r['Directories'][11]
            r = RSRC(buffer[e['Offset'].get_value()+section_offset:])

            ## Second level is name
            e = r['Directories'][1]
            r = RSRC(buffer[e['Offset'].get_value()+section_offset:])

            ## Third level is language - we need english
            e = r['Directories'][0x0409]
            r = RSRCDataEntry(buffer[e['Offset'].get_value()+section_offset:])

            ## Now r points into the message array:
            offset = (r['RVA'].get_value()
                      - s['VirtualAddress'].get_value() + section_offset)

            m = Messages(buffer.set_offset(offset))

            return m
            
if __name__ == "__main__":
    fd=open(sys.argv[1],'r')

    buffer = Buffer(fd=fd)
    print get_messages(buffer)
