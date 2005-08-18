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
#  Version: FLAG $Version: 0.78 Date: Fri Aug 19 00:47:14 EST 2005$
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
import sys

class IMAGE_DOS_HEADER(SimpleStruct):
    """ The simple Dos header at the begining of the file """
    def init(self):
        self.fields = [
            [ STRING,2,"e_magic","Magic number", ],
            [ WORD,1,"e_cblp","Bytes on last page of file",],
            [ WORD,1,"e_cp","Pages in file",],
            [ WORD,1,"e_crlc","Relocations",],
            [ WORD,1,"e_cparhdr","Size of header in paragraphs",],
            [ WORD,1,"e_minalloc","Minimum extra paragraphs needed",],
            [ WORD,1,"e_maxalloc","Maximum extra paragraphs needed",],
            [ WORD,1,"e_ss","Initial (relative) SS value",],
            [ WORD,1,"e_sp","Initial SP value",],
            [ WORD,1,"e_csum","Checksum",],
            [ WORD,1,"e_ip","Initial IP value",],
            [ WORD,1,"e_cs","Initial (relative) CS value",],
            [ WORD,1,"e_lfarlc","File address of relocation table",],
            [ WORD,1,"e_ovno","Overlay number",],
            [ WORD_ARRAY,4,"e_res","Reserved words",],
            [ WORD,1,"e_oemid","OEM identifier (for e_oeminfo)",],
            [ WORD,1,"e_oeminfo","OEM information- e_oemid specific",],
            [ WORD_ARRAY,10,"e_res2","Reserved words",],
            [ P_IMAGE_FILE_HEADER,1,"e_lfanew","File address of new exe header",],
            ]

    def read(self,data):
        result=SimpleStruct.read(self,data)
        if result['e_magic']!='MZ':
            raise IOError("File does not appear to have the right magic (MZ)")

        return result

class IMAGE_FILE_HEADER(SimpleStruct):
    """ The PE header pointed to by the Dos header """
    def init(self):
        self.fields = [
            [ STRING,4,"e_magic","Magic",],
            [ WORD,1, "Machine"],
            [ WORD,1, "NumberOfSections"],
            [ TIMESTAMP,1,"TimeDateStamp"],
            [ DWORD ,1,"PointerToSymbolTable"],
            [ DWORD,1, "NumberOfSymbols"],
            [ WORD,1, "SizeOfOptionalHeader"],
            [ WORD,1, "Characteristics"],
            [ IMAGE_OPTIONAL_HEADER,1,"OptionalHeader"],
            ]

    def read(self,data):
        result=SimpleStruct.read(self,data)
        if result['e_magic']!='PE\x00\x00':
            raise IOError("File does not appear to be a PE executable, magic is not correct (PE %s)" % result['e_magic'] )

        return result
        
class P_IMAGE_FILE_HEADER(POINTER):
    target_class = IMAGE_FILE_HEADER

class IMAGE_OPTIONAL_HEADER(SimpleStruct):
    """ An optional header pointed to by the PE header.

    This is not really optional at all - I guess its called optional in a cynical manner, just as the P in PE executable stands for Portable (can you even use the word portable and windows in the same sentence?).
    """
    def init(self):
        self.fields = [
            [WORD,1,"Magic"],
            [BYTE,1,"MajorLinkerVersion"],
            [BYTE,1,"MinorLinkerVersion"],
            [DWORD,1,"SizeOfCode"],
            [DWORD,1,"SizeOfInitializedData"],
            [DWORD,1,"SizeOfUninitializedData"],
            [DWORD,1,"AddressOfEntryPoint"],
            [DWORD,1,"BaseOfCode"],
            [DWORD,1,"BaseOfData"],
            [DWORD,1,"ImageBase"],
            [DWORD,1,"SectionAlignment"],
            [DWORD,1,"FileAlignment"],
            [WORD,1,"MajorOperatingSystemVersion"],
            [WORD,1,"MinorOperatingSystemVersion"],
            [WORD,1,"MajorImageVersion"],
            [WORD,1,"MinorImageVersion"],
            [WORD,1,"MajorSubsystemVersion"],
            [WORD,1,"MinorSubsystemVersion"],
            [DWORD,1,"Win32VersionValue"],
            [DWORD,1,"SizeOfImage"],
            [DWORD,1,"SizeOfHeaders"],
            [DWORD,1,"CheckSum"],
            [WORD,1,"Subsystem"],
            [WORD,1,"DllCharacteristics"],
            [DWORD,1,"SizeOfStackReserve"],
            [DWORD,1,"SizeOfStackCommit"],
            [DWORD,1,"SizeOfHeapReserve"],
            [DWORD,1,"SizeOfHeapCommit"],
            [DWORD,1,"LoaderFlags"],
            [DWORD,1,"NumberOfRvaAndSizes"],
            [IMAGE_DATA_DIRECTORY_Table,1,"Data Directory"],
            ]

    def read(self,data):
        result = SimpleStruct.read(self,data)
        NumberOfSections=self.parent['NumberOfSections'].get_value()

        self.add_element(result,
                  IMAGE_SECTION_HEADER_ARRAY(
                    data[self.calculate_struct_size(result):],NumberOfSections),
                  'Sections')

        return result

class IMAGE_SECTION_HEADER(SimpleStruct):
    """ These are headers describing each section in the file """
    def init(self):
        self.fields=[
            [STRING,8,"Name",],
            [DWORD,1,"PhysicalAddress/VirtualSize",],
            [DWORD,1,"VirtualAddress",],
            [DWORD,1,"SizeOfRawData",],
            [DWORD,1,"PointerToRawData",],
            [DWORD,1,"PointerToRelocations",],
            [DWORD,1,"PointerToLinenumbers",],
            [WORD,1,"NumberOfRelocations",],
            [WORD,1,"NumberOfLinenumbers",],
            [DWORD,1,"Characteristics",],
            ]

class IMAGE_DATA_DIRECTORY(SimpleStruct):
    """ The data directory points to the start of each section """
    def init(self):
        self.fields=[
            [DWORD,1,"VirtualAddress",],
            [DWORD,1,"Size",],
            ]

class IMAGE_DATA_DIRECTORY_ARRAY(ARRAY):
    target_class=IMAGE_DATA_DIRECTORY

class IMAGE_DATA_DIRECTORY_Table(SimpleStruct):
    """ The IMAGE_DATA_DIRECTORY_Table is an array of directories.

    The position in the array refers to which type of directory it is, so we represent it in a struct.
    """
    def init(self):
        self.fields = [
            [ IMAGE_DATA_DIRECTORY,1,'Export Directory'],
            [ IMAGE_DATA_DIRECTORY,1,'Import Directory'],
            [ IMAGE_DATA_DIRECTORY,1,'Resource Directory'],
            [ IMAGE_DATA_DIRECTORY,1,'Exception Directory'],
            [ IMAGE_DATA_DIRECTORY,1,'Security Directory'],
            [ IMAGE_DATA_DIRECTORY,1,'Basereloc Directory'],
            [ IMAGE_DATA_DIRECTORY,1,'Debug Directory'],
            [ IMAGE_DATA_DIRECTORY,1,'Copyright Directory'],
            [ IMAGE_DATA_DIRECTORY,1,'Global Ptr Directory'],
            [ IMAGE_DATA_DIRECTORY,1,'TLS','Thread Local Storage Directory'],
            [ IMAGE_DATA_DIRECTORY,1,'Load Config Directory'],
            [ IMAGE_DATA_DIRECTORY,1,'Bound Import Directory'],
            [ IMAGE_DATA_DIRECTORY,1,'Entry Address Table Directory'],
            [ IMAGE_DATA_DIRECTORY_ARRAY,3,'Unknown'],
            ]

class IMAGE_SECTION_HEADER_ARRAY(StructArray):
    target_class=IMAGE_SECTION_HEADER

if __name__ == "__main__":
    fd=open(sys.argv[1],'r')

    buffer = Buffer(fd=fd)
    header = IMAGE_DOS_HEADER(buffer)
    print header
    print header['e_lfanew'].p()

