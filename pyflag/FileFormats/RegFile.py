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
#  Version: FLAG $Version: 0.75 Date: Sat Feb 12 14:00:04 EST 2005$
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
""" A Library to read the windows NT/2k/XP registry format.

"""
from format import *
import sys

## This is where the first page starts
FIRST_PAGE_OFFSET=0x1000

class RegF(SimpleStruct):
    def init(self):
        self.fields=[
            [ STRING,4,'Magic'],
            [ LONG_ARRAY,2,'Unknown1'],
            [ WIN_FILETIME,1,'Last Modified'],
            [ LONG_ARRAY,4,'Unknown2'],
            ##Offset is relative to FIRST_PAGE_OFFSET. This offset is
            ##to the root key's nk record.
            [ LONG,1,'root_key_offset'],
            [ LONG,1,'filesize'],
            [ RegFName,0x1fc-0x2c,'Name'],
            [ RegFCheckSum,1,'checksum'],
            ]

class RegFName(STRING):
    """ A string which does not print NULLs """
    def __str__(self):
        result=[c for c in STRING.__str__(self) if c!='\x00' ]
        return ''.join(result)

class RegFCheckSum(STRING):
    def read(self,data):
        cs = ULONG(data).get_value()
        section_offset = self.parent.buffer.offset
        our_offset=self.buffer.offset
        sum=0
        offset=section_offset
        while offset<our_offset:
            data.set_offset(offset)
            byte=ULONG(data)
#            print "0x%X" % (0L + byte.get_value())
            sum+=byte.get_value()
            offset+=byte.size()

        return "given %x calculated %x" % (cs,sum)

class HBin(SimpleStruct):
    def init(self):
        self.fields=[
            [ STRING,4,'Magic'],
            [ LONG,1,'offset_from_1st'], #Offset from the 1st hbin-Block
            [ LONG,1,'size'],
            [ BYTE_ARRAY,14,'unknown1'],
            ## This is ignored as it is unclear what it is... (See ntchpw)
            [ LONG,1,'page_length'],
            ]

class sk_key(SimpleStruct):
    def init(self):
        self.fields=[
            [ WORD,1,'id'],
            [ WORD,1,'pad'],
            [ LONG,1,'offset_prev'], #Offset of previous "sk"-Record
            [ LONG,1,'offset_next'], # To next sk record
            [ LONG,1,'usage_count'],
            [ LONG,1,'size'],
            ]

class nk_key(SimpleStruct):
    def init(self):
        self.fields=[
            [ LONG,1,'size'],
            [ STRING,2,'Magic'],
            [ WORD,1,'Type'],
            [ WIN_FILETIME,1,'WriteTS'],
            [ LONG,1,'parent_offset'],
            [ ULONG,1,'number_of_subkeys'],
            [ BYTE_ARRAY,14,'pad'],
            [ Pri_key,1,'ri_key'],
            [ ULONG,1,'dummy'],
            [ LONG,1,'no_values'],
            [ LONG,1,'offs_value_list'],
            [ LONG,1,'offs_sk'],
            [ LONG,1,'offs_class_name'],
            [ LONG_ARRAY,5,'pad2'],
            [ WORD,1,'len_name'],
            [ WORD,1,'len_classname'],
            ]

class ri_key(SimpleStruct):
    def init(self):
        self.fields = [
            [ LONG,1,'size'],
            [ STRING,2,'id'],
            [ WORD,1,'no_pointers'],
            ]

class Pri_key(POINTER):
    """ This is a pointer to the ri_key struct for a particular nk.

    It is pointing relative to FIRST_PAGE_OFFSET.
    """
    target_class=ri_key
    def calc_offset(self,data,offset):
        data.set_offset(offset+FIRST_PAGE_OFFSET)
        return data

if __name__ == "__main__":
    fd=open(sys.argv[1],'r')
    buffer = Buffer(fd=fd)
    header = RegF(buffer)
    print header

    first_hbin=HBin(buffer[FIRST_PAGE_OFFSET:])
    print first_hbin
    root_key = nk_key(buffer[FIRST_PAGE_OFFSET+header['root_key_offset'].get_value():])
    print root_key,root_key['ri_key'].p()
