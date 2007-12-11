# ******************************************************
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.84RC5 Date: Wed Dec 12 00:45:27 HKT 2007$
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
""" A library for reading PST files.

PST files are created by outlook. This is an example of one of the
most complex and stupid file formats on the planet. It is a nice
example of how the file format library can be used to parse such a
monstrosity.

The following relies very heavily on libpst and in particular the
great work in the document:

http://www.five-ten-sg.com/libpst/rn01re04.html
"""
from format import *
from plugins.FileFormats.BasicFormats import *
import sys
import LZFU

class IndexTypeEnum(BYTE_ENUM):
    types = {
        0x0e: "Standard",
        }

class Index1NodePointer(SimpleStruct):
    fields = [
        [ 'ID', ULONG ],
        [ 'backpointer', ULONG],
        [ 'Offset', ULONG],
        ]

    def size(self):
        return 12

    def read(self):
        result = SimpleStruct.read(self)

        ## Resolve the Node:
        self.buffer.offset= int(result['Offset'])
        node = Index1Node(self.buffer, **self.parameters)

        self.add_element(result, "Node", node)

        return result

class Index1DataPointer(SimpleStruct):
    fields = [
        [ 'ID1', ULONG ],
        [ 'Offset' , ULONG],
        [ 'Size',   USHORT],
        [ 'Unknown', USHORT],
        ]

    def read(self):
        result = SimpleStruct.read(self)
        self.parameters['list'][int(result['ID1'])] = self

        return result

class Index1DataPointerArray(StructArray):
    target_class = Index1DataPointer

class Index2NodePointer(Index1NodePointer):
    def read(self):
        result = SimpleStruct.read(self)

        ## Resolve the Node:
        self.buffer.offset= int(result['Offset'])
        node = Index2Node(self.buffer, **self.parameters)

        self.add_element(result, "Node", node)

        return result

class Index2DataPointer(SimpleStruct):
    fields = [
        [ 'ID2', ULONG ],
        [ 'DESC-ID1' , ULONG],
        [ 'LIST-ID1',   USHORT],
        [ 'Parent ID2', USHORT],
        ]

    def read(self):
        result = SimpleStruct.read(self)
        self.parameters['list'][int(result['ID2'])] = self

        return result

class Index2DataPointerArray(StructArray):
    target_class = Index2DataPointer

class Index1Node(SimpleStruct):
    fields = [
        [ "ItemCount", UBYTE, dict(offset=0x1f0) ],
        [ "MaxItemCount", UBYTE, dict(offset=0x1f1) ],
        [ "NodeLevel", UBYTE, dict(offset=0x1f3)],
        [ "backPointer", ULONG, dict(offset=0x1f8)],
        ]

    def read(self):
        result = SimpleStruct.read(self)

        if result['NodeLevel'].get_value():
            ## We have a list of children here:
            children = Index1NodeChildren(None)
            offset = 0
            for x in range(result['ItemCount'].get_value()):
                c = Index1NodePointer( self.buffer[offset:], **self.parameters)
                offset += c.size()
                children.extend(c)

            self.add_element(result, "Children", children)
        else:
            data = Index1DataPointerArray(self.buffer, count=int(result['ItemCount']),
                                          list=self.parameters['list'])
            self.add_element(result, "Data", data)
            
        return result

class Index1NodeChildren(StructArray):
    target_class = Index1Node

class Index2NodeChildren(StructArray):
    target_class = Index1Node

class Index2Node(SimpleStruct):
    fields = [
        [ "ItemCount", UBYTE, dict(offset=0x1f0) ],
        [ "MaxItemCount", UBYTE, dict(offset=0x1f1) ],
        [ "NodeLevel", UBYTE, dict(offset=0x1f3)],
        [ "backPointer", ULONG, dict(offset=0x1f8)],
        ]

    def read(self):
        result = SimpleStruct.read(self)

        if result['NodeLevel'].get_value():
            ## We have a list of children here:
            children = Index2NodeChildren(None)
            offset = 0
            for x in range(result['ItemCount'].get_value()):
                c = Index2NodePointer( self.buffer[offset:], **self.parameters)
                offset += c.size()
                children.extend(c)

            self.add_element(result, "Children", children)
        else:
            data = Index2DataPointerArray(self.buffer, count=int(result['ItemCount']),
                                          list=self.parameters['list'])
            self.add_element(result, "Data", data)
            
        return result

class DescriptorIndex(SimpleStruct):
    fields = [
        [ 'signature', USHORT ],
        [ 'unknown' , USHORT ],
        [ 'offset' , ULONG ],
        ]

class ReferenceType(WORD_ENUM):
    types = {
        0x0002 : "Signed 16bit value",
        0x0003 : "Signed 32bit value",
        0x0004 : "4-byte floating point",
        0x0005 : "Floating point double",
        0x0006 : "Signed 64-bit int",
        0x0007 : "Application Time",
        0x000A : "32-bit error value",
        0x000B : "Boolean (non-zero = true)",
        0x000D : "Embedded Object",
        0x0014 : "8-byte signed integer (64-bit)",
        0x001E : "Null terminated String",
        0x001F : "Unicode string",
        0x0040 : "Systime - Filetime structure",
        0x0048 : "OLE Guid",
        0x0102 : "Binary data",
        0x1003 : "Array of 32bit values",
        0x1014 : "Array of 64bit values",
        0x101E : "Array of Strings",
        0x1102 : "Array of Binary data",
        }

class FieldType(WORD_ENUM):
    types = {
         0x0002: "AutoForward allowed",
         0x0003: "Extended Attributes Table",
         0x0017: "Importance Level",
         0x001a: "IPM Context. What type of message is this",
         0x0023: "Global Delivery Report",
         0x0026: "Priority",
         0x0029: "Read Receipt",
         0x002b: "Reassignment Prohibited",
         0x002e: "Original Sensitivity",
         0x0036: "Sensitivity",
         0x0037: "Email Subject. The referenced item is of type Subject Type",
         0x0039: "Date. This is likely to be the arrival date",
         0x003b: "Outlook Address of Sender",
         0x003f: "Outlook structure describing the recipient",
         0x0040: "Name of the Outlook recipient structure",
         0x0041: "Outlook structure describing the sender",
         0x0042: "Name of the Outlook sender structure",
         0x0043: "Another structure describing the recipient",
         0x0044: "Name of the second recipient structure",
         0x004f: "Reply-To Outlook Structure",
         0x0050: "Name of the Reply-To structure",
         0x0051: "Outlook Name of recipient",
         0x0052: "Second Outlook name of recipient",
         0x0057: "My address in TO field",
         0x0058: "My address in CC field",
         0x0059: "Message addressed to me",
         0x0063: "Response requested",
         0x0064: "Sender's Address access method (SMTP, EX)",
         0x0065: "Sender's Address",
         0x0070: "Processed Subject (with Fwd:, Re, ... removed)",
         0x0071: "Date. Another date",
         0x0075: "Recipient Address Access Method (SMTP, EX)",
         0x0076: "Recipient's Address",
         0x0077: "Second Recipient Access Method (SMTP, EX)",
         0x0078: "Second Recipient Address",
         0x007d: "Email Header. This is the header that was attached to the email",
         0x0c17: "Reply Requested",
         0x0c19: "Second sender struct",
         0x0c1a: "Name of second sender struct",
         0x0c1d: "Second outlook name of sender",
         0x0c1e: "Second sender access method (SMTP, EX)",
         0x0c1f: "Second Sender Address",
         0x0e01: "Delete after submit",
         0x0e03: "CC Address?",
         0x0e04: "SentTo Address",
         0x0e06: "Date.",
         0x0e07: "Flag - contains IsSeen value",
         0x0e08: "Message Size",
         0x0e0a: "Sentmail EntryID",
         0x0e1f: "Compressed RTF in Sync",
         0x0e20: "Attachment Size",
         0x0ff9: "binary record header",
         0x1000: "Plain Text Email Body. Does not exist if the email doesn't have a plain text version",
         0x1006: "RTF Sync Body CRC",
         0x1007: "RTF Sync Body character count",
         0x1008: "RTF Sync body tag",
         0x1009: "RTF Compressed body",
         0x1010: "RTF whitespace prefix count",
         0x1011: "RTF whitespace tailing count",
         0x1013: "HTML Email Body. Does not exist if the email doesn't have a HTML version",
         0x1035: "Message ID",
         0x1042: "In-Reply-To or Parent's Message ID",
         0x1046: "Return Path",
         0x3001: "Folder Name? I have seen this value used for the contacts record aswell",
         0x3002: "Address Type",
         0x3003: "Contact Address",
         0x3004: "Comment",
         0x3007: "Date item creation",
         0x3008: "Date item modification",
         0x300b: "binary record header",
         0x35df: "Valid Folder Mask",
         0x35e0: "binary record found in first item. Contains the reference to 'Top of Personal Folder' item",
         0x35e3: "binary record with a reference to 'Deleted Items' item",
         0x35e7: "binary record with a refernece to 'Search Root' item",
         0x3602: "the number of emails stored in a folder",
         0x3603: "the number of unread emails in a folder",
         0x360a: "Has Subfolders",
         0x3613: "the folder content description",
         0x3617: "Associate Content count",
         0x3701: "Binary Data attachment",
         0x3704: "Attachment Filename",
         0x3705: "Attachement method",
         0x3707: "Attachment Filename long",
         0x370b: "Attachment Position",
         0x370e: "Attachment mime encoding",
         0x3710: "Attachment Mime Sequence",
         0x3a00: "Contact's Account name",
         0x3a01: "Contact Alternate Recipient",
         0x3a02: "Callback telephone number",
         0x3a03: "Message Conversion Prohibited",
         0x3a05: "Contacts Suffix",
         0x3a06: "Contacts First Name",
         0x3a07: "Contacts Government ID Number",
         0x3a08: "Business Telephone Number",
         0x3a09: "Home Telephone Number",
         0x3a0a: "Contacts Initials",
         0x3a0b: "Keyword",
         0x3a0c: "Contact's Language",
         0x3a0d: "Contact's Location",
         0x3a0e: "Mail Permission",
         0x3a0f: "MHS Common Name",
         0x3a10: "Organizational ID #",
         0x3a11: "Contacts Surname",
         0x3a12: "original entry id",
         0x3a13: "original display name",
         0x3a14: "original search key",
         0x3a15: "Default Postal Address",
         0x3a16: "Company Name",
         0x3a17: "Job Title",
         0x3a18: "Department Name",
         0x3a19: "Office Location",
         0x3a1a: "Primary Telephone",
         0x3a1b: "Business Phone Number 2",
         0x3a1c: "Mobile Phone Number",
         0x3a1d: "Radio Phone Number",
         0x3a1e: "Car Phone Number",
         0x3a1f: "Other Phone Number",
         0x3a20: "Transmittable Display Name",
         0x3a21: "Pager Phone Number",
         0x3a22: "user certificate",
         0x3a23: "Primary Fax Number",
         0x3a24: "Business Fax Number",
         0x3a25: "Home Fax Number",
         0x3a26: "Business Address Country",
         0x3a27: "Business Address City",
         0x3a28: "Business Address State",
         0x3a29: "Business Address Street",
         0x3a2a: "Business Postal Code",
         0x3a2b: "Business PO Box",
         0x3a2c: "Telex Number",
         0x3a2d: "ISDN Number",
         0x3a2e: "Assistant Phone Number",
         0x3a2f: "Home Phone 2",
         0x3a30: "Assistant's Name",
         0x3a40: "Can receive Rich Text",
         0x3a41: "Wedding Anniversary",
         0x3a42: "Birthday",
         0x3a43: "Hobbies",
         0x3a44: "Middle Name",
         0x3a45: "Display Name Prefix (Title)",
         0x3a46: "Profession",
         0x3a47: "Preferred By Name",
         0x3a48: "Spouse's Name",
         0x3a49: "Computer Network Name",
         0x3a4a: "Customer ID",
         0x3a4b: "TTY/TDD Phone",
         0x3a4c: "Ftp Site",
         0x3a4d: "Gender",
         0x3a4e: "Manager's Name",
         0x3a4f: "Nickname",
         0x3a50: "Personal Home Page",
         0x3a51: "Business Home Page",
         0x3a57: "Company Main Phone",
         0x3a58: "childrens names",
         0x3a59: "Home Address City",
         0x3a5a: "Home Address Country",
         0x3a5b: "Home Address Postal Code",
         0x3a5c: "Home Address State or Province",
         0x3a5d: "Home Address Street",
         0x3a5e: "Home Address Post Office Box",
         0x3a5f: "Other Address City",
         0x3a60: "Other Address Country",
         0x3a61: "Other Address Postal Code",
         0x3a62: "Other Address State",
         0x3a63: "Other Address Street",
         0x3a64: "Other Address Post Office box",
         0x65e3: "Entry ID",
         0x67f2: "Attachment ID2 value",
         0x67ff: "Password checksum [0x67FF]",
         0x6f02: "Secure HTML Body",
         0x6f04: "Secure Text Body",
         0x7c07: "Top of folders RecID [0x7c07]",
         0x8000: "Contain extra bits of information that have been taken from the email's header. I call them extra lines",
         0x8005: "Contact Fullname",
         0x801a: "Home Address",
         0x801b: "Business Address",
         0x801c: "Other Address",
         0x8082: "Email Address 1 Transport",
         0x8083: "Email Address 1 Address",
         0x8084: "Email Address 1 Description",
         0x8085: "Email Address 1 Record",
         0x8092: "Email Address 2 Transport",
         0x8093: "Email Address 2 Address",
         0x8094: "DEBUG_EMAIL ((Email Address 2 Description",
         0x8095: "Email Address 2 Record",
         0x80a2: "DEBUG_EMAIL ((Email Address 3 Transport",
         0x80a3: "Email Address 3 Address",
         0x80a4: "Email Address 3 Description",
         0x80a5: "Email Address 3 Record",
         0x80d8: "Internet Free/Busy",
         0x8205: "Appointment shows as",
         0x8208: "Appointment Location",
         0x8214: "Label for appointment",
         0x8234: "TimeZone of times",
         0x8235: "Appointment Start Time",
         0x8236: "Appointment End Time",
         0x8516: "Duplicate Time Start",
         0x8517: "Duplicate Time End",
         0x8530: "Followup String",
         0x8534: "Mileage",
         0x8535: "Billing Information",
         0x8554: "Outlook Version",
         0x8560: "Appointment Reminder Time",
         0x8700: "Journal Entry Type",
         0x8706: "Start Timestamp",
         0x8708: "End Timestamp",
         0x8712: "Journal Entry Type",
        }

class Field(SimpleStruct):
    fields = [
        [ 'itemType', FieldType ],
        [ 'ReferenceType', ReferenceType ],
        [ 'value', ULONG ],
        ]

    def resolve_index_offset(self,offset):
        tmp= (int(offset)>>4) / 2
        return int(self.index[tmp]) ,int(self.index[tmp + 1])

    def size(self):
        return 8

    def resolve_value(self, item_type, reference_type, value):
        try:
            if item_type==0x1009:
                offset, end_offset = self.resolve_index_offset(value)
                ## Decompress the rtf:
                lzfu = LZFU.LZFUHeader(self.obuffer[offset:end_offset])
                value = lzfu['data']
            elif reference_type==0x1E:
                offset, end_offset = self.resolve_index_offset(value)
                value = TERMINATED_STRING(self.obuffer[offset:end_offset])
            elif reference_type==0x102:
                offset, end_offset = self.resolve_index_offset(value)
                value = STRING(self.obuffer[offset:end_offset], length=end_offset-offset-1)
            elif reference_type==0x40:
                offset, end_offset = self.resolve_index_offset(value)
                value = WIN_FILETIME(self.obuffer[offset:end_offset])
        except KeyError:
            print "index %s for reference type 0x%X not found %s" % (value, reference_type, self.index)

        return value
        
    def read(self):        
        result = SimpleStruct.read(self)

        self.index = self.parameters['index']

        ## We now refer to absolute offsets:
        self.obuffer = self.parameters['obuffer']

        reference_type = int(result['ReferenceType'])
        item_type = int(result['itemType'])

        ## Correct the value if needed
        result['value'] = self.resolve_value(item_type, reference_type, result['value'])

        return result

class FieldArray(ARRAY):
    target_class = Field
    
class DescriptorItemBCEC(SimpleStruct):
    fields = [
        [ 'indexOffset', USHORT ],
        [ 'signature' , USHORT_CONSTANT, dict(expected=0xbcec) ],
        [ 'offset', USHORT],
        
        ## This is the total number of items available it is stored at
        ## the index offset. This is an example of using a callable as
        ## a parameter to reference back into another field:
        [ 'count' , USHORT, dict(offset = lambda x: int(x['indexOffset']))],
        [ 'index' , WORD_ARRAY, dict(offset = lambda x: int(x['indexOffset'])+2,
                                     count = lambda x: int(x['count'])+2) ],
        ]

    def resolve_index_offset(self,offset):
        tmp= (int(offset)>>4) / 2
        return int(self.index[tmp]) ,int(self.index[tmp + 1])

    def read(self):
        result = SimpleStruct.read(self)
        self.index = result['index']

        ## This is the offset of the index:
        offset, end_offset = self.resolve_index_offset(result['offset'])

        ## Obtain the index:
        idx = DescriptorIndex(self.buffer[offset:end_offset])

        ## how large is the index and where is it?
        offset, end_offset = self.resolve_index_offset(idx['offset'])

        ## Now get all items:
        fields = FieldArray(self.buffer[offset: end_offset], count= (end_offset - offset) / 8,
                            index=self.index, obuffer=self.buffer)
        print fields

        return result


class IND2Entry(Field):
    fields = [
        [ 'ReferenceType', ReferenceType ],
        [ 'itemType' , FieldType ],
        [ 'ind2Offset', USHORT],
        [ 'unknown', USHORT],
        ]

    def size(self):
        return 12

    def read(self):
        result = SimpleStruct.read(self)

        self.index = self.parameters['index']
        
        ## We now refer to absolute offsets:
        self.obuffer = self.parameters['obuffer']

        reference_type = int(result['ReferenceType'])
        item_type = int(result['itemType'])

#        value = result['ind2Offset']
        
        try:
            value = self.parameters['index2'][int(result['ind2Offset'])]
        except:
            value = result['ind2Offset']

        ## Correct the value if needed
        self.add_element(result,'value', self.resolve_value(item_type, reference_type, value))

        return result
        

class IND2Table(ARRAY):
    target_class = IND2Entry

class Index2Index7C(SimpleStruct):
    fields = [
        [ 'signature', BYTE_CONSTANT, dict(expected=0x7c) ],
        [ 'item_count', BYTE ],
        [ 'recordSize', USHORT, dict(offset = 8) ],
        [ 'b5Offset', USHORT ],
        [ 'unknown', USHORT],
        [ 'index2Offset', USHORT ],
        ]

class DescriptorItem7CEC(DescriptorItemBCEC):
    fields = [
        [ 'indexOffset', USHORT ],
        [ 'signature' , USHORT_CONSTANT, dict(expected=0x7CEC) ],
        [ 'offset', USHORT],
        
        ## This is the total number of items available it is stored at
        ## the index offset. This is an example of using a callable as
        ## a parameter to reference back into another field:
        [ 'count' , USHORT, dict(offset = lambda x: int(x['indexOffset']))],
        [ 'index' , WORD_ARRAY, dict(offset = lambda x: int(x['indexOffset'])+2,
                                     count = lambda x: int(x['count'])+2) ],
        ]

    def read(self):
        result = SimpleStruct.read(self)
        self.index = result['index']

        ## This is the offset of the index:
        offset, end_offset = self.resolve_index_offset(result['offset'])

        ## Obtain the index:
        idx = Index2Index7C(self.buffer[offset:end_offset])
        print idx

        ## Now find the IND2 offset:
        offset2, end_offset2 = self.resolve_index_offset(idx['index2Offset'])
        index2 = ULONG_ARRAY(self.buffer[offset2:end_offset2], count = (end_offset2 - offset2)/4)
        print index2

        ## Now read the Fields:
        fields = IND2Table(self.buffer[offset + idx.size():end_offset],
                           #count = int(idx['item_count']),
                           count = 2,
                           index = self.index,
                           obuffer = self.buffer,
                           index2 = index2)

        print fields

        return result
        
class PSTHeader(SimpleStruct):
    fields = [
        [ 'Magic',   ULONG ],
        [ 'IndexType', IndexTypeEnum, dict(offset=0xa) ],
        [ 'EncryptionOffset', BYTE, dict(offset=0x1cd) ],
        [ 'Size' , ULONG, dict(offset=0xa8) ],
        [ 'backPointer1', ULONG, dict(offset=0xc0) ],
        [ 'offsetIndex1', ULONG, dict(offset=0xc4)],
        [ 'backPointer2', ULONG, dict(offset=0xb8)],
        [ 'offsetIndex2' , ULONG, dict(offset=0xbc)],        
        ]

    def read(self):
        result = SimpleStruct.read(self)

        self.index1_list = {}
        ## Now try to read the indexes:
        index1 = Index1Node(self.buffer[int(result['offsetIndex1']):], list=self.index1_list)
        self.add_element(result, "Index1", index1)
        
        self.index2_list = {}
        index2 = Index2Node(self.buffer[int(result['offsetIndex2']):], list=self.index2_list)
        self.add_element(result, "Index2", index2)

        return result

    def find_descriptors(self):
        """ Iterates over the indexes to locate the descriptors """
        descriptors = []

        for k,v in pst.index2_list.items():
            print v
            try:
                key = int(v['DESC-ID1'])
                descriptor = pst.index1_list[key]
            except KeyError:
                print "Cant find index 1 for 0x%X" % key
                continue

            print descriptor
            offset = int(descriptor['Offset'])
            length = int(descriptor['Size'])
            cdata = self.buffer[offset:offset+length].__str__()
            data  = ''.join([chr(translation[ord(x)]) for x in cdata ])

            ## Now try to instantiate a Descriptor Item on the
            ## decrypted data:
            try:
                desc = DescriptorItemBCEC(data)
            except RuntimeError,e:
                try:
                    desc = DescriptorItem7CEC(data)
                except RuntimeError, e:
                    print "Unable to process description %s" % e

            print "at offset 0x%X: %s" % (offset,desc )

## With "Compressible Encryption" the pst file is simply obfuscated
## using the following substitution cipher:
translation = [ 0x47, 0xf1, 0xb4, 0xe6, 0x0b, 0x6a, 0x72, 0x48,
                0x85, 0x4e, 0x9e, 0xeb, 0xe2, 0xf8, 0x94, 0x53,
                0xe0, 0xbb, 0xa0, 0x02, 0xe8, 0x5a, 0x09, 0xab,
                0xdb, 0xe3, 0xba, 0xc6, 0x7c, 0xc3, 0x10, 0xdd,
                0x39, 0x05, 0x96, 0x30, 0xf5, 0x37, 0x60, 0x82,
                0x8c, 0xc9, 0x13, 0x4a, 0x6b, 0x1d, 0xf3, 0xfb,
                0x8f, 0x26, 0x97, 0xca, 0x91, 0x17, 0x01, 0xc4,
                0x32, 0x2d, 0x6e, 0x31, 0x95, 0xff, 0xd9, 0x23,
                0xd1, 0x00, 0x5e, 0x79, 0xdc, 0x44, 0x3b, 0x1a,
                0x28, 0xc5, 0x61, 0x57, 0x20, 0x90, 0x3d, 0x83,
                0xb9, 0x43, 0xbe, 0x67, 0xd2, 0x46, 0x42, 0x76,
                0xc0, 0x6d, 0x5b, 0x7e, 0xb2, 0x0f, 0x16, 0x29,
                0x3c, 0xa9, 0x03, 0x54, 0x0d, 0xda, 0x5d, 0xdf,
                0xf6, 0xb7, 0xc7, 0x62, 0xcd, 0x8d, 0x06, 0xd3,
                0x69, 0x5c, 0x86, 0xd6, 0x14, 0xf7, 0xa5, 0x66,
                0x75, 0xac, 0xb1, 0xe9, 0x45, 0x21, 0x70, 0x0c,
                0x87, 0x9f, 0x74, 0xa4, 0x22, 0x4c, 0x6f, 0xbf,
                0x1f, 0x56, 0xaa, 0x2e, 0xb3, 0x78, 0x33, 0x50,
                0xb0, 0xa3, 0x92, 0xbc, 0xcf, 0x19, 0x1c, 0xa7,
                0x63, 0xcb, 0x1e, 0x4d, 0x3e, 0x4b, 0x1b, 0x9b,
                0x4f, 0xe7, 0xf0, 0xee, 0xad, 0x3a, 0xb5, 0x59,
                0x04, 0xea, 0x40, 0x55, 0x25, 0x51, 0xe5, 0x7a,
                0x89, 0x38, 0x68, 0x52, 0x7b, 0xfc, 0x27, 0xae,
                0xd7, 0xbd, 0xfa, 0x07, 0xf4, 0xcc, 0x8e, 0x5f,
                0xef, 0x35, 0x9c, 0x84, 0x2b, 0x15, 0xd5, 0x77,
                0x34, 0x49, 0xb6, 0x12, 0x0a, 0x7f, 0x71, 0x88,
                0xfd, 0x9d, 0x18, 0x41, 0x7d, 0x93, 0xd8, 0x58,
                0x2c, 0xce, 0xfe, 0x24, 0xaf, 0xde, 0xb8, 0x36,
                0xc8, 0xa1, 0x80, 0xa6, 0x99, 0x98, 0xa8, 0x2f,
                0x0e, 0x81, 0x65, 0x73, 0xe4, 0xc2, 0xa2, 0x8a,
                0xd4, 0xe1, 0x11, 0xd0, 0x08, 0x8b, 0x2a, 0xf2,
                0xed, 0x9a, 0x64, 0x3f, 0xc1, 0x6c, 0xf9, 0xec
                ]

if __name__=="__main__":
    fd=open(sys.argv[1],'r')
    b=Buffer(fd=fd)
    data = fd.read()
#    out = ''.join([ chr(translation[ord(x)]) for x in data ])
#    sys.stderr.write(out)
    
    pst = PSTHeader(b)
#    print pst
    pst.find_descriptors()    
