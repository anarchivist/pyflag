""" This module handles OLE2 files, such as Microsoft office files.

We currently implement support for the following file formats:
outlook .msg files - These get extracted into the normal vfs - we also collect stats on the file
MS Office - We collect metadata in a special report.

Generic OLE VFS - The contents of the OLE file is make available through the VFS
"""
from libole2 import OLEFile
from format import *
import sys,re

prop_lookup = {
    '001A': 'Message class',
    '0037': 'Subject',
    '003D': 'Subject prefix',
    '0040': 'Received by name',
    '0042': 'Sent repr name',
    '0044': 'Rcvd repr name',
    '004D': 'Org author name',
    '0050': 'Reply rcipnt names',
    '005A': 'Org sender name',
    '0064': 'Sent repr adrtype',
    '0065': 'Sent repr email',
    '0070': 'Topic',
    '0075': 'Rcvd by adrtype',
    '0076': 'Rcvd by email',
    '0077': 'Repr adrtype',
    '0078': 'Repr email',
    '007d': 'Message header',
    '0C1A': 'Sender name',
    '0C1E': 'Sender adr type',
    '0C1F': 'Sender email',
    '0E02': 'Display BCC',
    '0E03': 'Display CC',
    '0E04': 'Display To',
    '0E1D': 'Subject (normalized)',
    '0E28': 'Recvd account1(?)',
    '0E29': 'Recvd account2(?)',
    '1000': 'Message body',
    '1008': 'RTF sync body tag',
    '1035': 'Message ID (?)',
    '1046': 'Sender email(?)',
    '3001': 'Display name',
    '3002': 'Address type',
    '3003': 'Email address',
    '39FE': '7-bit email (?)',
    '39FF': '7-bit display name',
    '3701': 'Attachment data',
    '3703': 'Attach extension',
    '3704': 'Attach filename',
    '3707': 'Attach long filenm',
    '370E': 'Attach mime tag',
    '3712': 'Attach ID (?)',
    '3A00': 'Account',
    '3A02': 'Callback phone no',
    '3A05': 'Generation',
    '3A06': 'Given name',
    '3A08': 'Business phone',
    '3A09': 'Home phone',
    '3A0A': 'Initials',
    '3A0B': 'Keyword',
    '3A0C': 'Language',
    '3A0D': 'Location',
    '3A11': 'Surname',
    '3A15': 'Postal address',
    '3A16': 'Company name',
    '3A17': 'Title',
    '3A18': 'Department',
    '3A19': 'Office location',
    '3A1A': 'Primary phone',
    '3A1B': 'Business phone 2',
    '3A1C': 'Mobile phone',
    '3A1D': 'Radio phone no',
    '3A1E': 'Car phone no',
    '3A1F': 'Other phone',
    '3A20': 'Transmit dispname',
    '3A21': 'Pager',
    '3A22': 'User certificate',
    '3A23': 'Primary Fax',
    '3A24': 'Business Fax',
    '3A25': 'Home Fax',
    '3A26': 'Country',
    '3A27': 'Locality',
    '3A28': 'State/Province',
    '3A29': 'Street address',
    '3A2A': 'Postal Code',
    '3A2B': 'Post Office Box',
    '3A2C': 'Telex',
    '3A2D': 'ISDN',
    '3A2E': 'Assistant phone',
    '3A2F': 'Home phone 2',
    '3A30': 'Assistant',
    '3A44': 'Middle name',
    '3A45': 'Dispname prefix',
    '3A46': 'Profession',
    '3A48': 'Spouse name',
    '3A4B': 'TTYTTD radio phone',
    '3A4C': 'FTP site',
    '3A4E': 'Manager name',
    '3A4F': 'Nickname',
    '3A51': 'Business homepage',
    '3A57': 'Company main phone',
    '3A58': 'Childrens names',
    '3A59': 'Home City',
    '3A5A': 'Home Country',
    '3A5B': 'Home Postal Code',
    '3A5C': 'Home State/Provnce',
    '3A5D': 'Home Street',
    '3A5F': 'Other adr City',
    '3A60': 'Other adr Country',
    '3A61': 'Other adr PostCode',
    '3A62': 'Other adr Province',
    '3A63': 'Other adr Street',
    '3A64': 'Other adr PO box',
    '3FF7': 'Server',
    '3FF8': 'Creator1',
    '3FFA': 'Creator2',
    '3FFC': 'To email',
    '403D': 'To adrtype',
    '403E': 'To email',
    '5FF6': 'To',
    }

def mesg_property(p,file):
    name = p['pps_rawname'].__str__()
    m = re.match('__substg1.0_(....)(....)',name)
    prop_id = m.group(1)
    type=m.group(2)
    
    try:
        property_name=prop_lookup[prop_id]
    except:
        return
        property_name="Unknown property ID %s" % prop_id
        
    data=file.cat(p)
    print "%s: %s" % (property_name,data)

def mesg_attach(p,file):
    pass

def mesg_receipt(p,file):
    pass

class FIDAndOffset(SimpleStruct):
    def init(self):
        self.fields=[
            [ CLSID,1,'FID'],
            [ LONG,1,'offset']
            ]

class FIDAndOffsetArray(ARRAY):
    target_class=FIDAndOffset

class PropHeader(SimpleStruct):
    def init(self):
        self.fields=[
            [ WORD,1,'byteOrder'],
            [ WORD,1,'Format'],
            [ WORD,1,'OSVersion1'],
            [ WORD,1,'OSVersion2'],
            [ CLSID,1,'ClassID'],
            [ LONG,1,'cSections'],
        ]

class DataSize(SimpleStruct):
    def init(self):
        self.fields=[
            [ LONG,1,'cBytes'],
            [ LONG,1,'cProps'],
            ]

class PropDataType(LONG_ENUM):
    """ These are the possible data types in properties """
    types = {
        0x03: LONG,
        0x1e: LPSTR,
        0x40: WIN_FILETIME,
        }

class PropType(LONG_ENUM):
    """ These are some of the properties that we know about.
    
    This list is not exhaustive.
    """
    types = {
        0x02:'PID_TITLE',
        0x03:'PID_SUBJECT',
        0x04:'PID_AUTHOR',
        0x05:'PID_KEYWORDS',
        0x06:'PID_COMMENTS',
        0x07:'PID_TEMPLATE',
        0x08:'PID_LASTAUTHOR',
        0x09:'PID_REVNUMBER',
        0x12:'PID_APPNAME',
        0x0A:'PID_TOTAL_EDITTIME',
        0x0B:'PID_LASTPRINTED',
        0x0C:'PID_CREATED',
        0x0D:'PID_LASTSAVED',
        0x0E:'PID_PAGECOUNT',
        0x0F:'PID_WORDCOUNT',
        0x10:'PID_CHARCOUNT',
        0x13:'PID_SECURITY',
        0x11:'PID_THUMBNAIL'
        }

class Property(SimpleStruct):
    def init(self):
        self.fields=[
            [ PropType,1,'Type'],
            [ LONG,1,'Offset'], #This is relative to the section
            ]

class PropArray(ARRAY):
    target_class=Property

def parse_summary_info(p,file):
#    print p
    ## Get the property stream
    data = file.cat(p)
    header = PropHeader(data)
    
    #print header
    ## A FIDAndOffsetArray tells us where all the property sections are
    fids = FIDAndOffsetArray(data[header.size():],header['cSections'])

    for fid in fids:
        offset=fid['offset'].get_value()
        ## Lets grab each section:
        section_data = data[offset:]
        section=DataSize(section_data)

        ## Now we know how many properties there are
        props = PropArray(section_data[section.size():],
                          section['cProps'].get_value())
        
        #print section

        ## Lets grab each property
        for prop in props:
            offset=prop['Offset'].get_value()
            ## This is an enum based on a long - This looks up the
            ## right type based on the value in the long
            value = PropDataType(section_data[offset:])
            cls=value.get_value()
            try:
                ## We recognise this data type - Lets get it
                if issubclass(cls,DataType):
                    value=cls(section_data[offset+value.size():])
                    ## Print the data according to its data type
                    print "%s: %s" % (prop['Type'],value)
            except TypeError,e:
                #print "Cant handle property type %s for %s" % (cls,prop['Type'])
                pass


dispatch = {
    "__substg1.0": mesg_property,
    "__attach_version1.0":mesg_attach,
    "__recip_version1.0":mesg_receipt,
    "SummaryInformation":parse_summary_info,
    }

if __name__ == "__main__":
    fd=open(sys.argv[1],'r')
    data=fd.read()
    fd.close()

    a=OLEFile(data)
    for p in a.properties:
        for i in dispatch.keys():
            if re.search(i,p['pps_rawname'].get_value()):
                dispatch[i](p,a)
