# ******************************************************
# Copyright 2006: Commonwealth of Australia.
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
""" A library for handling IE History index.dat files

Supports IE versions from IE 5 onwards.
"""
import format,sys
from format import *
from plugins.FileFormats.BasicFormats import *

class Header(SimpleStruct):
    def init(self):
        self.fields = [
            [ 'Magic', STRING, {"length":0x1c}  ],
            [ 'file_size', LONG],
            [ 'hash_offset', LONG],
            [ 'unknown', WORD_ARRAY,{'count':7}],
            [ 'blocksize', LONG],
            ]
    
## The default blocksize
blocksize=0x80

class Hash(LONG_ARRAY):
    """ A data structure representing the index list in the history file.

    The hash section represents the offsets to all the url blocks in the file.
    We collect all of these and return a list of all offsets in all hash sections.
    Note that the hash section may point at more hash sections, which  we automatically traverse all sections, so callers do not need to worry about looking for more hash sections.
    """
    def read(self):
        data = []
        magic=STRING(self.buffer,length=4)
        # Check the magic for this section
        if magic!='HASH':
            raise IOError("Location %s is not a hash array - This file may be empty!!"%(data.offset))
        
        section_length = LONG(self.buffer[4:]).get_value()
        self.next_hash_offset = LONG(self.buffer[8:]).get_value()
        offset=16
        while offset<section_length*blocksize:
            record_type=LONG(self.buffer[offset:]).get_value()
            if record_type!=0x3:
                off = LONG(self.buffer[offset+4:]).get_value()
                ## If the offsets are nonsensical we dont add them (i.e. point at 0xBADF00D are null)
                if off!=0 and off!=0xBADF00D:
                    if off not in data:
                        data.append(off)
                    
            ## Go to the next offset in the list
            offset+=8
                
        return data

class PHASH(POINTER):
    target_class = Hash

class URLEntry(SimpleStruct):
    """ URL records are stored here """
    def init(self):
        self.fields = [
            [ 'type', STRING, {'length':4},],
            [ 'size', LONG ], #In multiples of the blocksize
            [ 'modified_time', WIN_FILETIME ],
            [ 'accessed_time', WIN_FILETIME ],
            [ 'unknown', LONG_ARRAY, {'count':0x7} ],
            [ 'url', HIST_STR_PTR, dict(section_offset=self.buffer.offset)],
            [ 'unknown', BYTE ],
            [ 'directory_index', BYTE ],
            [ 'unknown', WORD ],
            [ 'filename', HIST_STR_PTR, dict(section_offset=self.buffer.offset)],
            [ '0x00200001', LONG ],
            [ 'content', PContent ],
            ] 

class HIST_STR_PTR(LONG):
    """ This is a pointer to a string relative to the start of the section """
    def __init__(self,buffer,*args,**kwargs):
        self.section_offset = kwargs['section_offset']
        LONG.__init__(self,buffer,args,kwargs)
        
    def read(self):
        ## These offsets are all relative to the start of the URL
        ## section, we find its absolute offset here
        offset=LONG.read(self)

        ## set our absolute offset to the start of our section
        data=self.buffer.set_offset(self.section_offset)

        ## Return the null terminated string:
        return TERMINATED_STRING(data[offset:])

    def __str__(self):
        result="%s" % (self.data,)
        return result.split('\0',1)[0]

class Content(SimpleStruct):
    """ The Data contained within the record.

    This is HTTP headers sometimes, but usually its the title of the page.
    We can tell which one it is by looking at the content_type.
    """
    def init(self):
        self.fields=[
            [ 'Magic', LONG ], #Always seems to be 0x0020010
            [ 'pad', LONG_ARRAY,{'count':3},],
            [ 'length', WORD ],
            [ 'content_type', ContentType ]
            ]

    def read(self):
        magic = LONG(self.buffer)
        ## The magic refers to a special structure if its there,
        ## otherwise its just a null terminated string:
        if magic!=0x0020010:
            result={}
            self.add_element(result,'data',TERMINATED_STRING(self.buffer[4:]))
            result['content_type']=ContentType("\xff\xff",1)
            return result

        result=SimpleStruct.read(self)
        length=result['length'].get_value()
        if length:
            ## Sometimes this is unicode, sometimes not depending on the type
            if result['content_type']=="Title":
                data=UCS16_STR(data[20:],{'length':length})
            else:
                data=STRING(data[20:],{'length':length})
        else:
            data=STRING('',{'length':0})

        self.add_element(result,data,'data')

        return result

class ContentType(WORD_ENUM):
    """ These are the different types available in the Content struct """
    types={
        0x0000: "No Data",
        0x1F10: "Title",
        0x1E0E: "ClsID",
        ## Private types - not seen in the wild:
        0xffff: "Header",
        }

class PContent(POINTER):
    """ The URLEntry points to the Content structure """
#    target_class=TERMINATED_STRING
    target_class=Content

class IEHistoryFile:
    """ A Class to access the records in an IE History index.dat file.

    Use like this:
    for record in IEHistoryFile(fd):
        print record

    record is a dict of properties and values. Note that values are data type classes.

    @arg fd: A File like object for the history file
    """
    def __init__(self,fd):
        self.buffer=Buffer(fd=fd)
        self.header=Header(self.buffer)
        
        magic=self.header['Magic']
        if magic != "Client UrlCache MMF Ver 5.2\x00":
            raise IOError("File is not supported, we only support MMF Ver 5.2, this magic is %r" % magic.get_value())
        
        hash_offset = self.header['hash_offset'].get_value()
        self.hashes = []
        
        while hash_offset > 0:
            h=Hash(self.buffer[hash_offset:],1)
            self.hashes.extend(h.data)
            hash_offset = h.next_hash_offset

    def __iter__(self):
        self.hash_iter=self.hashes.__iter__()
        return self

    def next(self):
        result={}

        ## Chase all offsets to only include those in the file
        while 1:
            try:
                offset=self.hash_iter.next()
                entry_type = STRING(self.buffer.set_offset(offset),length=4).__str__()
            except IOError:
                continue

            break
            
        if entry_type == 'URL ':
            entry=URLEntry(self.buffer[offset:])
            result['event']=entry
            for key in ('type','modified_time','accessed_time','url','filename'):
                result[key]=entry[key]

            c=entry['content'].get_value()
            result['data']=c
            for key in ('content_type','data'):
                result[key]=c[key]
                
            return result
        
        return None

if __name__ == "__main__":
    fd=open(sys.argv[1],'r')
    import time,sys
    
    a=time.time()
    
    history=IEHistoryFile(fd)
    for event in history:
        if event:
#            print event['event']
#            r=["%s=%r" % (k,"%s"%v) for k,v in event.items() if k!='event' ]
#            print '\n'.join(r)

            print "url is %s" % event['event']

    sys.stderr.write("Completed in %s seconds\n" % (time.time()-a))
