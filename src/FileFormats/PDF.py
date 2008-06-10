# ******************************************************
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.87-pre1 Date: Tue Jun 10 13:18:41 EST 2008$
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
""" This is a simple PDF parser.

We currently do not include many types of pdf encodings like LZW,
CCITT etc. We do include zlib support though.
"""

import lexer, zlib, os

class PDFObject:
    """ PDF documents contain objects within them """
    def __init__(self, object_number, generation_number):
        self.object_number = object_number
        self.generation_number = generation_number
        self.contents = []
        self.stream = ''
        self.dictionary = {}
        self.decoded_stream = ''

    def append(self, value):
        self.contents.append(value)
        if type(value) == dict:
            self.dictionary = value
            
    def __str__(self):
        return "Object %s %s, contains: %r, %r" % (self.object_number,
                                                   self.generation_number,
                                                   self.contents,
                                                   self.decoded_stream[:100])

class PDFFile:
    """ A Class representing the PDF File """
    def __init__(self):
        ## The trailer dictionary
        self.trailer = []

        ## The xrefs:
        self.xref = []
        self.xref_offsets = []

        ## The objects in this file:
        self.objects = []

    def __str__(self):
        result = 'Output of PDF file\n'
        result += "Xref Table:\n"
        for i in self.xref:
            result += "%s\n" % (i,)
#            result += "id=%s, group=%s, offset=%s, type=%s\n" % i
        result += "Trailer: %r\n" % self.trailer
        for o in self.objects:
            result += "%s\n" % o

        result += "Xref Offsets: %s\n" % (self.xref_offsets,)
        result += "Xref range: %s\n" % (self.xref_range,)
        return result
        
class PDFParser(lexer.SelfFeederMixIn, lexer.Lexer):
    error = 0
    verbose = 1

    def __init__(self, fd, verbose=0):
        self.tokens = [
            ## Streams are only valid within object declerations (Note
            ## that the standard says that regardless of platform
            ## convensions streams must be followed by exactly \r\n -
            ## otherwise we cant tell if the first char of the stream
            ## is \n or not)
            [ 'OBJECT DECLERATION', '^stream[\r\n]+', 'PUSH_STATE,STREAM_START', None],

            ## For all streams, we read as much as possible until the
            ## end stream token. The order here is important. When we
            ## see an endstream token we finalise the stream.
            [ '.*_STREAM', '[\r\n]*endstream', 'END_STREAM,POP_STATE', None],
            ## Try not to swallow too much data in case the endstream
            ## straddles a feed boundary (We assume we have a minimum
            ## of SECTOR_SIZE lookahead here).
            [ '.*_STREAM', '.{1,200}?(?=[\r\n]*endstream)', 'STREAM', None ],
            [ '.*_STREAM', '.{1,200}', 'STREAM', None ],

            ## Identify comments:
            [ ".", "%%EOF[\r\n]+", "RESET_STATE", 'INITIAL'], 
            [ ".", "%[^\n\r]*", "COMMENT", None ],

            ## End of line terminator:
            [ '.', '(\r|\r\n|\n)$', "EOL", None ],

            ## Detect an object decleration:
            [ 'INITIAL', '^(\d+) (\d+) obj', "save_state,PUSH_STATE,OBJECT_DECLERATION_START", "OBJECT DECLERATION" ],
            [ '.','^endobj',"OBJECT_DECLERATION_END,POP_STATE", None],

            ## This stuff comes from the PDF reference Adobe Chanter 3 - Syntax

            ## This bit parses the xref table:
            [ '.', '^xref', 'PUSH_STATE', 'XREF_HEADER' ],
            [ 'XREF_HEADER', '(\d+) (\d+)', 'XREF_START', 'XREF_DATA'],

            [ '.', '^startxref', 'PUSH_STATE', 'START XREF'],
            [ 'START XREF', '\d+', 'START_XREF,POP_STATE', None],

            ## The xref data is always exactly the same length according
            ## to the standard... We expect to see exactly n entries here
            ## (as declared by the header above), so the XREF_DATA cb will
            ## pop the state when we have seen enough.
            [ 'XREF_DATA' , '(\d{10}) (\d{5}) ([a-zA-Z])', 'XREF_DATA', None ],

            ## Indirect reference:
            [ '.', '(\d+) (\d+) R', "OBJECT_REFERENCE", None],

            ## Boolean
            [ '.', '(true|false)', 'BOOLEAN', None],

            ## Null
            [ '.', 'null', 'NULL', None ],

            ## Strings - there are 2 types:
            ## Literal strings:

            ## The LITERAL_STRING_START cb needs to save the current
            ## state to be restored later. FIXME: () within the string
            ## will confuse us here.
            [ '.', '\(', "PUSH_STATE", 'LITERAL_STRING'],
            [ 'LITERAL_STRING', '^[^\\\()]+', 'LITERAL_STRING', None ],
            [ 'LITERAL_STRING', '^\\\[()]?', 'LITERAL_STRING', None ],
    #        [ 'LITERAL_STRING', r'(\(|\))', 'LITERAL_STRING', None ],
            [ 'LITERAL_STRING', '\)', 'LITERAL_STRING_END,POP_STATE', None],

            ## Hexadecimal strings:
            [ '.', "<(([0-9A-Fa-f]|\s)+)>", 'HEX_STRING', None],

            ## Numbers - the RE is not too accurate but should be enough
            [ '.', '([-+]?([0-9]+(\.[0-9]*)?|\.[0-9]+))', "NUMBERS", None],

            ## Name object:
            [ '.', '/[#\.\w_\+-]+', 'NAME_OBJECT', None],

            ## Array Objects:
            [ '.', '\[', 'PUSH_STATE,ARRAY_START', 'ARRAY'],
            [ 'ARRAY', '\]', 'ARRAY_END,POP_STATE', None],

            ## Dictionary Objects:
            [ '.','<<', 'PUSH_STATE,DICTIONARY_START', 'DICTIONARY'],
            [ 'DICTIONARY', '>>', 'POP_STATE,DICTIONARY_END', None ],

            ## The trailer:
            [ '.', '^trailer', 'TRAILER,PUSH_STATE', 'TRAILER' ],

            ## Whitespace:
            [ '.','\s+', 'SPACE', None],
            ]
        lexer.Lexer.__init__(self)
        self.objects=[]
        self.fd = fd
        self.pdf = PDFFile()
        self.string =''
        self.xref_start_entry = 0
        self.xref_entries_to_go = 0
        self.verbose = verbose

    def ERROR(self, message=None):
        ## IF the error count is too high, we need to reset our state:
        if message:
            print "Error: %s" % message

        lexer.Lexer.ERROR(self)

    def RESET_STATE(self, t, m):
        ## Lose all the current objects:
        self.objects = []

    def OBJECT_DECLERATION_START(self, t, m):
        self.add_to_current_object(PDFObject(m.group(1),m.group(2)))

    def OBJECT_DECLERATION_END(self, token, match):
        o = self.objects.pop()
        ## Add the object to our file:
        self.pdf.objects.append(o)

    def add_to_current_object(self, value):
        try:
            try:
                current_object = self.objects[-1]
            except IndexError:
                #print "Top level object %s" % value
                self.objects.append(value)
                return


            ## Is it an array?
            try:
                current_object.append(value)
                return
            except AttributeError:
                pass

            ## It must be a dictionary - dictionaries are populated by key
            ## value successively inserted - so we store the first value,
            ## and when we get the second value we put it in:
            if current_object[1]:
                try:
                    if self.state_stack[-1] == 'TRAILER' and current_object[1]=='/Prev':
                        self.pdf.xref_offsets.append(value)
                except: pass

                current_object[current_object[1]] = value
                current_object[1] = None

            else:
                current_object[1] = value
        except:
            pass
    def OBJECT_REFERENCE(self, token, m):
        self.add_to_current_object([ int(m.group(1)), int(m.group(2)) ])

    def NUMBERS(self, token, m):
        self.add_to_current_object(float(m.group(0)))

    def LITERAL_STRING(self, token, m):
        self.string += m.group(0)

    def LITERAL_STRING_END(self, t,m):
        self.add_to_current_object(self.string)
        self.string =''

    def NAME_OBJECT(self, t,m):
        self.add_to_current_object(m.group(0))

    def ARRAY_START(self, t,m):
        self.objects.append([])

    def ARRAY_END(self, t,m):
        self.add_to_current_object(self.objects.pop())

    def DICTIONARY_START(self, token, match):
        ## Create a new dictionary in our object
        self.objects.append({1:0})
        
    def DICTIONARY_END(self, token, match):
        d = self.objects.pop()
        del d[1]
        self.add_to_current_object(d)

    def BOOLEAN(self, t, m):
        if m.group(0)=='true':
            self.add_to_current_object(True)
        else:
           self.add_to_current_object(False) 

    def HEX_STRING(self, t,m):
        hexstring = m.group(1)
        result=''
        for i in range(0,len(hexstring)-2,2):
            result += chr(int(hexstring[i:i+2],16))

        self.add_to_current_object(result)

    def XREF_START(self, t, m):
        self.xref_start_entry = int(m.group(1))
        self.xref_entries_to_go = int(m.group(2))
        self.pdf.xref_range = [ self.xref_start_entry,
                                self.xref_start_entry + self.xref_entries_to_go ]

    def XREF_DATA(self, t,m):
        object_number = self.xref_start_entry
        offset = int(m.group(1))
        generation_number = int(m.group(2))
        type = m.group(3)
        ## Add the reference directly to our file handler
        self.pdf.xref.append([object_number, offset, generation_number, type])

        self.xref_start_entry +=1
        self.xref_entries_to_go -= 1

        ## We are finished with this table restore parser state to
        ## whatever it was before:
        if self.xref_entries_to_go==0:
            return self.POP_STATE()

    def TRAILER(self, t, m):
        self.objects.append(self.pdf.trailer)

    def STREAM_START(self, t,m):
        ## We expect there to be an object on the stack:
        obj = self.objects[-1]

        ## What kind of stream is this? FIXME - implement cascaded
        ## filters
        if obj.dictionary.get('/Filter') == '/FlateDecode':
            ## Initialise the decompressor:
            self.dc = zlib.decompressobj()
            self.stream = ''
            self.decompressed = ''
            return "FLATE_STREAM"
        else:
            return "GENERIC_STREAM"

    def STREAM(self, t, m):
        if self.state == 'FLATE_STREAM':
            if self.verbose>2:
                print "Got %s bytes" % len(m.group(0))
                
            self.stream += m.group(0)
            try:
                decompressed = self.dc.decompress(m.group(0))
                if self.verbose>2:
                    print "Decompressed %r" % decompressed
                    
                self.decompressed += decompressed
            except zlib.error,e:
                self.ERROR("Unable to decompress stream %s after %s bytes " % (e, self.processed))
                
        else:
            self.stream += m.group(0)

    def END_STREAM(self, t,m):
        if self.state == 'FLATE_STREAM':
            ## Finalise the stream:
            try:
                ex = self.dc.decompress('Z') + self.dc.flush()
                if ex:
                    self.decompressed += ex
            except zlib.error,e:
                self.ERROR("Unable to decompress stream %s after %s bytes" % (e, self.processed))

    def START_XREF(self, t, m):
        """ We record the reference to the previous xref table here """
        try:
            offset = int(m.group(0))
            if offset != 0:
                self.pdf.xref_offsets.append(offset)
        except AttributeError:
            pass

if __name__ == '__main__':
    import sys
    
    if len(sys.argv)==2:
        fd = open(sys.argv[1])
    else:
        fd = open("test_document.pdf")
        
    p = PDFParser(fd, 1)

    while p.feed():
        while p.next_token(): pass

    print p.pdf
