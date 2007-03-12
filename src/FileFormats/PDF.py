import lexer, zlib, os

class myfile(file):
    def __init__(self, filename):
        self.buffer = ''
        file.__init__(self,filename)

    def read(self, length):
        result = ''
        
        while len(result)<length:
            result += self.buffer[:length]
            self.buffer = self.buffer[:length]

            if not self.buffer:
                self.buffer = file.read(self, 1024)

        return result

    def seek(self, off, whence):
        self.buffer = ''
        return file.seek(self, off, whence)

    def readline(self, delimiters = None, max_size = 1024):
        if not delimiters:
            delimiters = ('\r','\n','\r\n')
            
        if len(self.buffer)<1024:
            self.buffer = self.buffer + file.read(self, 1024)

        idxs = {}
        for i in ('\r','\n','\r\n'):
            try:
                idxs[self.buffer.index(i)] = i
            except:
                pass

        if not idxs: return ''
        
        idx = min(idxs.keys())
        #print idx, idxs
        line = self.buffer[:idx + len(idxs[idx])]
        #print "%r %s"% (self.buffer[:100],idx)


        self.buffer = self.buffer[idx + len(idxs[idx]):]
        return line

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

    def read_stream(self, fd):
        """ Reads the stream from the fd. When we finished the fd
        should be consumed until after the endstream command
        """
        if self.dictionary['/Filter']=='/FlateDecode':
            dc = zlib.decompressobj()
            while 1:
                line = fd.readline()
                if line.startswith('endstream'):
                    ## Flush the decompressor:
                    ex = dc.decompress('Z') + dc.flush()
                    if ex:
                        self.decoded_stream += ex
                    return

                ## Try to decompress the line:
                self.stream += line
                decompressed = dc.decompress(line)
                self.decoded_stream += decompressed
                #print "Decompressed %r" % decompressed
                
            self.decoded_stream = zlib.decompress(self.stream)
            ## We cant decode this yet so just consume all the data until the endstream
        else:
            while 1:
                line=fd.readline()
                if line.startswith('endstream'):
                    break

                if len(line)==0:
                    break

                self.stream += line                

            self.decoded_stream = self.stream

class PDFFile:
    """ A Class representing the PDF File """
    ## The trailer dictionary
    trailer = []

    ## The xrefs:
    xref = []

    ## The objects in this file:
    objects = []

    def __str__(self):
        result = 'Output of PDF file\n'
        result += "Xref Table:\n"
        for i in self.xref:
            result += "%s\n" % (i,)
#            result += "id=%s, group=%s, offset=%s, type=%s\n" % i
        result += "Trailer: %r\n" % self.trailer
        for o in self.objects:
            result += "%s\n" % o

        return result
        
class PDFParser(lexer.Lexer):
    state = "INITIAL"
    error = 0
    objects=[]

    tokens = [
        ## Identify comments:
        [ ".", "%%EOF", "RESET_STATE", 'INITIAL'], 
        [ ".", "%[^\n\r]*", "COMMENT", None ],
        
        ## End of line terminator:
        [ '.', '(\r|\r\n|\n)$', "EOL", None ],

        ## Detect an object decleration:
        [ 'INITIAL', '^(\d+) (\d+) obj', "OBJECT_DECLERATION_START,PUSH_STATE", "OBJECT DECLERATION" ],
        [ '.','^endobj',"OBJECT_DECLERATION_END,POP_STATE", None],

        ## This stuff comes from the PDF reference Adobe Chanter 3 - Syntax

        ## This bit parses the xref table:
        [ '.', '^xref', 'PUSH_STATE', 'XREF_HEADER' ],
        [ 'XREF_HEADER', '(\d+) (\d+)', 'XREF_START', 'XREF_DATA'],

        [ '.', '^startxref', 'IGNORE', None],
         

        ## The xref data is always exactly the same length according
        ## to the standard... We expect to see exactly n entries here
        ## (as declared by the header above), so the XREF_DATA cb will
        ## pop the state when we have seen enough.
        [ 'XREF_DATA' , '(\d{10}) (\d{5}) ([a-zA-Z])', 'XREF_DATA', None ],
        
        ## Indirect reference:
        [ '.', '(\d+) (\d+) R', "OBJECT_REFERENCE", None],
        
        ## Boolean
        [ '.', '(true|false)', 'BOOLEAN', None],

        ## Strings - there are 2 types:
        ## Literal strings:
        
        ## The LITERAL_STRING_START cb needs to save the current state
        ## to be restored later
        [ '.', '\(', "PUSH_STATE", 'LITERAL_STRING'],
        [ 'LITERAL_STRING', '^[^\\()]+', 'LITERAL_STRING', None ],
#        [ 'LITERAL_STRING', r'(\(|\))', 'LITERAL_STRING', None ],

        ## Note that here the CB pops the previous state
        [ 'LITERAL_STRING', '\)', 'LITERAL_STRING_END,POP_STATE', None],
        
        ## Hexadecimal strings:
        [ '.', "<(([0-9A-Fa-f]|\s)+)>", 'HEX_STRING', None],

        ## Numbers - the RE is not too accurate but should be enough
        [ '.', '([-+]?([0-9]+(\.[0-9]*)?|\.[0-9]+))', "NUMBERS", None],

        ## Name object:
        [ '.', '/[#\w_-]+', 'NAME_OBJECT', None],

        ## Array Objects:
        [ '.', '\[', 'ARRAY_START,PUSH_STATE', 'ARRAY'],
        [ 'ARRAY', '\]', 'ARRAY_END,POP_STATE', None],

        ## Dictionary Objects:
        [ '.','<<', 'DICTIONARY_START,PUSH_STATE', 'DICTIONARY'],
        [ 'DICTIONARY', '>>', 'DICTIONARY_END,POP_STATE', None ],

        ## Streams - this is kind of cheating a little, when we
        ## encounter a stream, the cb is responsible for consuming the
        ## stream from the input - this can be done either by using
        ## the length from the corresponding object dictionary, or
        ## looking for the keyword "endstream" itself. This is why we
        ## dont change the parser state here.
        [ '.', '^stream(\r|\r\n|\n)', 'STREAM_START', None],

        ## The trailer:
        [ '.', '^trailer', 'TRAILER', None ],

        ## Whitespace:
        [ '.','\s+', 'SPACE', None],
        ]

    def __init__(self, fd):
        self.fd = fd
        lexer.Lexer.__init__(self)
        self.pdf = PDFFile()
        self.string =''
        self.xref_start_entry = 0
        self.xref_entries_to_go = 0
        
    def feed(self):
        data = self.fd.readline()
        lexer.Lexer.feed(self, data)

        return len(data)

    def ERROR(self, message=None):
        ## IF the error count is too high, we need to reset our state:
        if self.error>100:
            self.state = 'INITIAL'
            self.error = 0

        if message:
            print "Error: %s" % message

        lexer.Lexer.ERROR(self)

    def OBJECT_DECLERATION_START(self, t, m):
        self.add_to_current_object(PDFObject(m.group(1),m.group(2)))

    def OBJECT_DECLERATION_END(self, token, match):
        o = self.objects.pop()
        ## Add the object to our file:
        self.pdf.objects.append(o)

    def add_to_current_object(self, value):
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
            current_object[current_object[1]] = value
            current_object[1] = None
        else:
            current_object[1] = value

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

    def STREAM_START(self, t,m):
        ## We expect there to be an object on the stack:
        obj = self.objects[-1]
        obj.read_stream(self.fd)

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

    def XREF_DATA(self, t,m):
        object_number = self.xref_start_entry
        offset = int(m.group(1))
        generation_number = int(m.group(2))
        type = m.group(3)
        ## Add the reference directory to our file handler
        self.pdf.xref.append([object_number, offset, generation_number, type])

        self.xref_start_entry +=1
        self.xref_entries_to_go -= 1

        ## We are finished with this table restore parser state to
        ## whatever it was before:
        if self.xref_entries_to_go==0:
            return self.POP_STATE()

    def TRAILER(self, t, m):
        self.objects.append(self.pdf.trailer)


if __name__ == '__main__':
    import sys
    
    if len(sys.argv)==2:
        fd = myfile(sys.argv[1])
    else:
        fd = myfile("test_document.pdf")
        
    p = PDFParser(fd)

    while p.feed():
        while p.next_token(): pass

    print p.pdf
