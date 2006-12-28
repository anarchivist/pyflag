""" The LZFU is a MS specific compression used for rtf files. It is mainly used in PST files """
from format import *
from plugins.FileFormats.BasicFormats import *
import sys,array
import StringIO

LZFU_INITDICT =  "{\\rtf1\\ansi\\mac\\deff0\\deftab720{\\fonttbl;}{\\f0\\fnil \\froman \\fswiss \\fmodern \\fscript \\fdecor MS Sans SerifSymbolArialTimes New RomanCourier{\\colortbl\\red0\\green0\\blue0\r\n\\par \\pard\\plain\\f0\\fs20\\b\\i\\u\\tab\\tx"

class LZFUHeader(SimpleStruct):
    fields = [
        [ "cbSize", ULONG ],
        [ "RawSize" , ULONG],
        [ "Magic", ULONG_CONSTANT, dict(expected=0x75465A4C)],
        [ "CRC", ULONG],
        ]

    def read(self):
        result = SimpleStruct.read(self)

        dictionary = array.array('c', LZFU_INITDICT + ' '*4096)
        dictionary_offset= len(LZFU_INITDICT)
        data = ''
        expected_length = int(result['RawSize'])-1

        while self.offset < self.buffer.size and len(data) < expected_length:
            flags = BYTE(self.buffer[self.offset:])
            self.offset += flags.size()
            
            flag_mask = 1
            while flag_mask!=0 and len(data) < expected_length:
                if flag_mask & int(flags):
                    ## Compressed reference:
                    blkhdr = USHORT(self.buffer[self.offset:], endianess='big')
                    self.offset += blkhdr.size()

                    offset = int(blkhdr)>>4
                    length = (int(blkhdr) & 0xf) + 2

                    for i in range(0,length):
                        c1 = dictionary[(offset+i)%4096];
                        dictionary[dictionary_offset]=c1;
                        dictionary_offset = (dictionary_offset+1) % 4096;
                        data += c1;
                else:
                    ## Verbatim byte:
                    b = self.buffer[self.offset]
                    if not b: break
                    
                    self.offset += 1
                    dictionary[dictionary_offset] = b
                    dictionary_offset= (dictionary_offset+1) % 4096
                        
                    data += b

                flag_mask = (flag_mask << 1) & 0xff

        self.add_element(result, 'data', STRING(data, length=len(data)))

        return result
    
if __name__=="__main__":
    fd=open(sys.argv[1],'r')
    b=Buffer(fd=fd)    
    lzfu = LZFUHeader(b)
    print lzfu
