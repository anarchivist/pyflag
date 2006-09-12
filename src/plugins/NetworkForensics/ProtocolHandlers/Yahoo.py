# Michael Cohen <scudette@users.sourceforge.net>
# Gavin Jackson <gavz@users.sourceforge.net>
# Greg <gregsfdev@users.sourceforge.net>
#
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
"""  This is a Yahoo instant messenger scanner.

We use the main Yahoo parser from FileFormats library.
"""
from pyflag.format import Buffer
import FileFormats.Yahoo as Yahoo
from NetworkScanner import *

class YahooParser:
    """ A Parser for yahoo IM conversations """
    def __init__(self, stream):
        self.stream = stream
        self.buffer=Buffer(fd=stream)

    def process(self):
        while self.buffer.size>0:
            try:
                m = Yahoo.Message(self.buffer)
            except IOError:
                ## Try to resync to the next message:
                data = self.buffer[:1000].__str__()
                print "%r" % data
                offset = data.find("YMSG")
                if offset<0: return
                print "Lost sync - need to skip %s bytes: %r" % (offset, data[:offset])
                m=Yahoo.Message(self.buffer[offset:])
                
            yield m
            self.buffer=self.buffer[m.offset:]

class YahooScanner(StreamScannerFactory):
    """ A Yahoo IM Protocol scanner """
    default = True
    depends = [ "MSNScanner", ]

    def process_stream(self, stream, factories):
        """ Process the IM stream """
        ## Check to see if its an IM stream:
        stream.seek(0)
        magic = stream.read(4)
        if magic!="YMSG": return
        stream.seek(0)
        logging.log(logging.DEBUG,"Openning %s for Yahoo IM" % stream.inode)

        parser = YahooParser(stream)
        for action in parser.process():
            print action
