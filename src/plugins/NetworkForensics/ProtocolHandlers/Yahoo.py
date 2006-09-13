# Michael Cohen <scudette@users.sourceforge.net>
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
    def __init__(self, stream, dbh):
        self.stream = stream
        self.buffer = Buffer(fd=stream)
        self.dbh = dbh

    def get_details(self, message):
        return dict(inode=self.stream.inode,
                    packet_id=self.stream.get_packet_id(self.stream.tell()),
                    session_id=message['session_id'].get_value())

    def process(self):
        while self.buffer.size>0:
            try:
                m = Yahoo.Message(self.buffer)
            except IOError:
                ## Try to resync to the next message, sometimes
                ## messages are padded with NULLs:
                data = self.buffer[:1000].__str__()
                offset = data.find("YMSG")
                if offset<0: return
                #print "Lost sync - need to skip %s bytes: %r" % (offset, data[:offset])
                m=Yahoo.Message(self.buffer[offset:])

            ## Try to dispatch a handler for this service:
            try:
                result = getattr(self, m['service'].__str__())(m)
            except AttributeError,e:
                print "No dispatcher for %s (%s)" % (m['service'],e)
                print m
                
            yield m

            ## Go to the next message:
            self.buffer=self.buffer[m.offset:]

    def YAHOO_SERVICE_AUTH(self,message):
        result = dict(sender = message.properties['1'],
                      data = "Is authenticating",
                      type = "AUTH REQUEST")

        result.update(self.get_details(message))
        self.dbh.insert('msn_session', **result)
        
#    def YAHOO_SERVICE_LOGON(self, message):
#        print message

    def YAHOO_SERVICE_MESSAGE(self,message):
        m = message.get_property('14')
        if not m:
            m=message['status']
            
        result = dict(sender = message.get_property('1','4'),
                      recipient = message.get_property('0','5'),
                      data=m,
                      type="MESSAGE",
                      )

        result.update(self.get_details(message))

        if not result['sender'] or not result['recipient']:
            print "%s" % message

        self.dbh.insert('msn_session', **result)

    def YAHOO_SERVICE_LIST(self, message):
        result = dict(sender = message.get_property('3'),
                      data = message.get_property('87'),
                      type = "BUDDY LIST")

        result2 = dict(sender = message.get_property('3'),
                      data = message.get_property('88'),
                      type = "IGNORE LIST")

        details = self.get_details(message)

        result.update(details)
        result2.update(details)

        self.dbh.insert('msn_session', **result)
        self.dbh.insert('msn_session', **result2)

    def YAHOO_SERVICE_NOTIFY(self, message):
        result = dict(sender = message.get_property('1','4'),
                      recipient = message.get_property('5'),
                      data = message.get_property('49'),
                      type = "NOTIFY")
        
        result.update(self.get_details(message))
        self.dbh.insert('msn_session', **result)

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

        parser = YahooParser(stream, DB.DBO(stream.case))
        for action in parser.process():
            pass
