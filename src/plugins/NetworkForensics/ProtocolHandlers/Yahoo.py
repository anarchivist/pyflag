# Michael Cohen <scudette@users.sourceforge.net>
#
#
# ******************************************************
#  Version: FLAG $Version: 0.85 Date: Fri Dec 28 16:12:30 EST 2007$
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
        self.buffer = Buffer(fd=stream)
        self.case = stream.case

    def get_details(self, message):
        return dict(inode=self.stream.inode,
                    packet_id=self.stream.get_packet_id(self.stream.tell()),
                    session_id=message['session_id'].get_value())

    def process(self):
        dbh = DB.DBO(self.case)    
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
                result = getattr(self, m['service'].__str__())(m,dbh)
            except AttributeError,e:
                print "No dispatcher for %s (%s)" % (m['service'],e)
                #print m
                
            yield m

            ## Go to the next message:
            self.buffer=self.buffer[m.offset:]

    def YAHOO_SERVICE_AUTH(self,message,dbh):
        result = dict(sender = message.properties['1'],
                      data = "Is authenticating",
                      type = "AUTH REQUEST")

        result.update(self.get_details(message))
        dbh.insert('msn_session', **result)
        
#    def YAHOO_SERVICE_LOGON(self, message):
#        print message

    def YAHOO_SERVICE_MESSAGE(self,message,dbh):
        m = message.get_property('14')
        if not m:
            m=message['status']
            
        result = dict(sender = message.get_property(1,4),
                      recipient = message.get_property(0,5),
                      data=m,
                      type="MESSAGE",
                      )

        result.update(self.get_details(message))

        if not result['sender'] or not result['recipient']:
            print "%s" % message

        dbh.insert('msn_session', **result)

    def YAHOO_SERVICE_LIST(self, message,dbh):
        result = dict(sender = message.get_property(3),
                      data = message.get_property(87),
                      type = "BUDDY LIST")

        result2 = dict(sender = message.get_property(3),
                      data = message.get_property(88),
                      type = "IGNORE LIST")

        details = self.get_details(message)

        result.update(details)
        result2.update(details)

        dbh.insert('msn_session', **result)
        dbh.insert('msn_session', **result2)

    def YAHOO_SERVICE_NOTIFY(self, message, dbh):
        result = dict(sender = message.get_property(1,4),
                      recipient = message.get_property(5),
                      data = message.get_property(49),
                      type = "NOTIFY")
        
        result.update(self.get_details(message))
        dbh.insert('msn_session', **result)

    def get_chat_parameters(self, message, dbh):
        result= dict(sender = message.get_property(109),
                    recipient = message.get_property(104),
                    type = message['service'])
        result.update(self.get_details(message))
        return result
    
    def YAHOO_SERVICE_CHATEXIT(self,message,dbh):
        result = self.get_chat_parameters(message)
        result['data'] = "Exiting chatroom with topic: %s" % message.get_property(105)
        dbh.insert('msn_session', **result)

    def YAHOO_SERVICE_COMMENT(self,message,dbh):
        result = self.get_chat_parameters(message)
        result['data'] = message.get_property(117)
        dbh.insert('msn_session', **result)

    def YAHOO_SERVICE_CHATJOIN(self,message,dbh):
        result = self.get_chat_parameters(message)
        result['data'] = "Joined Chatroom of topic: %s" % message.get_property(105)
        dbh.insert('msn_session', **result)

    def YAHOO_SERVICE_CHATPING(self,message,dbh):
        pass

    def YAHOO_SERVICE_PING(self,message,dbh):
        pass
        
class YahooScanner(StreamScannerFactory):
    """ A Yahoo IM Protocol scanner """
    default = True
    depends = []

    def process_stream(self, stream, factories):
        """ Process the IM stream """
        ## Check to see if its an IM stream:
        stream.seek(0)
        magic = stream.read(4)
        if magic!="YMSG": return
        stream.seek(0)
        pyflaglog.log(pyflaglog.DEBUG,"Openning %s for Yahoo IM" % stream.inode)

        parser = YahooParser(stream)
        for action in parser.process():
            pass
