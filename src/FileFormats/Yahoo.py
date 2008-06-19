#!/usr/bin/env python
# ******************************************************
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.87-pre1 Date: Thu Jun 12 00:48:38 EST 2008$
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
"""
This is a format library to parse Yahoo instant messenger communication streams.

Most of the information here comes from:
http://libyahoo2.sourceforge.net/ymsg-9.txt

and the associated libyahoo source code.
"""
from format import *
from plugins.FileFormats.BasicFormats import *
import sys

class Services(WORD_ENUM):
    types = {
        1: 'YAHOO_SERVICE_LOGON', 
        2: 'YAHOO_SERVICE_LOGOFF', 
        3: 'YAHOO_SERVICE_ISAWAY', 
        4: 'YAHOO_SERVICE_ISBACK', 
        5: 'YAHOO_SERVICE_IDLE', 
        6: 'YAHOO_SERVICE_MESSAGE', 
        7: 'YAHOO_SERVICE_IDACT', 
        8: 'YAHOO_SERVICE_IDDEACT', 
        9: 'YAHOO_SERVICE_MAILSTAT', 
        10: 'YAHOO_SERVICE_USERSTAT', 
        11: 'YAHOO_SERVICE_NEWMAIL', 
        12: 'YAHOO_SERVICE_CHATINVITE', 
        13: 'YAHOO_SERVICE_CALENDAR', 
        14: 'YAHOO_SERVICE_NEWPERSONALMAIL', 
        15: 'YAHOO_SERVICE_NEWCONTACT', 
        16: 'YAHOO_SERVICE_ADDIDENT', 
        17: 'YAHOO_SERVICE_ADDIGNORE', 
        18: 'YAHOO_SERVICE_PING', 
        19: 'YAHOO_SERVICE_GROUPRENAME', 
        20: 'YAHOO_SERVICE_SYSMESSAGE', 
        0x16: 'YAHOO_SERVICE_PASSTHROUGH2', 
        0x18: 'YAHOO_SERVICE_CONFINVITE',   
        0x19: 'YAHOO_SERVICE_CONFLOGON', 
        0x1a: 'YAHOO_SERVICE_CONFDECLINE',  
        0x1b: 'YAHOO_SERVICE_CONFLOGOFF', 
        0x1c: 'YAHOO_SERVICE_CONFADDINVITE', 
        0x1d: 'YAHOO_SERVICE_CONFMSG', 
        0x1e: 'YAHOO_SERVICE_CHATLOGON', 
        0x1f: 'YAHOO_SERVICE_CHATLOGOFF', 
        0x20: 'YAHOO_SERVICE_CHATMSG', 
        0x28: 'YAHOO_SERVICE_GAMELOGON', 
        0x29: 'YAHOO_SERVICE_GAMELOGOFF', 
        0x2a: 'YAHOO_SERVICE_GAMEMSG', 
        0x46: 'YAHOO_SERVICE_FILETRANSFER', 
        0x4a: 'YAHOO_SERVICE_VOICECHAT', 
        0x4b: 'YAHOO_SERVICE_NOTIFY', 
        0x4d: 'YAHOO_SERVICE_P2PFILEXFER', 
        0x4f: 'YAHOO_SERVICE_PEERTOPEER',
        0x50: 'YAHOO_SERVICE_WEBCAM',
        0x54: 'YAHOO_SERVICE_AUTHRESP', 
        0x55: 'YAHOO_SERVICE_LIST', 
        0x57: 'YAHOO_SERVICE_AUTH', 
        0x83: 'YAHOO_SERVICE_ADDBUDDY', 
        0x84: 'YAHOO_SERVICE_REMBUDDY', 
        0x85: 'YAHOO_SERVICE_IGNORECONTACT', 
        0x86: 'YAHOO_SERVICE_REJECTCONTACT',
        0x89: 'YAHOO_SERVICE_GROUPRENAME',
        0x96: 'YAHOO_SERVICE_CHATONLINE',
        0x97: 'YAHOO_SERVICE_CHATGOTO',
        0x98: 'YAHOO_SERVICE_CHATJOIN',
        0x99: 'YAHOO_SERVICE_CHATLEAVE',
        0x9b: 'YAHOO_SERVICE_CHATEXIT',
        0xa0: 'YAHOO_SERVICE_CHATLOGOUT',
        0xa1: 'YAHOO_SERVICE_CHATPING',
        0xa8: 'YAHOO_SERVICE_COMMENT',
        }

class Status(LONG_ENUM):
    types={
        0: 'YAHOO_STATUS_AVAILABLE', 
        1: 'YAHOO_STATUS_BRB', 
        2: 'YAHOO_STATUS_BUSY', 
        3: 'YAHOO_STATUS_NOTATHOME', 
        4: 'YAHOO_STATUS_NOTATDESK', 
        5: 'YAHOO_STATUS_NOTINOFFICE', 
        6: 'YAHOO_STATUS_ONPHONE', 
        7: 'YAHOO_STATUS_ONVACATION', 
        8: 'YAHOO_STATUS_OUTTOLUNCH', 
        9: 'YAHOO_STATUS_STEPPEDOUT',  
        12: 'YAHOO_STATUS_INVISIBLE',  
        99: 'YAHOO_STATUS_CUSTOM', 
        999: 'YAHOO_STATUS_IDLE', 
        0x5a55aa56: 'YAHOO_STATUS_OFFLINE', 
        0x16: 'YAHOO_STATUS_TYPING', 
        }

class Element(TERMINATED_STRING):
    """ YMSG packets use a weird terminator to delimit strings """
    terminator = "\xc0\x80"
    initial_blocksize=100
    inclusive = False

class Message(SimpleStruct):
    """ The Yahoo Message.

    This consist of some information followed by a sequence of Elements
    """

    ## Messages are always in network order
    opts = {'endianess':'b'}
    fields = [
        [ 'magic',   STRING,  dict(length=4) ],
        [ 'version', ULONG,  opts],
        [ 'pkt_len', WORD,   opts],
        [ 'service', Services,   opts],
        [ 'status',  Status,  opts],
        [ 'session_id', ULONG, opts],
        ]
        
    def read(self):
        result = SimpleStruct.read(self)
        if result['magic'] != "YMSG":
            raise IOError("Packet is not a Yahoo message")

        pkt_len = int(result['pkt_len'])
        if pkt_len > 64000:
            raise IOError("Packet too large... Maybe traffic is corrupt?")

        ## This is where we expect the data to end. Often the last
        ## element in the payload is just padding:
        tmp = self.buffer[self.offset:self.offset+pkt_len]
        self.properties = {}
        while tmp.size>2:
            key = Element(tmp)
            tmp=tmp[key.size():]
            value = Element(tmp)
            tmp=tmp[value.size():]
            self.properties[key.get_value()] = value.get_value()
            #print "%s -> %s" % (key.get_value(),value.get_value())

        ## This ensures that the YMSG packet takes up exactly as much
        ## as its meant to - without overflowing into the next
        ## packet. Note that sometimes packet length is not accurate,
        ## so the scanner may resync by searching for the next YMSG
        ## header.
        self.offset+=pkt_len
        return result

    def __str__(self):
        result = SimpleStruct.__str__(self)
        result+="Properties: \n"
        for k,v in self.properties.items():
            result+="     %s: %s\n" % (k,v)

        return result
    
    def payload(self):
        return self.data['data'].get_value().__str__()

    def get_property(self,*args):
        """ Tries to retrieve the property in one of the args in order.

        If none are found, we return None.
        """
        for a in args:
            try:
                return self.properties[a.__str__()]
            except:
                pass

        return None

if __name__ == "__main__":
    fd = open(sys.argv[1],'r')
    b=Buffer(fd=fd)

    while b.size>0:
        m = Message(b)
        print m
        b=b[m.offset:]
