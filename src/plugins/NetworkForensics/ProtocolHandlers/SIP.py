""" This is a module to parse SIP communications """
import pyflag.Packets as Packets
from format import *
from plugins.FileFormats.BasicFormats import *
import pyflag.FlagFramework as FlagFramework
import pyflag.DB as DB
import struct,re
from pyflag.TableObj import StringType, PacketType, IPType
import pyflag.Store as Store

## This keeps track of outstanding invitations.
SIPInvites = Store.Store()

## This keeps track of outstanding sessions.
SIPSessions = Store.Store()

class SDP:
    def parse(self, data):
        for line in data.splitlines():
            attribute, value = line.split("=",1)
            value = value.strip()
            
            if attribute=='m':
                print "details %s" % value
                self.details = value

class SIPAttribute:
    message = None
    sequence = None
    sdp = None

    dispatch = { 'from': '_from' }

    def __init__(self, case):
        self.case = case
    
    def parse_request(self, method, uri, data):
        if method=="INVITE":
            self.parse_data(data)
            ## Make sure we remeber this invite
            self.sdp.to = self.to
            self.sdp._from = self._from
            SIPInvites.put(self.sdp, key=self.sequence)

    def record_sdp_session(self, sdp, _from, to):
        details = sdp.details.split()
        dbh = DB.DBO(self.case)
        dbh.insert('mmsessions',
                   _from = "%r" % _from,
                   to = to,
                   type = details[2],
                   session_id = self.sequence,
                   )

    def parse_response(self, start_code, reason, data):
        if start_code=="200":
            self.parse_data(data)
            print "Parsed %s %r " % (self.sequence, self.sdp)
            if self.sdp:
                invite_sdp = SIPInvites.get(self.sequence)
                self.record_sdp_session(invite_sdp, invite_sdp._from, invite_sdp.to)
#                self.record_sdp_session(self.sdp, self._from, self.to)
        
    def parse_data(self, data):
        tmp = data.split("\r\n\r\n")

        try:
            self.message = tmp[1]
        except AttributeError:
            pass

        for line in tmp[0].splitlines():
            header, value = line.split(':',1)
            header = header.lower().replace("-","_")
            value = value.strip()
            try:
                header = self.dispatch.get(header, header)
                getattr(self, header)(value)
            except AttributeError:
                print "Unable to handle header %s: %s" % (header, value)

    def content_type(self, ct):
        print "Content Type is %s" % ct
        if ct.lower() == "application/sdp":
            self.sdp = SDP()
            self.sdp.parse(self.message)

    def cseq(self, sequence):
        self.sequence = sequence

    def to(self, to):
        self.to = to

    def _from(self, _from):
        self._from = _from

class SIPInit(FlagFramework.EventHandler):
    def create(self, dbh, case):
        ## This table is used to record sdp sessions detected
        dbh.execute(
            """Create table if not exists `mmsessions` (
            `packet_id` int,
            `from` VARCHAR(255) NOT NULL,
            `to` VARCHAR(255) NOT NULL,
            `type` VARCHAR(255) NOT NULL,
            `session_id` VARCHAR(255) NOT NULL,
            key(session_id)
            )""")


class SIPHandler(Packets.PacketHandler):
    """ SIP is a HTTP Like protocol based on UDP packets """
    request_re = re.compile(r"(?sm)(([A-Z]+) ([^ ]+) (SIP/\d.\d))\r\n(.+)",re.DOTALL)
    response_re = re.compile(r"(?sm)((SIP/\d\.\d) (\d\d\d) ([A-Za-z]+))\r\n(.+)", re.DOTALL)
    
    def handle(self, packet):
        try:
            udp = packet.find_type("UDP")
            data = udp.data
            m = self.request_re.match(data)
            attributes = SIPAttribute(self.case)
            if m:
                print "SIP request found %r" % m.group(1)
                try:
                    attributes.parse_request(m.group(2), m.group(3), m.group(5))
                except Exception, e:
                    print e

            m = self.response_re.match(data)
            if m:
                print "SIP response found %s" % m.group(1)
                try:
                    attributes.parse_response(m.group(3), m.group(4), m.group(5))
                except Exception, e:
                    print e
                
        except AttributeError:
            pass


        
import pyflag.tests as tests

class SIPTests(tests.ScannerTest):
    """ Test SIP Scanner """
    test_case = "PyFlagTestCase"
    test_file = "internode-voip-radio-raw.pcap"
    subsystem = "Advanced"
    fstype = "PCAP Filesystem"

if __name__=='__main__':
    pass
