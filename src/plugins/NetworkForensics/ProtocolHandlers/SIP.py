# This is a module to proccess VOIP calls using SIP.
#
# SIP is a very complex protocol which is particularly badly designed
# to operate in an internet environment especially if NAT is
# involved. The whole point of SIP is to exchange IP addresses and
# ports of different end points to allow them to find each
# other. Unfortunately, in a NAT environment a node is unaware of its
# IP address and usually provides bogus or unroutable ip addresses
# within the SIP/SDP headers.
#
# The funny thing is that most implementations completely ignore the
# IP addresses transmitted within the SIP/SDP headers anyway and use a
# number of different methods to figure out the IP address of the end
# node:

# 1) Sometimes a received= attribute is added to the Via or Contact
# headers by the SIP proxy to specify the routable IP address of the
# client.

# 2) Sometimes the IP addresses reported by the SIP headers are
# completely ignored and the SIP proxy simply uses the originating IP
# address of the SIP call in order to route calls back.

# It seems like the whole point of SIP is defeated because no one
# actually follows the protocol at all anyway. Its a total mess. Its
# also very difficult to tell what method is actually used to specify
# the IP address in the traffic because that may depend on the point
# in the network where the capture is made and the specific NAT
# configuration.

# PyFlag tries to reproduce the audio streams and link them back to
# SIP calls. So we only need to parse enough of the SIP protocol to
# know which UDP packets are likely to contain the RDP streams. We
# then consider those packets as likely RDP packets. We make the
# assumption that port numbers are preserved across NAT which is the
# most common case. This is unfortunately not necessarily the case in
# every configuration but is the most common.

# This can cause problems because our interpretation of the traffic is
# very loose - which means we can mistaken spurious traffic for RDP
# packets.

""" This is a module to parse SIP communications """
import pyflag.Packets as Packets
from format import *
from plugins.FileFormats.BasicFormats import *
import pyflag.FlagFramework as FlagFramework
import pyflag.DB as DB
import struct,re
from pyflag.ColumnTypes import StringType, PacketType, IPType
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
        ## Forward stream:
        dbh.insert('mmsessions',
                   _from = "%r" % _from,
                   to = to,
                   type = details[2],
                   session_id = self.sequence,
                   )

        forward_id = dbh.autoincrement()
        dbh.insert('mmsessions',
                   to = _from,
                   _from = "%r" % to,
                   type = details[2],
                   session_id = self.sequence,
                   )

        reverse_id = dbh.autoincrement()

        return forward_id, reverse_id

    def record_rdp_ports(self, sdp1, sdp2, forward, reverse):
        details1 = sdp1.details.split()
        details2 = sdp2.details.split()
        key = (int(details1[1]), int(details2[1]))
        print "We expect a session between port %s" % (key,)

        SIPSessions.put( [sdp1._from, sdp1.to, forward, reverse] , key=key)
        
    def parse_response(self, start_code, reason, data):
        if start_code=="200":
            self.parse_data(data)
            print "Parsed %s %r " % (self.sequence, self.sdp)
            if self.sdp:
                invite_sdp = SIPInvites.get(self.sequence)
                forward, reverse = self.record_sdp_session(invite_sdp, invite_sdp._from, invite_sdp.to)
                self.record_rdp_ports(invite_sdp, self.sdp, forward,reverse)
                
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
            `id` int auto_increment,
            `packet_id` int,
            `from` VARCHAR(255) NOT NULL,
            `to` VARCHAR(255) NOT NULL,
            `type` VARCHAR(255) NOT NULL,
            `session_id` VARCHAR(255) NOT NULL,
            key(id)
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
                    pass

            m = self.response_re.match(data)
            if m:
                print "SIP response found %s" % m.group(1)
                try:
                    attributes.parse_response(m.group(3), m.group(4), m.group(5))
                except Exception, e:
                    pass
                    #print e
                    #print FlagFramework.get_bt_string(e)
                
        except (AttributeError, TypeError):
            pass

class RDPPacket(SimpleStruct):
    fields = [
        [ 'Flags', UBYTE, {} ],
        [ 'Type', UBYTE, {} ],
        [ 'Seq', USHORT, {} ],
        [ 'Timestamp', ULONG, {} ],
        ]

    def __init__(self, buffer, *args, **kwargs):
        kwargs['endianess']='b'
        SimpleStruct.__init__(self, buffer, *args, **kwargs)


class RDPHandler(Packets.PacketHandler):
    """ Picks out RDP packets depending on the SIP exchanges. """
    def handle(self, packet):
        try:
            udp = packet.find_type("UDP")
            src = udp.src_port
            dest = udp.dest_port

            ## Check if we expect this packet (Note that we ignore IP
            ## addresses due to NAT issues - see above).
            try:
                a,b,forward, reverse = SIPSessions.get((src,dest))
                self.process_session(a,b, forward, udp.data)
            except KeyError,e:
                try:
                    a,b, forward, reverse = SIPSessions.get((dest,src))
                    self.process_session(b,a, reverse, udp.data)
                except KeyError:
                    return
        except AttributeError,e:
            pass

    def process_session(self, a, b, stream_id, data):
        rdp_packet = RDPPacket(data)

        ## Get the fd for this session:
        try:
            key = "Session%s" % stream_id
            fd = SIPSessions.get(key)
        except KeyError:
            fd = open(key, 'a')
            SIPSessions.put(fd, key = key)

        type = rdp_packet['Type'].get_value() & 0x7F
        ## G711Alaw
        if type==0x08:
            #import audio_codecs

            #data = audio_codecs.g711a_decode(data[12:])
            data = data[12:]
        else:
            return
        
        ## Write the data on:
        fd.write(data)

import pyflag.tests as tests

class SIPTests(tests.ScannerTest):
    """ Test SIP Scanner """
    test_case = "PyFlagTestCase"
    test_file = "internode-voip-radio-raw.pcap"
    subsystem = "Advanced"
    fstype = "PCAP Filesystem"

if __name__=='__main__':
    pass
