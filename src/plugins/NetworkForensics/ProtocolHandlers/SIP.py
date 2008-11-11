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
import sys,os.path
sys.path.append(os.path.dirname(__file__) + "/../")

import pyflag.Packets as Packets
from format import *
from plugins.FileFormats.BasicFormats import *
import pyflag.FlagFramework as FlagFramework
import pyflag.DB as DB
import struct,re, math
from pyflag.ColumnTypes import StringType, PacketType, IPType
import pyflag.Store as Store
import pyflag.pyflaglog as pyflaglog
import NetworkScanner
from pyflag.ColumnTypes import StringType, TimestampType, InodeIDType, IntegerType, PacketType, guess_date
#disable =True

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
                self.details = value
            elif attribute=='c':
                self.con_details = value.split(" ")

class SIPParser:
    message = None
    sequence = None
    sdp = None

    dispatch = { 'from': '_from' }

    def __init__(self, case):
        self.case = case
    
    def parse_request(self, method, uri, data):
        if method=="INVITE":
            self.parse_data(data)

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
            print "Parsing 200"
            self.parse_data(data)
            #print "Parsed %s %r " % (self.sequence, self.sdp)
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
                pass
#                print "Unable to handle header %s: %s" % (header, value)

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

class VOIPTable(FlagFramework.CaseTable):
    """ VOIP Table - Keep all VOIP transactions """
    name = 'voip'
    columns = [
        [ InodeIDType, {} ],
        [ TimestampType, dict(name='Start Time', column='start') ],
        [ TimestampType, dict(name='End Time', column='end') ],
        [ IPType, dict(name='Source Addr', column='source') ],
        [ IntegerType, dict(name="Source Port", column='source_port') ],
        [ IPType, dict(name='Dest Addr', column='dest') ],
        [ IntegerType, dict(name="Dest Port", column='dest_port') ],
        
        [ StringType, dict(name='Protocol', column='protocol') ],
        ]

import pyflag.Magic as Magic

class SIPRequestMagic(Magic.Magic):
    """ Identify SIP request streams """
    type = "SIP Request"
    mime = "protocol/x-sip-request"

    regex_rules = [
        ( "[A-Z]+ [^ ]{1,600} SIP/2.", (0,500)),
        ]

    samples = [
        ( 100, "INVITE sip:xxxxxx@voice.mibroadband.com.au SIP/2.0"),
        ( 100, "ACK sip:xxxxxx@voice.mibroadband.com.au SIP/2.0"),
        ]

class SIPResponseMagic(Magic.Magic):
    """ Identify SIP response streams """
    type = "SIP Response"
    mime = "protocol/x-sip-response"
    regex_rules = [
        ( r"SIP/2.0 \d\d\d ", (0,500)),
        ]
    
    samples = [
        ( 100, "SIP/2.0 407 Proxy Authentication Required"),
        ( 100, "SIP/2.0 200 OK"),
        ]
    
class SIPScanner(NetworkScanner.StreamScannerFactory):
    """ SIP is a HTTP Like protocol based on UDP packets """
    request_re = re.compile(r"(?sm)(([A-Z]+) ([^ ]+) (SIP/\d.\d))\r\n(.+)",re.DOTALL)
    response_re = re.compile(r"(?sm)((SIP/\d\.\d) (\d\d\d) ([A-Za-z ]+))\r\n(.+)", re.DOTALL)

    default = True
    group = "NetworkScanners"
    depends = ['TypeScan']
    
    def process_stream(self, stream, factories):
        combined_inode = "I%s|S%s/%s" % (stream.fd.name, stream.inode_id, stream.reverse)
        try:
            fd = self.fsfd.open(inode=combined_inode)
            ## If we cant open the combined stream, we quit (This could
            ## happen if we are trying to operate on a combined stream
            ## already
        except IOError: return
        self.parser = SIPParser(self.case)
        
        pyflaglog.log(pyflaglog.DEBUG, "Openning %s for SIP" % combined_inode)
        for packet_id, cache_offset, data in fd.packet_data():
            self.handle(data)

    class Scan(NetworkScanner.StreamTypeScan):
        types = [ 'protocol/x-sip-request' ]
    
    def handle(self, data):
        try:
            m = self.request_re.match(data)
            if m:
                #print "SIP request found %r" % m.group(1)
                try:
                    self.parser.parse_request(m.group(2), m.group(3), m.group(5))
                except Exception, e:
                    pass

            m = self.response_re.match(data)
            if m:
                #print "SIP response found %s" % m.group(1)
                try:
                    self.parser.parse_response(m.group(3), m.group(4), m.group(5))
                except Exception, e:
                    pass
                    #print e
                    #print FlagFramework.get_bt_string(e)
                
        except (AttributeError, TypeError):
            pass

def calculate_stream_stats(case, stream_id):
    """ This function calculate stream statistics such as jitter and
    average bit rate. These statistics help us determine if the stream
    is likely to be VOIP. Decoding the stream is a totally different
    matter though.
    """
    dbh = DB.DBO(case)
    ## The following creates a temporary table with data points
    ## relating to the stream's packet arrival times and cache
    ## offsets. We substract the absolute time from the stream to
    ## control numerical overflows.
    dbh.execute("select @i:=0, unix_timestamp(ts_sec) as t_offset from "
                "connection join pcap on "
                "connection.packet_id = pcap.id where inode_id=%r limit 1", stream_id)
    row = dbh.fetch()

    table_name = "temp_stream_stats_%s" % stream_id
    
    dbh.execute("create temporary table %s "
                "select @i:=@i+1 as i, "
                "unix_timestamp(ts_sec) + ts_usec * 1e-6 - %s as t, "
                "cache_offset as o from connection join pcap on "
                "connection.packet_id = pcap.id where inode_id=%r",
                table_name, row['t_offset'], stream_id)
    
    ## Now collect some values for calculating stats
    dbh.execute("select count(i) as n, sum(i) as s_i, sum(i * i) as s_i2,"
                "sum(t) as s_t, sum(t*t) as s_t2, sum(i*t) as s_cp_i_t, "
                "sum(o) as s_o, sum(o*o) as s_o2, sum(o*t) as s_cp_o_t from "
                "%s", table_name)

    row = dbh.fetch()
    ## Make sure they are all floats
    for k in row: row[k]=float(row[k])
    
    ## Now calculate Pearsons r for time vs. packet count (measure of
    ## jitter) and stream offset vs. time (measure of data rate).
    n = row['n']
    tmp_i_t = (n * row['s_cp_i_t'] - row['s_i'] * row['s_t'] )
    tmp_o_t = (n * row['s_cp_o_t'] - row['s_o'] * row['s_t'] )
    tmp_i = (n * row['s_i2'] - row['s_i'] ** 2 )
    tmp_t = (n * row['s_t2'] - row['s_t'] ** 2 )
    tmp_o = (n * row['s_o2'] - row['s_o'] ** 2 )

    ## This is the time jitter rate
    r_jitter = tmp_i_t / math.sqrt(tmp_i * tmp_t)

    ## This is the packet rate (packets per second)
    b_rate = tmp_i_t / tmp_t

    ## This is the data jitter rate
    r_data = tmp_o_t / math.sqrt(tmp_o * tmp_t)

    ## This is the avg data rate (in kbit/s) note that it may be
    ## slightly bigger than the codecs data rate due to RTP headers
    b_data = tmp_o_t / tmp_t * 8 / 1000

    return r_jitter, b_rate, r_data, b_data



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
import pyflag.pyflagsh as pyflagsh

class SIPTests(tests.ScannerTest):
    """ Test SIP Scanner """
    test_case = "PyFlagTestCase"
    test_file = "voip.pcap"
    subsystem = "Standard"
    fstype = "PCAP Filesystem"

    def test01HTTPScanner(self):
        """ Test HTTP Scanner """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env,
                             command="scan",
                             argv=["*",                   ## Inodes (All)
                                   "SIPScanner",
                                   ])                   ## List of Scanners

if __name__=='__main__':
    print calculate_stream_stats("PyFlagTestCase", 17)
