""" This is a module to parse SIP communications """
import pyflag.Packets as Packets
from format import *
from plugins.FileFormats.BasicFormats import *
import pyflag.FlagFramework as FlagFramework
import pyflag.DB as DB
import struct,re
from pyflag.TableObj import StringType, PacketType, IPType

class SIPHandler(Packets.PacketHandler):
    """ SIP is a HTTP Like protocol based on UDP packets """
    request_re = re.compile("([A-Z]+) ([^ ]+) (SIP/\d.\d)\r\n")
    response_re = re.compile("(SIP/\d.\d) (\d\d\d) ([A-Za-z]+)\r\n")
    def handle(self, packet):
        try:
            udp = packet.find_type("UDP")
            data = udp.data
            m = self.request_re.match(data)
            if m:
                print "SIP request found %s" % m.group(0)

            m = self.response_re.match(data)
            if m:
                print "SIP response found %s" % m.group(0)
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
