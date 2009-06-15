# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
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
""" This is a module to parse DNS requests """
import pyflag.Packets as Packets
from format import *
from plugins.FileFormats.BasicFormats import *
import pyflag.FlagFramework as FlagFramework
import pyflag.DB as DB
import struct
from pyflag.ColumnTypes import StringType, PacketType, IPType
import pyflag.conf
config=pyflag.conf.ConfObject()
from plugins.NetworkForensics.NetworkScanner import StreamScannerFactory
from pyflag.ColumnTypes import StringType, TimestampType, InodeIDType, IntegerType, PacketType, guess_date, PCAPTime, IPType

class DNSString(STRING):
    """ This parses names encoded in DNS. We support standard DNS
    compression. Note we require that the buffer was originally
    created with the absolute offset being the start of the UDP packet
    in order to implement compression decoding. This is because
    compression refers to absolute offsets.
    """
    def __init__(self, buffer, *args, **kwargs):
        BYTE.__init__(self, buffer, *args, **kwargs)

    def read(self):
        result = ''
        offset = 0
        pos = -1
        ## The count of compression loops - helps detect circular loops
        count = 0
        buffer = self.buffer
        ## Limit total size to prevent loops
        while len(result)<1000 and count<10:
            length = UBYTE(buffer[offset:]).get_value()
            ## Exit conditions:
            if length == 0: break

            if length == 0xc0:
                ## The next byte is the new offset
                new_offset = UBYTE(buffer[offset+1:]).get_value()
                
                ## Save the current absolute stream offset:
                if pos<0:
                    pos = offset + 1

                buffer = buffer.set_offset(new_offset)
                offset = 0
                count += 1
            else:
                result = "%s%s." % (result, buffer[offset+1:offset + length +1])
                offset += 1 + length
                

        if pos > 0:
            self.length = pos + 1
        else:
            self.length = offset + 1
            
        return result

class DNSRRType(WORD_ENUM):
    types = { 1: "A",
              2: "NS",
              5: "CNAME",
              6: "SOA",
              11: "WKS",
              12: "PTR",
              13: "HINFO",
              15: "MX",
              16: "TXT",
              0x1c: "AAAA"}

class DNSRRClass(WORD_ENUM):
    types = { 1: "IN",
              2: "CS",
              3: "CH",
              4: "HS" }

class DNSQuestion(SimpleStruct):
    """ A single question is simply a struct """
    fields = [
        [ 'Name',  DNSString,  {} ],
        [ 'Type',  DNSRRType,  {} ],
        [ 'Class', DNSRRClass, {} ],
        ]

class DNSQuestionArray(ARRAY):
    target_class = DNSQuestion

class DNSAnswer(SimpleStruct):
    """ An Answer """
    fields = [
        [ 'Name', DNSString, {} ],
        [ 'Type', DNSRRType, {} ],
        [ 'Class', DNSRRClass, {} ],
        [ 'TTL',   LONG, {} ],
        [ 'RDLength', USHORT, {}],
        ]

    def read(self):
        """ The resource data field must be parsed specially depending on the type """
        result = SimpleStruct.read(self)

        if result['Type']=='CNAME':
            self.add_element(result, "C Name", DNSString(self.buffer[self.offset:]), self.parameters)
        elif result['Type']=='A':
            self.add_element(result, "IP Address", IPAddress(self.buffer[self.offset:]), self.parameters)
        else:
            self.add_element(result, "Data", STRING(self.buffer[self.offset:], length=result['RDLength']))

        self.offset += result['RDLength'].get_value()
        return result

class DNSAnswerArray(ARRAY):
    target_class = DNSAnswer

class DNSPacket(SimpleStruct):
    """ A DNS packet contains a list of questions and answers as well
    as RRs
    """
    fields = [
        [ 'Transaction ID',     USHORT, {}],
        [ 'Flags',              USHORT, {}],
        [ 'Num Queries',        USHORT, {}],
        [ 'Num Answers',        USHORT, {}],
        [ 'Num Authority RRs',  USHORT, {}],
        [ 'Num Additional RRs', USHORT, {}],
        [ 'Questions',          DNSQuestionArray,
          dict(count = lambda x: x['Num Queries'])],
        [ 'Answers',            DNSAnswerArray,
          dict(count = lambda x: x['Num Answers'])],
        ]

    def __init__(self, buffer, *args, **kwargs):
        ## endianess is always big with DNS:
        kwargs['endianess']='b'
        SimpleStruct.__init__(self, buffer, *args, **kwargs)

config.add_option("DNS_PORTS", default='[53,]',
                  help="A list of ports to be considered for DNS transactions")


class DNSScanner(StreamScannerFactory):
    """ Collect information about DNS resolution """
    default = True
    group = "NetworkScanners"

    def process_stream(self, stream, factories):
        forward_stream, reverse_stream = self.stream_to_server(stream, "DNS")
        if reverse_stream:
            fd = self.fsfd.open(inode_id=reverse_stream)
            ## We assume maximum length for DNS (this might be too
            ## short for TCP connections).
            data = fd.read(1024)
            try:
                dns = DNSPacket(data)
                dbh = DB.DBO(self.case)
                ## This is needed so we can iterate twice over the
                ## same array in case a CNAME is found
                answers = [x for x in dns['Answers']]

                for answer in answers:
                    if answer['Type']=='A':
                        dbh.insert('dns', inode_id = forward_stream,
                                   name = answer['Name'],
                                   ip_addr = struct.unpack('>I',answer['IP Address'].data)[0])

                    ## See if there are any CNAMEs in this packet:
                    elif answer['Type']=='CNAME':
                        ## Try to find an A record for it. Normally
                        ## CNAME records are followed by A records.
                        for possible_a in answers:
                            if possible_a['Type']=='A' and possible_a['Name']==answer['C Name']:
                                dbh.insert('dns', inode_id = forward_stream,
                                           name = answer['Name'],
                                           ip_addr = struct.unpack('>I',possible_a['IP Address'].data)[0])

            except (AttributeError,KeyError,IOError),e:
                pass

class DNSCaseTable(FlagFramework.CaseTable):
    """ DNS Table - Stores DNS transactions """
    name = 'dns'
    columns = [
        [ InodeIDType, {} ],
        [ StringType, dict(name = 'DNS Name', column='name') ],
        [ IPType, dict(name = 'IP Address', column='ip_addr') ],
        ]

import pyflag.Reports as Reports

class DNSBrowser(Reports.CaseTableReports):
    """ A list of all DNS names seen in the traffic """
    name = "Browse DNS"
    family = "Network Forensics"
    default_table = "DNSCaseTable"
    columns = ['Inode', 'DNS Name', 'IP Address']
        
import pyflag.tests as tests

import pyflag.pyflagsh as pyflagsh

class DNSTests(tests.ScannerTest):
    """ Test DNS Scanner """
    test_case = "PyFlagTestCase"
    test_file = "stdcapture_0.4.pcap.e01"
    subsystem = "EWF"
    fstype = "PCAP Filesystem"

    def test01DNS(self):
        "Test DNS handling"
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env,
                             command="scan",
                             argv=["*",                   ## Inodes (All)
                                   "DNSScanner",
                                   ])                   ## List of Scanners
        dbh = DB.DBO(self.test_case)
        dbh.execute("select * from dns where name = 'www.google.com.'")
        self.assert_(dbh.fetch())
        dbh.execute("select count(*) as c from dns where name like '%google%'")
        row = dbh.fetch()
        self.assertEqual(row['c'], 14)
    
if __name__=='__main__':
    test_str = 'Q\xcf\x81\x80\x00\x01\x00\x03\x00\x06\x00\x06\x04mail\x06google\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x001\x00\x0f\ngooglemail\x01l\xc0\x11\xc0-\x00\x01\x00\x01\x00\x00\x01\x1e\x00\x04B\xf9S\x13\xc0-\x00\x01\x00\x01\x00\x00\x01\x1e\x00\x04B\xf9SS\xc08\x00\x02\x00\x01\x00\x01\x03\xee\x00\x04\x01e\xc08\xc08\x00\x02\x00\x01\x00\x01\x03\xee\x00\x04\x01g\xc08\xc08\x00\x02\x00\x01\x00\x01\x03\xee\x00\x04\x01a\xc08\xc08\x00\x02\x00\x01\x00\x01\x03\xee\x00\x04\x01b\xc08\xc08\x00\x02\x00\x01\x00\x01\x03\xee\x00\x04\x01c\xc08\xc08\x00\x02\x00\x01\x00\x01\x03\xee\x00\x04\x01d\xc08\xc0\x88\x00\x01\x00\x01\x00\x01=\xcd\x00\x04\xd8\xef5\t\xc0\x98\x00\x01\x00\x01\x00\x01=\xcd\x00\x04@\xe9\xb3\t\xc0\xa8\x00\x01\x00\x01\x00\x01=\xcd\x00\x04@\xe9\xa1\t\xc0\xb8\x00\x01\x00\x01\x00\x01=\xcd\x00\x04@\xe9\xb7\t\xc0h\x00\x01\x00\x01\x00\x01=\xcd\x00\x04Bf\x0b\t\xc0x\x00\x01\x00\x01\x00\x01=\xcd\x00\x04@\xe9\xa7\t'

    a = DNSPacket(test_str)
    print a
