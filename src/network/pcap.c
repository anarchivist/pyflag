/** This implements a packet interface to pcap files */
#include "pcap.h"
#include "packet.h"

// Depending on the pcap magic we need to adjust our endianess.
int PcapFileHeader_Read(Packet self, StringIO input) {
  PcapFileHeader this = (PcapFileHeader)self;
  int len;

  // We start off trying to read the header as big endian
  len = this->__super__->Read(self, input);

  // This is little endian:
  if(this->header.magic == 0xD4C3B2A1) {
    this->little_endian = 1;

    // Readjust the format string to little_endian:
    self->format = this->le_format;

    // Rewind the stream:
    CALL(input, seek, 0, 0);

    // Reread the data:
    len = this->__super__->Read(self,input);
  };

  return len;
};

VIRTUAL(PcapFileHeader, Packet)
     INIT_STRUCT(header, PCAP_HEADER_STRUCT);

     SET_DOCSTRING("PCap file header");
     NAME_ACCESS(header, linktype, linktype, FIELD_TYPE_INT);
     NAME_ACCESS(header, snaplen, snaplen, FIELD_TYPE_INT);

     VMETHOD(super.Read) = PcapFileHeader_Read;
     VATTR(le_format) = PCAP_HEADER_STRUCT_LE;
END_VIRTUAL

VIRTUAL(PcapPacketHeader, Packet)
     INIT_STRUCT(header, PCAP_PKTHEADER_STRUCT);

     SET_DOCSTRING("Pcap packet header");
     NAME_ACCESS(header, ts_sec, ts_sec, FIELD_TYPE_INT);
     NAME_ACCESS(header, ts_usec, ts_usec, FIELD_TYPE_INT);
     NAME_ACCESS(header, caplen, caplen, FIELD_TYPE_INT);
     NAME_ACCESS(header, offset, offset, FIELD_TYPE_INT);
     NAME_ACCESS_SIZE(header, data, data, FIELD_TYPE_STRING, len);

     VATTR(le_format) = PCAP_PKTHEADER_STRUCT_LE;
END_VIRTUAL
