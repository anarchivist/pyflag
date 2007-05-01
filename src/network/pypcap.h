#ifndef _PYPCAP_H
#define _PYPCAP_H

typedef struct {
  PyObject_HEAD

  // A buffer to be used to read from:
  StringIO buffer;

  // A python file like object - we only care that it has a read
  // method. We use the read method to repeatadely fill the buffer
  // with large chunks.
  PyObject *fd;

  // The file header:
  PcapFileHeader file_header;
  PcapPacketHeader packet_header;
  StringIO dissection_buffer;

  // Default id to use for newly dissected packets:
  int packet_id;
  uint32_t pcap_offset;
} PyPCAP;


#define FILL_SIZE (1024 * 100)
#define MAX_PACKET_SIZE (2 * 1024)

#endif
