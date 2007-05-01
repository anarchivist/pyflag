/** This is a very abridged pcap header file for use within pyflag.

We only need a couple of things so we just have them here to avoid a
dependancy on libpcap. (We dont actually link against it). */
#ifndef __PCAP_H
#define __PCAP_H

#include <sys/types.h>
#include <stdint.h>
#include "network.h"

#define DLT_NULL	0	/* BSD loopback encapsulation */
#define DLT_EN10MB	1	/* Ethernet (10Mb) */
#define DLT_EN3MB	2	/* Experimental Ethernet (3Mb) */
#define DLT_AX25	3	/* Amateur Radio AX.25 */#define DLT_PRONET	4	/* Proteon ProNET Token Ring */
#define DLT_CHAOS	5	/* Chaos */
#define DLT_IEEE802	6	/* IEEE 802 Networks */
#define DLT_ARCNET	7	/* ARCNET, with BSD-style header */
#define DLT_SLIP	8	/* Serial Line IP */
#define DLT_PPP		9	/* Point-to-point Protocol */
#define DLT_FDDI	10	/* FDDI */

#define DLT_LINUX_SLL	113

struct pcap_file_header {
  uint32_t magic;
  uint16_t version_major;
  uint16_t version_minor;
  uint32_t thiszone;	/* gmt to local correction */
  uint32_t sigfigs;	/* accuracy of timestamps */
  uint32_t snaplen;	/* max length saved portion of each pkt */
  uint32_t linktype;	/* data link type (LINKTYPE_*) */
} __attribute__((packed));

//Pcap files may come in little endian format or the more correct big
//endian:
#define PCAP_HEADER_STRUCT q(STRUCT_INT, STRUCT_SHORT, STRUCT_SHORT,	\
			     STRUCT_INT, STRUCT_INT, STRUCT_INT, STRUCT_INT)

#define PCAP_HEADER_STRUCT_LE q(STRUCT_INT_LE, STRUCT_SHORT_LE, STRUCT_SHORT_LE, \
				STRUCT_INT_LE, STRUCT_INT_LE, STRUCT_INT_LE, STRUCT_INT_LE)

struct pcap_pkthdr {
  uint32_t ts_sec;	/* time stamp */
  uint32_t ts_usec;
  uint32_t caplen;	/* length of portion present */
  uint32_t len;	/* length this packet (off wire) */
  char *data;

  uint32_t offset;
  // This holds the dissected tree
  Root root;
} __attribute__((packed));

#define PCAP_PKTHEADER_STRUCT q(STRUCT_INT, STRUCT_INT, STRUCT_INT,	\
				STRUCT_STRING_AND_LENGTH32)

#define PCAP_PKTHEADER_STRUCT_LE q(STRUCT_INT_LE, STRUCT_INT_LE,	\
				   STRUCT_INT_LE, STRUCT_STRING_AND_LENGTHLE32)

/** These are serializers and unserializers for packets */
#include "packet.h"

CLASS(PcapFileHeader, Packet)
     struct pcap_file_header header;

     // A flag to indicate our endianess:
     int little_endian;
     char *le_format;

     // The offset into the pcap file of this packet
     unsigned long long int pcap_offset;
END_CLASS

CLASS(PcapPacketHeader, Packet)
     struct pcap_pkthdr header;
     int little_endian;
     char *le_format;
END_CLASS

#endif
