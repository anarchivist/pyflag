/*********************************************************************
    This file defines a number of classes for parsing network packets
    of various types.
**********************************************************************/
#include "packet.h"
#include "misc.h"

/************************************************
    Needed packers and unpackers
*************************************************/

#define STRUCT_ETH_ADDR 10

/***********************************************
    The Root node.

    The Root node has placeholders for all types of possible link
    layers. This allows us to access the link layers by name like
    eth.src for example.
*************************************************/
struct root_node_struct {
  Packet eth;
} __attribute__((packed));

CLASS(Root, Packet)
     struct root_node_struct packet;
     int link_type;
END_CLASS

/***********************************************
    Ethernet headers
*************************************************/
struct ethernet_2_struct {
  unsigned char destination[6];
  unsigned char source[6];
  int type;
  Packet payload;
}  __attribute__((packed));

#define ethernet_2_Format q(STRUCT_ETH_ADDR, STRUCT_ETH_ADDR, STRUCT_SHORT);

CLASS(ETH_II, Packet)
     struct ethernet_2_struct packet;
END_CLASS

/***********************************************
    IP headers
*************************************************/
struct ip_struct {

#ifdef LE
  char header_length:4;
  char version:4;
#else
  char version:4;
  char header_length:4;
#endif

  uint8_t dsf;
  uint16_t total_length;
  uint16_t id;

#ifdef LE
  uint16_t fragment_offset:13;
  uint16_t flags_mf:1;  
  uint16_t flags_df:1;
  uint16_t flags_res:1;
#else
  uint16_t flags_res:1;
  uint16_t flags_df:1;
  uint16_t flags_mf:1;  
  uint16_t fragment_offset:13;
#endif  

  uint8_t ttl;
  uint8_t protocol;

  uint16_t checksum;
  uint32_t src;
  uint32_t dest;

  Packet payload;
};

#define ip_Format q(STRUCT_CHAR, STRUCT_CHAR, STRUCT_SHORT, STRUCT_SHORT, \
		    STRUCT_SHORT, STRUCT_CHAR, STRUCT_CHAR, STRUCT_SHORT, \
		    STRUCT_INT, STRUCT_INT)

CLASS(IP, Packet)
     struct ip_struct packet;
END_CLASS

/***********************************************
    TCP headers
*************************************************/
struct tcp_struct {
  uint16_t src_port;
  uint16_t dest_port;
  uint32_t seq;
  uint32_t ack;

#ifdef LE
  uint8_t packing:4;
#endif
  uint8_t header_length:4;

  uint8_t flags;
  uint16_t window_size;
  uint16_t checksum;

  /** The payload data portion */
  int data_len;
  char *data;
} __attribute__((packed));

#define tcp_Format q(STRUCT_SHORT, STRUCT_SHORT, STRUCT_INT, STRUCT_INT, \
		     STRUCT_CHAR, STRUCT_CHAR, STRUCT_SHORT, STRUCT_SHORT)

CLASS(TCP, Packet)
     struct tcp_struct packet;
END_CLASS

/***********************************************
    UDP headers
*************************************************/
struct udp_struct {
  uint16_t src_port;
  uint16_t dest_port;
  uint16_t length;
  uint16_t checksum;

  int data_len;
  char *data;
};

#define udp_Format q(STRUCT_SHORT, STRUCT_SHORT,	\
		     STRUCT_SHORT, STRUCT_SHORT)

CLASS(UDP, Packet)
     struct udp_struct packet;
END_CLASS
