/******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG  $Version: 0.78 Date: Fri Aug 19 00:47:14 EST 2005$
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
# ******************************************************/
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
    Linux Cooked capture (The Any device)
*************************************************/
struct cooked_struct {
  uint16_t packet_type;
  uint16_t link_layer_addr_type;
  uint16_t link_layer_addr_len;
  char link_layer_header[8];
  uint16_t type;
  Packet payload;
} __attribute__((packed));

#define cooked_Format q(STRUCT_SHORT, STRUCT_SHORT, STRUCT_SHORT, \
			STRUCT_ETH_ADDR, STRUCT_CHAR, STRUCT_CHAR, \
			STRUCT_SHORT)

CLASS(Cooked, Packet)
     struct cooked_struct packet;
END_CLASS

/***********************************************
    Ethernet headers
*************************************************/
struct ethernet_2_struct {
  unsigned char destination[6];
  unsigned char source[6];
  uint16_t type;
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

  /** Private derived data */
  int len;

  /* The offset in the packet where the data portion starts */
  int data_offset;

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
