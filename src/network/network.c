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
#include "network.h"
#include "misc.h"
#include "pcap.h"

/*** Packers and unpackers for ethernet mac addresses */
static int Eth2_MAC_pack(char *input, StringIO output) {
  return CALL(output, write, (char *)(input), 6);
};

static int Eth2_MAC_unpack(void *context, StringIO input, char *output) {
  if(CALL(input, read, (char *)(output), 6) < 6)
    return -1;
  return 6;
};

MODULE_INIT(network_structs) {
  Struct_Register(STRUCT_ETH_ADDR, 6,
		  Eth2_MAC_pack, Eth2_MAC_unpack);
};

/****************************************************
   Root node
*****************************************************/
int Root_Read(Packet self, StringIO input) {
  Root this=(Root)self;

  this->__super__->Read(self, input);
  
  switch(this->link_type) {
  case DLT_EN10MB:
    this->packet.eth = (Packet)CONSTRUCT(ETH_II, Packet, super.Con, self);
    return CALL(this->packet.eth, Read, input);

  case DLT_LINUX_SLL:
    this->packet.eth = (Packet)CONSTRUCT(Cooked, Packet, super.Con, self);
    return CALL(this->packet.eth, Read, input);

  default:
    DEBUG("unable to parse link type of %u\n", this->link_type);
    return -1;
  };
};

VIRTUAL(Root, Packet)
     INIT_STRUCT(packet, q(STRUCT_NULL));

     NAME_ACCESS(packet, eth, FIELD_TYPE_PACKET);

     VMETHOD(super.Read) = Root_Read;
END_VIRTUAL
/****************************************************
   Cooked headers
*****************************************************/
int Cooked_Read(Packet self, StringIO input) {
  Cooked this=(Cooked)self;
  int len;

  len=this->__super__->Read(self, input);

  switch(this->packet.type) {
  case 0x800:
    this->packet.payload = (Packet)CONSTRUCT(IP, Packet, super.Con, self);
    len += CALL(this->packet.payload, Read, input);
    break;

  default:
#ifdef __VERBOSE_DEBUG__
    DEBUG("Unknown ethernet payload type 0x%x.\n", 
	  this->packet.type);
#endif
    break;
  };

  return len;
};

VIRTUAL(Cooked,Packet)
     INIT_STRUCT(packet, cooked_Format);

     NAME_ACCESS(packet, type, FIELD_TYPE_SHORT_X);
     NAME_ACCESS(packet, payload, FIELD_TYPE_PACKET);

     VMETHOD(super.Read) = Cooked_Read;
END_VIRTUAL

/****************************************************
   Ethernet headers
*****************************************************/
int Eth2_Read(Packet self, StringIO input) {
  ETH_II this=(ETH_II)self;
  int len;

  /** Call our superclass's Read method - this will populate most of
      our own struct. 
      
      We will automatically consume as much of input as we can handle
      so far.
  */
  len=this->__super__->Read(self, input);

  /** Now depending on the ethernet type we dispatch another parser */
  switch(this->packet.type) {
  case 0x800:
    this->packet.payload = (Packet)CONSTRUCT(IP, Packet, super.Con, self);
    len += CALL(this->packet.payload, Read, input);
    break;

  default:
#ifdef __VERBOSE_DEBUG__
    DEBUG("Unknown ethernet payload type 0x%x.\n", 
	  this->packet.type);
#endif
    break;
  };

  return len;
};

VIRTUAL(ETH_II, Packet)
     INIT_STRUCT(packet, ethernet_2_Format);

     NAME_ACCESS(packet, destination, FIELD_TYPE_HEX);
     NAME_ACCESS(packet, source, FIELD_TYPE_HEX);
     NAME_ACCESS(packet, type, FIELD_TYPE_SHORT_X);
     NAME_ACCESS(packet, payload, FIELD_TYPE_PACKET);

     NAMEOF(this) = "eth";
     VMETHOD(super.Read) = Eth2_Read;
END_VIRTUAL

/****************************************************
   IP header
*****************************************************/
int IP_Read(Packet self, StringIO input) {
  IP this=(IP)self;
  int len;

  len=this->__super__->Read(self, input);

  /** Sometimes we get trailing trash at the end of a packet, since
      the dissectors which follow us would not know how long the
      packet actually is - it is up to us to set the size of it.
   */
  if(input->size > self->start + this->packet.total_length) {
    CALL(input,truncate, self->start + this->packet.total_length);
  };

  /** Now choose the dissector for the next layer */
  switch(this->packet.protocol) {
  case 0x6:
    this->packet.payload = (Packet)CONSTRUCT(TCP, Packet, super.Con, self);
    break;

  case 0x11:
    this->packet.payload = (Packet)CONSTRUCT(UDP, Packet, super.Con, self);
    break;
    
  default:
#ifdef __VERBOSE_DEBUG__
    DEBUG("Unknown IP payload type 0x%x.\n", 
	  this->packet.protocol);
#endif
    return len;
  };

  /** Now we seek to the spot in the input stream where the payload is
      supposed to start. This could be a few bytes after our current
      position in case the packet has options that we did not account
      for.
  */
  CALL(input, seek, self->start + this->packet.header_length * 4, 
       SEEK_SET);

  CALL(this->packet.payload, Read, input);

  return input->readptr - self->start;
};

VIRTUAL(IP, Packet)
     INIT_STRUCT(packet, ip_Format);

     NAME_ACCESS(packet, ttl, FIELD_TYPE_CHAR);
     NAME_ACCESS(packet, protocol, FIELD_TYPE_CHAR);
     NAME_ACCESS(packet, src, FIELD_TYPE_IP_ADDR);
     NAME_ACCESS(packet, dest, FIELD_TYPE_IP_ADDR);
     NAME_ACCESS(packet, payload, FIELD_TYPE_PACKET);

     VMETHOD(super.Read)=IP_Read;
END_VIRTUAL

/****************************************************
   TCP header
*****************************************************/
int TCP_Read(Packet self, StringIO input) {
  TCP this=(TCP)self;

  this->__super__->Read(self, input);

  this->packet.len  = this->packet.header_length * 4;

  /** Now we seek to the spot in the input stream where the data
      payload is supposed to start. This could be a few bytes after
      our current position in case the packet has options that we did
      not account for.
  */
  this->packet.data_offset = self->start + this->packet.len ;
  CALL(input, seek, this->packet.data_offset, SEEK_SET);

  /** Now populate the data payload of the tcp packet 

      NOTE: We assume the rest of the packet is all data payload (and
      there is only 1 packet in the input stream). This is not always
      true, we really need to go from the IP total length field.
  */
  this->packet.data_len = input->size - input->readptr;

  this->packet.data = talloc_memdup(self, input->data + input->readptr,
				    this->packet.data_len);
  
  return input->size - self->start;
};

VIRTUAL(TCP, Packet)
     INIT_STRUCT(packet, tcp_Format);

     NAME_ACCESS(packet, src_port, FIELD_TYPE_SHORT);
     NAME_ACCESS(packet, dest_port, FIELD_TYPE_SHORT);
     NAME_ACCESS(packet, seq, FIELD_TYPE_INT);
     NAME_ACCESS(packet, ack, FIELD_TYPE_INT);
     NAME_ACCESS(packet, len, FIELD_TYPE_INT);
     NAME_ACCESS(packet, flags, FIELD_TYPE_CHAR_X);
     NAME_ACCESS(packet, window_size, FIELD_TYPE_SHORT);
     NAME_ACCESS(packet, data_offset, FIELD_TYPE_INT);
     NAME_ACCESS(packet, data_len, FIELD_TYPE_INT);
     NAME_ACCESS_SIZE(packet, data, FIELD_TYPE_STRING, data_len);

     VMETHOD(super.Read) = TCP_Read;
END_VIRTUAL

/****************************************************
   UDP Header
*****************************************************/
int UDP_Read(Packet self, StringIO input) {
  UDP this = (UDP) self;
  int len;

  len =this->__super__->Read(self, input);

  /** UDP has no options, data starts right away. */
  this->packet.data_len = this->packet.length - len;
  this->packet.data = talloc_memdup(self, input->data + input->readptr,
				    this->packet.data_len);

  return this->packet.length;
};

VIRTUAL(UDP, Packet)
     INIT_STRUCT(packet, udp_Format);

     NAME_ACCESS(packet, src_port, FIELD_TYPE_SHORT);
     NAME_ACCESS(packet, dest_port, FIELD_TYPE_SHORT);
     NAME_ACCESS(packet, length, FIELD_TYPE_SHORT);
     NAME_ACCESS(packet, checksum, FIELD_TYPE_SHORT_X);
     NAME_ACCESS_SIZE(packet, data, FIELD_TYPE_STRING, data_len);

     VMETHOD(super.Read) = UDP_Read;
END_VIRTUAL
