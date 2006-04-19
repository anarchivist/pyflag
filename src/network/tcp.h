#ifndef __TCP_H
#define __TCP_H
#include "network.h"

struct tuple4
{
  uint16_t source;
  uint16_t dest;
  uint32_t saddr;
  uint32_t daddr;
};


/** These are lists of packets which can not be processed just
    yet. For example if a packet is lost we must wait for the
    retransmission before we can process the following packets in the
    stream.
*/
struct skbuff {
     IP packet;
     struct list_head list;
};

enum tcp_state_t {
  PYTCP_NONE,
  PYTCP_JUST_EST,
  PYTCP_DATA,
  PYTCP_CLOSE,
  PYTCP_RESET,
  PYTCP_TIMED_OUT,
  PYTCP_DESTROY
};
  
/** This class holds information about each TCP Stream we find */
CLASS(TCPStream, Object)
     struct tuple4 addr;
     enum tcp_state_t state;
     struct skbuff queue;
     struct list_head list;
     TCPStream reverse;
     int id;

     /** The next sequence number we expect */
     uint32_t next_seq;

     TCPStream METHOD(TCPStream, Con, struct tuple4 *addr);

     /** An opaque data to go with the callack */
     void *data;
     void METHOD(TCPStream, callback, IP ip);

     /** This method is used to add an IP packet to the queue. Note
	 that its talloc reference will be stolen and on destruction
	 it will be automatically removed from the queue.
     */
     void METHOD(TCPStream, add, IP packet);
     void METHOD(TCPStream, flush);
END_CLASS

/** The loading factor for the hash table */
#define TCP_STREAM_TABLE_SIZE 256

/** This class manages a bunch of TCPStreams in a hash_table */
CLASS(TCPHashTable, Object)
     TCPStream table[TCP_STREAM_TABLE_SIZE];

     /** This is the callback which will be invoked upon processing
	 packets
     */
     void (*callback)(TCPStream self, IP ip);
     void *data;

     TCPHashTable METHOD(TCPHashTable, Con);

     /** This method returns a valid TCPStream to match the IP packet from
	 the hash table. 
     */
     TCPStream    METHOD(TCPHashTable, find_stream, IP ip);

     /** Process the ip packet */
     int METHOD(TCPHashTable, process, IP ip);
END_CLASS

/** Given a packet finds the corresponding stream - or if one does not
    exist, we create it here.
*/
TCPStream find_stream(IP packet);

int process_tcp(IP packet);

#endif
