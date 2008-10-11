#ifndef __TCP_H
#define __TCP_H
#include "network.h"
#include "pypacket.h"

// This is the reassembler configuration space.
struct reassembler_configuration_t
{
   /** If we do not see anything from a stream within this many packets
    we determine it to be dead. 
    */
   int max_packets_expired;

   /** This limits the total number of simulatneous streams we are
    tracking.
    * 
    If the number of streams is exceeded, old ones are
    purged. Whenever a stream is touched, it is considered new, but
    only if it has at least MINIMUM_STREAM_SIZE in it. (Otherwise we
    would be purged by portscans etc).
    */
   int max_number_of_streams;
   int minimum_stream_size;

   // This is the total number of packets we are willing to hold
   // onto. Any more and we need to expire packets
   int max_outstanding_skbuffs;
   
   // The following are global counters which are maintained in order
   // to keep memory usage under control
   int total_streams;
   int total_outstanding_skbuffs;

  // This is used to collect stats about the number of python
  // connection objects allocated
  long int stream_connection_objects;
} reassembler_configuration;

struct tuple4
{
  uint16_t source;
  uint16_t dest;
  uint32_t saddr;
  uint32_t daddr;
  uint32_t pad; //This pad is needed to align this struct on 64 bit
		//machines for speed.
} __attribute__((packed));


/** These are lists of packets which can not be processed just
    yet. For example if a packet is lost we must wait for the
    retransmission before we can process the following packets in the
    stream.
*/
struct skbuff {
  PyPacket *packet;
  struct list_head list;
};

enum tcp_state_t {
  PYTCP_NONE,
  PYTCP_JUST_EST,
  PYTCP_DATA,
  PYTCP_CLOSE,
  PYTCP_RESET,
  PYTCP_TIMED_OUT,
  PYTCP_DESTROY,
  // This is used to indicate the packet is not a TCP/IP packet
  PYTCP_NON_TCP,

  // This signals that this packet is retransmitted:
  PYTCP_RETRANSMISSION
};

#define TCP_FORWARD 1
#define TCP_REVERSE 0
  
/** This class holds information about each TCP Stream we find */
CLASS(TCPStream, Object)
     struct tuple4 addr;
     enum tcp_state_t state;
     struct skbuff queue;

     // This list keeps all the streams with the same hash value
     struct list_head list;

     // This is a global list of all streams. It is kept ordered by
     // use time so we can expire older connections.
     struct list_head global_list;

     TCPStream reverse;
     int con_id;
     int max_packet_id;

     /** The cache file which we write on */
     CachedWriter file;

     /** The next sequence number we expect */
     uint32_t next_seq;

     int direction;

     /** The total size of this stream */
     int total_size;

     /** This is a reference to our hash table */
     struct TCPHashTable *hash;

     TCPStream METHOD(TCPStream, Con, struct tuple4 *addr, int con_id);

     /* This is a python object which collect information about the
	stream */
     PyObject     *stream_object;

     void METHOD(TCPStream, callback, PyPacket *packet);

     /** This method is used to add an IP packet to the queue. Note
	 that its talloc reference will be stolen and on destruction
	 it will be automatically removed from the queue.
     */
     void METHOD(TCPStream, add, PyPacket *packet);
END_CLASS

/* This is a stream handler for UDP packet. Although UDP does not
   have sequence numbers its important to track UDP communications
   sometimes.
*/
CLASS(UDPStream, TCPStream)
END_CLASS

/** The loading factor for the hash table */
#define TCP_STREAM_TABLE_SIZE 256

#include "reassembler.h"

/** This class manages a bunch of TCPStreams in a hash_table */
CLASS(TCPHashTable, Object)
     TCPStream table[TCP_STREAM_TABLE_SIZE];

     /** This list keeps all streams in sorted order */
     TCPStream sorted;

     /** This is the con_id pool that will be used. Numbers will start
	 at this number and increment by 1 for each new
	 connection. Our python handler needs to initialise this pool
	 and we hope that we do not run out. The con_ids will end up
	 in the db and might collide with other numbers.
     */
     int con_id;

     void (*callback)(TCPStream self, PyPacket *packet);

     // This is a reference to the main reassembler object:
     Reassembler *reassembler;

     // A running tally
     int packets_processed;

     TCPHashTable METHOD(TCPHashTable, Con, int initial_con_id);

     /** This method returns a valid TCPStream to match the IP packet from
	 the hash table. 
     */
     TCPStream    METHOD(TCPHashTable, find_stream, IP ip);

     /** Process the ip packet */
     int          METHOD(TCPHashTable, process, PyPacket *packet);
     void         METHOD(TCPHashTable, flush);
END_CLASS

/** Given a packet finds the corresponding stream - or if one does not
    exist, we create it here.
*/
TCPStream find_stream(IP packet);

int process_tcp(IP packet);

#endif
