#ifndef __TCP_H
#define __TCP_H
#include "network.h"

/** If we do not see anything from a stream within this many packets
    we determine it to be dead. 
*/
#define MAX_PACKETS_EXPIRED 10000

/** This limits the total number of simulatneous streams we are
    tracking.

    If the number of streams is exceeded, old ones are
    purged. Whenever a stream is touched, it is considered new, but
    only if it has at least MINIMUM_STREAM_SIZE in it. (Otherwise we
    would be purged by portscans etc).
*/
#define MAX_NUMBER_OF_STREAMS 1000
#define MINIMUM_STREAM_SIZE 100

struct tuple4
{
  uint16_t source;
  uint16_t dest;
  uint32_t saddr;
  uint32_t daddr;
} __attribute__((packed));


/** These are lists of packets which can not be processed just
    yet. For example if a packet is lost we must wait for the
    retransmission before we can process the following packets in the
    stream.
*/
struct skbuff {
  IP packet;
  // This is an arbitrary object which is passed to the callback
  // together with the packet. We get the object when we first add the
  // packet to the hash table. Note that we do not increase nor
  // decrease its reference count (because we have no idea what it is)
  // so callers to add need to increase its ref count and the callback
  // implemented needs to decrease it. Make sure it doesnt get freed
  // from under us. It can be NULL if there is no interesting use for
  // it.
  void *object;
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

     TCPStream METHOD(TCPStream, Con, struct tuple4 *addr, int con_id);

     /** An opaque data to go with the callack */
     void *data;
     void METHOD(TCPStream, callback, IP ip, void *object);

     /** This method is used to add an IP packet to the queue. Note
	 that its talloc reference will be stolen and on destruction
	 it will be automatically removed from the queue.
     */
void METHOD(TCPStream, add, IP packet, void *object);
END_CLASS

/** The loading factor for the hash table */
#define TCP_STREAM_TABLE_SIZE 256

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

     /** This is the callback which will be invoked upon processing
	 packets
     */
     void (*callback)(TCPStream self, IP ip, void *object);
     void *data;
     int packets_processed;

     TCPHashTable METHOD(TCPHashTable, Con, int initial_con_id);

     /** This method returns a valid TCPStream to match the IP packet from
	 the hash table. 
     */
     TCPStream    METHOD(TCPHashTable, find_stream, IP ip);

     /** Process the ip packet */
     int          METHOD(TCPHashTable, process, IP ip, void *object);
END_CLASS

/** Given a packet finds the corresponding stream - or if one does not
    exist, we create it here.
*/
TCPStream find_stream(IP packet);

int process_tcp(IP packet);

#endif
