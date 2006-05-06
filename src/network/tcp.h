#ifndef __TCP_H
#define __TCP_H
#include "network.h"

/************************************************************
    DiskStreamIO is a class which makes it easy and efficient to write
    numerous files concurrently.

The problem with the stream reassembler is that we need to keep track
of many streams simultaneously. Each stream is written to its own
cache file, however, data is appended to each file in small chunks
(often up to a byte at the time).

It is prohibitive to reopen each stream file, append a small amount of
data, and close it. Due to the number of concurrent streams it is
impossible to keep all the files open at the same time (because we
will run out of file descriptors).

This class manages a stream in memory. When the stream becomes too
large, we flush the data to disk. This allows us to have numerous
pending streams open without running out of file descriptors.
***************************************************************/
  /** The maximum size to remain buffered */
#define MAX_DISK_STREAM_SIZE 4096

CLASS(DiskStreamIO, StringIO)
     char *filename;

     /** Total number of bytes written to the file so far */
     int written;

     DiskStreamIO METHOD(DiskStreamIO, Con, char *filename);
     int METHOD(DiskStreamIO, get_offset);
END_CLASS

/** If we do not see anything from a stream within this many packets
    we determine it to be dead. 
*/
#define MAX_PACKETS_EXPIRED 10000

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
  Root root;
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
     struct list_head list;
     TCPStream reverse;
     int con_id;
     int max_packet_id;

     /** The cache file which we write on */
     DiskStreamIO file;

     /** The next sequence number we expect */
     uint32_t next_seq;

     int direction;

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
     int packets_processed;

     TCPHashTable METHOD(TCPHashTable, Con);

     /** This method returns a valid TCPStream to match the IP packet from
	 the hash table. 
     */
     TCPStream    METHOD(TCPHashTable, find_stream, IP ip);

     /** Process the ip packet */
     int          METHOD(TCPHashTable, process, IP ip);
END_CLASS

/** Given a packet finds the corresponding stream - or if one does not
    exist, we create it here.
*/
TCPStream find_stream(IP packet);

int process_tcp(IP packet);

#endif
