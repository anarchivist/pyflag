#include <stdio.h>
#include <stdlib.h>
#include <zlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdarg.h>
#include "except.h"
#include "global.h"
#include "md5.h"
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* 
 The multicaster imaging tool allows imaging over IP multicasting. The
 protocol features error correction, retransission and packet signing
 to ensure data integrity.

 This is useful for imaging a single machine onto many client machines
 at the same time. This program was first developed in order to image
 classrooms full of computers at once, whilest it is possible to image
 machines over the network using netcat in TCP point to point mode,
 this solution does not scale. The multicaster imaging tool allows to
 image a virtually unlimited number of clients off the same server
 without loss of bandwidth.

 This is the basic protocol:

 Server: 

   Listens on UDP port (6666 by default) for transmission request
   packets.  Transmit on to 239.1.1.1 multicast address to UDP port
   6667, data packets.

 Client:

   Listen on the multicast IP for data packets, when the transmission
   begins keeps a buffer of missing packets and periodically send the
   list of missing blocks to the server in a transmission request
   packet.

 There are 2 types of packets: A transmission request packet and data
 packets. Both are UDP packets with the following contents in the data
 payload:
*/
struct transmission_request {
  unsigned char type;
  unsigned short int block_size;
  unsigned short int number_of_blocks;
  unsigned int blocks[256];
}  __attribute__((packed));

/*
 The type field should be set to 'r' for retransmission requests.

 Where block_size represents the block_size in bytes. The block size
 is determined by the server when initialising the transmission. Note
 that each block is carried by exactly one UDP packet, hence the
 largest practical block size is around 1500 bytes without
 fragmentation.

 If the client requests a different block size, the request is
 ignored.

 Follows is the number of blocks and a list of blocks that are
 missing. The list should contain all missing blocks from 0 until the
 largest received block id.

 Note that using this protocol the client may only request up to 256
 outstanding blocks, however the client may choose to queue more
 blocks then this and request those at a later stage.

 The servers data packets have the following payload:
*/
struct data_header {
  unsigned char type;
  unsigned short int block_size;
  unsigned short int length;
  unsigned int block_id;
}  __attribute__((packed));

/* 
 This is then followed by data and a 16 byte md5 sum of the
 packet. The md5 sum is derived by appending the packet payload to a
 shared secret hash and performing an md5 sum over the data. If a
 client receives a packet which does not pass the md5 check, the
 packet is ignored.
   
*/

extern int errno;

void send_packet( unsigned short int block_size, unsigned int block_id,
		  char *data, int length, char type,int out_fd,char *key) ;

#define MAX_BLOCKSIZE 65535

/* Receives a packet from a UDP socket. Checks the packet integrity by appending the key to it and taking the md5 sum, and comparing with the supplied MD5:

block_size  - the blocksize of the returned packet. If block_size == 0, it gets
   set to the new block_size. The block_size must remain constant for
   the entire connection duration.  

block_id - The block id of this packet.

data - A buffer that will be filled with the incoming data. This must be
   at least as large as block_size or, if block_size ==0,
   MAX_BLOCKSIZE

type - The type of this packet.

in_fd - bound fd to read from.

key - a HASHSIZE long char * array containing the key to use.

Note that this function will block until data is available from fd.
Raises E_IOERROR if there is anything wrong with the packet.
*/
int recv_packet(unsigned short int  *block_size, unsigned int *block_id,
		char **from,
		char *data,unsigned short int *data_length, 
		char *type, int in_fd, char *key);

/* Returns a connected UDP socket to the multicast group */
int connect_socket(char *addr, unsigned int port,int multicast);

/* Bind a listening socket for data connections */
int bind_socket(unsigned int port,char * multicast);

#define KEY "this is a secret key"
#define BLOCKSIZE 3000
#define OUTSTANDING_SIZE 1000

struct config_t {
  char *in_filename;
  char *out_filename;
  int server_listening_port;
  int client_listening_port;
  char *multicast_addr;
  char *server_addr;
  char *prefered_interface;
  int blocksize;
  char *key;
  //usec to wait between each packet
  int timeout;
};

#define VERSION "0.1"

char *md5sum(char *key);
void add_to_outstanding(int *outstanding,int number);
