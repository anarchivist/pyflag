/*
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.84RC4 Date: Wed May 30 20:48:31 EST 2007$
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
# ******************************************************
*/

/*** This is a remote servlet to run a remote system. It listens on a
     given port for an authenticated connection from the pyflag remote
     client. Once an authenticated connection is made, this servlet
     allows access to the machines physical devices so that remote
     forensic analysis may be carried out.

     Authentication:
     ===============
     The server uses ECC (NIST Curve 163) for authentication. ECC is
     the modern PKI standard (standardised by NIST). ECC is considered
     to provide very strong security for smaller number of bits. For
     example, a 160bit eliptic curve is roughly equivalent to 1024 bit
     RSA exchange.

     The protocol used within PyFlag is very simple (all bytes are
     sent using big endian):

     1) The client connects over a tcp/ip socket and writes a
     challenge. The challenge is obtained by hashing a 128 bit session
     key with the ECC Public key. The rest of the packet is encrypted
     using this session key with the RC4 algorithm.

     2) The client writes the initial handshake packet (which is
     encrypted using the session key). The packet is:

     // Connection packet:
     SIZEOF_CHALLENGE challenge;

     // Rest of packet is encrypted using RC4. The same RC4 stream is
     // used to encrypt all further communications to the server.
     int version;
     int length;
     char named_device;
     
     3) The server accepts the information and decrypts the handshake
     packet. If the protocol version is supported, the named device is
     opened and the server moves into the ready state.

     4) The client writes request packets in the following format:

     uint64_t offset
     uint32_t size

     5) The server reponds by:

     uint32_t size
     char data[]

     Both sides initialise their own RC4 streams using the secret key,
     and use the same stream throughout the connection.
 */
#include "remote.h"
#include "except.h"
#include <sys/socket.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

void usage(char **argv) {
  printf("%s [options]\n"
	 "-p\t\tport to listen on (3533 by default)\n"
	 "-s\t\tsingle mode - dont fork, exit after servicing a single connection\n"
	 ,argv[0]);
  exit(0);
};

/** This function handles a single connection */
void handle_connection(int fd) {
  unsigned char key[16];
  char challenge[SIZEOF_CHALLENGE];
  int len;
  int version;
  int length;
  char *filename;
  int target_fd;
  uint32_t calculated_length;
  RC4 rc4;
  uint64_t image_size;
  StringIO queue;

  // Read the challenge:
  len = read(fd, challenge, SIZEOF_CHALLENGE);
  if(len < SIZEOF_CHALLENGE) {
    DEBUG("Unable to read challenge from socket\n");
    return;
  };

  // Try to calculate the session key from this:
  if(!ecc_get_key((char *)key, challenge, Priv)) {
    DEBUG("Unable to decode challenge\n");
    return;
  };
  
  // Prepare the key:
  rc4 = CONSTRUCT(RC4, RC4, Con, NULL, key, sizeof(key));
  queue = CONSTRUCT(StringIO, StringIO, Con, rc4);

  if(!read_from_network(fd, (unsigned char *)&version, sizeof(version), rc4)) {
    DEBUG("Cant read version\n");
    return;
  };
  version = ntohl(version);

  if(version != REMOTE_VERSION) {
    DEBUG("Client version not supported\n");
    return;
  };
  
  if(!read_from_network(fd, (unsigned char *)&length, sizeof(length), rc4))
    return;

  length = ntohl(length);

  // Make sure the filename is not too large
  if(length > 1024) return;

  filename = talloc_zero_size(NULL, length+1);
  if(!read_from_network(fd, (unsigned char *)filename, length, rc4))
    return;

  target_fd = open(filename, O_RDONLY);
  if(target_fd < 0) {
    DEBUG("Cant open %s..\n", filename);
    return;
  };

  //Figure out the image size:
  image_size = lseek(target_fd, 0, SEEK_END);

  while(1) {
    uint64_t offset;
    uint32_t length;
    char buff[BUFF_SIZE];

    if(!read_from_network(fd, (unsigned char *)&offset, sizeof(offset), rc4))
      return;

    offset = ntohll(offset);

    if(!read_from_network(fd, (unsigned char *)&length, sizeof(length), rc4))
      return;

    length = ntohl(length);

    // Send out the total length of the data - which may be less than
    // requested if the image is smaller
    {
      uint32_t c_calc_len;

      calculated_length = min(image_size, offset+length) - offset;
      c_calc_len = htonl(calculated_length);
      queue_for_sending(queue, (unsigned char *)&c_calc_len, sizeof(c_calc_len), rc4);
    };

    if(lseek(target_fd, offset, SEEK_SET) != offset) {
      DEBUG("Unable to seek to %llu\n", offset);
      return;
    };

    //DEBUG("Will need to read %u from %llu\n", calculated_length, offset);

    while(calculated_length > 0) {
      int l = read(target_fd, buff, min(calculated_length, BUFF_SIZE));
      if(l==0) {
	break;
      };
      if(l<0) return;

      queue_for_sending(queue, (unsigned char *)buff, l, rc4);

      // If the queue is too full, we need to flush it
      if(queue->size > 64000)
	if(!write_to_network(fd, queue))
	  return;

      calculated_length -= l;
    };

    if(!write_to_network(fd, queue))
      return;
  };
};

int main(int argc, char **argv) {
  int fd,port=3533, infd, pid;
  struct sockaddr_in s;
  socklen_t size = sizeof(s);
  int c;
  // Set is set for single shot mode - no forking is performed
  int single = 0;

  ecc_init();
 
  while (1) {
    int option_index = 0;
    static struct option long_options[] = {
      {"port", 1, 0, 'p'},
      {"single", 0, 0, 's'},
      {"help", 0, 0, 'h'},
      {0, 0, 0, 0}
    };

    c = getopt_long (argc, argv, "p:hs",
		     long_options, &option_index);
    if(c==-1) break;

    switch (c) {
      // We need to save the results to a file:
    case 'p': {
      port = atoi(optarg);
      break;
    };
    case 's':
      single = 1;
      break;

    case 'h':
    default:
      usage(argv);
    };
  };


  fd = socket (PF_INET, SOCK_STREAM, 0);
  if(fd<0) {
    RAISE(E_IOERROR,NULL,"Cant create socket");
  };

  if(setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &s, sizeof (s))<0) 
    RAISE(E_IOERROR,NULL,"Set Sockopt failed");
  
  s.sin_family=AF_INET;
  s.sin_addr.s_addr=INADDR_ANY;
  s.sin_port=htons(port);
  
  if(bind(fd,(struct sockaddr *)&s,sizeof(s))<0)
    RAISE(E_IOERROR,NULL,"Unable to bind to port %u",port);
  
  if(listen(fd,1)<0) RAISE(E_IOERROR,NULL,"Unable to listen");
  
  while(1) {
    infd=accept(fd,(struct sockaddr *)&s,&size);
    // Handle a single connection and then quit
    if(single) {
      handle_connection(infd);
      exit(0);
    };

    pid=fork();
    
    // Child handles the connection
    if(!pid) {
      handle_connection(infd);
      exit(0);
    };
  };

  return 0;
}
