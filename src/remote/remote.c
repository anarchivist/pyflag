#include "remote.h"
#include "stringio.h"

uint64_t htonll(uint64_t x) {
  uint32_t left = x >> 32;
  uint64_t right = htonl(x);

  return htonl(left) | (right << 32);
};

uint64_t ntohll(uint64_t x) {
  uint32_t left = x >> 32;
  
  uint64_t right = ntohl(x);

  return ntohl(left) | (right << 32);
};

/* This reads the required amount of data from the network and then
   decrypts it using rc4. We do not return until we have the required
   length or an error occurs.

   Return the length read or 0 for error.
 */
int read_from_network(int fd, unsigned char *buffer, unsigned int len, RC4 rc4) {
  unsigned int i=0;

  //DEBUG("reading %u bytes\n", len);

  while(i<len) {
    int l = recv(fd, buffer+i, len-i, MSG_WAITALL);
    
    if(l<=0) return 0;
    i+=l;
  };

  // Decrpyt the data:
  CALL(rc4, crypt, buffer, len);

  return len;
};

void queue_for_sending(StringIO queue, unsigned char *original_buffer, unsigned int len, RC4 rc4) {
  char buffer[len];

  // Make a local copy of the buffer.
  memcpy(buffer, original_buffer, len);

  // Encrypt the data:
  CALL(rc4, crypt, buffer, len);

  CALL(queue, write, buffer, len);
};

// Note that we do not modify our buffers here
int write_to_network(int fd, StringIO queue) {
  int len = queue->size;
  int i=0;

  //  DEBUG("writing %u bytes\n", len);

  while(i<len) {
    int l = send(fd, queue->data+i, len-i, MSG_NOSIGNAL);
    
    if(l<=0) return 0;
    i+=l;
  };

  CALL(queue, truncate, 0);
  return len;
};
