#define REMOTE_VERSION 1
#include "rc4.h"
#include "pki.h"
#include "ecc.h"
#include "stringio.h"

// Some functions which should be there
uint64_t htonll(uint64_t x);
uint64_t ntohll(uint64_t x);

int read_from_network(int fd, unsigned char *buffer, unsigned int len, RC4 rc4);
int write_to_network(int fd, StringIO queue);
void queue_for_sending(StringIO queue, unsigned char *buffer, unsigned int len, RC4 rc4);
