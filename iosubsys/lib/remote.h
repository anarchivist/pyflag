#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include "except.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/wait.h>

#define BUFFERSIZE 1024

struct remote_handle {
  int paircs[2];
  int pairsc[2];
  int pid;
  int port;
  char *host;
};

//Opens a connection to the server, and initialises the sockets
void remote_open_server(struct remote_handle *hndle,char **argv);

//Returns the response from the server.  Buffer returned is malloced
//and should be freed by the caller.
void remote_read_response(struct remote_handle *hndle,char **buf,int *length);

/* Read data from server by issuing read requests:
   offset - The offset in the remote device to seek to
   data - A variable to hold the malloced buffer. Note that callers are expected to free it.
   length - The length of data to read. The variable is adjusted for the length actually read.
*/
void remote_read_data(struct remote_handle *hndle, long long unsigned int offset, char **data, unsigned int *length);

