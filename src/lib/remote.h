/*
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.80.1 Date: Tue Jan 24 13:51:25 NZDT 2006$
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

#ifdef CYGWIN
#include <winsock.h>
#else
#include <sys/socket.h>
#endif

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
void remote_read_data(struct remote_handle *hndle, uint64_t offset, char **data, uint32_t *length);

