/*
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.80.1 Date: Tue Jan 24 13:51:25 NZDT 2006$
# ******************************************************

This library was relicensed on the 5th March 2006 to the modified BSD
licence.  This allows this library to be used in commercial
applications, and other OSS projects using the BSD license. This move
was done in order to try and create a freely available codebase for
applications that need to be able to read encase file format. The
proprietary Encase file format is currently an impediment to forensics
application compatibility and openness in judicial
processes. Hopefully the release of this library can serve to help in
removing this impediment. Note that the rest of PyFlag is still
released under the GPL, the BSD license only applies to this library.

Modified BSD License:

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
   3. The name of the author may not be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# ******************************************************
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdarg.h>

extern void evf_warn(const char *message, ...);

struct evf_file_header {
  char magic[8];
  char one;
  unsigned short int segment;
  unsigned short int zero;
} __attribute__((packed));

struct evf_section_header {
  char type[16];
  unsigned long long next;
  unsigned long long size;
  char padding[40];
  unsigned int crc;
} __attribute__((packed));

struct evf_volume_header {
  unsigned int reserved;
  unsigned int chunk_count;
  unsigned int sectors_per_chunk;
  unsigned int bytes_per_sector;
  unsigned int sector_count;
  char reserved2[20];
  char padding[1003];
  char signature[5];
  unsigned int crc;
}  __attribute__((packed));

struct evf_table_header {
  unsigned int count;
  char padding[16];
  unsigned int crc;
}  __attribute__((packed));

struct evf_hash {
  char md5[16];
  unsigned int zero;
  unsigned int unknown;
  unsigned int zero2;
  unsigned int unknown2;
}  __attribute__((packed));

/* This is a linked list keeping track of all sections, their start
   and end offsets within the fd. We need this to figure out the size
   of the last chunk in each section table */
struct section {
  int fd;
  unsigned long int start_offset;
  unsigned long int end_offset;
  struct section *next;
};

/* This struct stores information about the index */
struct offset_table {
  int chunk_size;
  /* Keep information on all the sections */
  struct section *section_list;
  int max_chunk;
  /* Stores the maximum number of segments */
  unsigned short int max_segment;
  /*An array that keeps track of open fds in their segment order */
  int *files;
  /* An array (same size as offset) of file descriptor into the
     correct file, must already be opened by initialiser */
  int *fd;
  /* array of offsets within the file pointed to by fd */
  unsigned int *offset;
  /* Array of chunk sizes */
  unsigned short int *size;
  char md5[16];
};

/* A fatal error occured */
void die(const char *message, ...);

/* A nonfatal error occured */
void warn(const char *message, ...);

struct evf_file_header *evf_read_header(int fd);
struct evf_section_header *evf_read_section(int fd);
void process_section(struct evf_section_header *header,
		     int image_number,struct offset_table *offsets);
void evf_decompress_fds(struct offset_table *offsets,int outfd);
void evf_printable_md5(char *md5,char *data);
int evf_read_random(char *buf, int len, unsigned long long int offs,
		    const struct offset_table *offsets);
void evf_compress_fds(int chunk_size,int infd, char *filename,int size);
int advance_stream(int fd, int length);
int read_from_stream(int fd,void *buf,int length);
