/*
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.75 Date: Sat Feb 12 14:00:04 EST 2005$
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
int evf_read_random(char *buf, int len, unsigned long long int offs,
		    const struct offset_table *offsets);
void evf_compress_fds(int chunk_size,int infd, char *filename,int size);
int advance_stream(int fd, int length);
int read_from_stream(int fd,void *buf,int length);
