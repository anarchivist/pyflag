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
