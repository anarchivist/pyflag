#ifndef _COMPRESSED_LOOP_H
#define _COMPRESSED_LOOP_H
#define INDEX_MAGIC "sgzidx"
#define SGZ_MAGIC "sgz"
#define CLOOP_HEADROOM 128

/* The cloop header usually looks like this:          */
/* #!/bin/sh                                          */
/* #V2.00 Format                                      */
/* ...padding up to CLOOP_HEADROOM...                 */
/* block_size (32bit number, network order)           */
/* num_blocks (32bit number, network order)           */

struct cloop_head
{
  char magic[3];
  unsigned int block_size;
  union {
    char compression[4];
    long int num_blocks;
  } x;
}  __attribute__((packed));

/* data_index (num_blocks 64bit pointers, network order)...      */
/* compressed data (gzip block compressed format)...             */

#endif /*_COMPRESSED_LOOP_H*/
