/*************************************************
         sgzlib - A seekable Gzip file format

   Author:         Michael Cohen (scudette@users.sourceforge.net)
   Version: 0.1   
   Copyright (2004).

   This library provides a unified interface for access and creation
   of sgzip files. sgzip files are files based on the gzip compression
   library which are also quickly seekable and therefore may be used
   for applications where seeking is important. Description of this
   library follows.

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.
                                                                                          
   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
                                                                                          
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
   USA

   Implementation notes:
   ----------------------------

   The sgzip file format basically relies on breaking the file into
   blocks, each of these blocks is compressed seperately (which
   results in a slight decrease of compression for small blocks). The
   file then stores these blocks in the compressed file. Just before
   each compressed block, an offset is stored to the next block in the
   file.

   Finally an index is written to the end of the file, consisting of
   all the blocks and their offsets in the compressed file. This is a
   diagram of the file format:

   Header  | Size of block | Compressed Block | \
            Size of block | Compressed Block | .... | Index | Tail

   The header stores information about the blocksize used (The
   blocksize is the size of blocks in the uncompressed file). Whereas
   the "Size of Block" stores the size of the compressed block (which
   is obviously different for each block).

   The Index is an array of unsigned long long ints representing the
   offsets into the compressed file for each uncompressed block. This
   is used for quickly searching the sgzipped file to locate a single
   block.

   Note that the information in the index is redundant, and hence the
   index may be alternatively calculated by reading each block
   offset. This may be used if the index was damaged for some reason
   (e.g. the file was truncated).

   Reading from a file:

   Before a file may be read, we need to retrieve its header and
   indexes. These can be done using sgzip_read_header and
   sgzip_read_index (or sgzip_calculate_index_from_stream). Then we
   simply call sgzip_read_random to read a random buffer from the
   file.

   Creating a new file:

   To create a new file, get a file descriptor using open (not a
   stream using fopen!). Write a new header using sgzip_write_header
   with a NULL arg for header (or else create your own header using
   sgzip_default_header and change it and then pass it to
   sgzip_write_header).

   open the other file descriptor (from a socket, pipe or a real file
   whatever suits), and pass both descriptors to
   sgzip_compress_fds. This function does not seek in either fd's so
   they do not need to be seekable (e.g. pipes are fine). However note
   that this function reads in chunks of blocksize from the fd, and
   therefore will block until this much data is available.

   An index will automatically be created on the out file descriptor.

   Performace:
   ---------------

   The smaller the blocksize is, the faster seek and read, because we
   do not need to decompress more data than is needed, particularly
   for small blocks. However, compressibility is reduced the smaller
   the block size is, partly due to overheads (e.g. indexes are bigger
   and more blocks mean more block sizes in the file), partly due to
   the properties of the gzip algorithm.

   Anectodially, it seems that blocks as small as 256kb only produce
   an increase of file size of the order of 1-2% (over pure gzip),
   while still delivering over 30 file seek/read operations per second
   (at least on my machine). While the default blocksize (512kb)
   delivers around 19 seek/read operations. (See benchmarking options
   in sgzip.c). As usual, YMMV depending on hardware etc.

   In applications when speed matters, a blocksize of 32kb or even
   10kb is quite acceptable, yielding very quick performance with a
   reasonable compression.

********************************************************/
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdint.h>

/* Header to be written at the start of the file */
struct sgzip_header {
  char magic[3];
  uint32_t blocksize;
  union {
    char compression[4];
    //After being loaded from the file, this will be where we store the 
    uint32_t max_chunks;
  } x;
}  __attribute__((packed));

//A struct to store some information about the sgzip state
struct sgzip_obj {
  struct sgzip_header *header;
  int level;
};

/* This linked list stores the index as we are building the file */
struct sgzip_index_list {
  uint64_t offset;
  struct sgzip_index_list *next;
}__attribute__((packed));

/*
 Produces a default sgzip header. Mallocs its own memory, caller must
 free it.
*/
struct sgzip_header *sgzip_default_header(void);
/* Reads the header from the file. 
Returns NULL if the file can not be identified as a sgzip file 
*/
struct sgzip_header *sgzip_read_header(int fd) ;

/* Write a correct file header on the file descriptor */
struct sgzip_header *sgzip_write_header(int fd,struct sgzip_header *header);

/* Copy stream in to stream out compressing the output in sgzip format */
void sgzip_compress_fds(int infd,int outfd,const struct sgzip_obj *obj);

/* read a random buffer from the sgziped file */
int sgzip_read_random(char *buf, int len, uint64_t offs,
		int fd, uint64_t *index,const struct sgzip_obj *obj);

/* 
   Reads the index from the file and returns an array of long ints
   representing the offsets into the compressed image where the blocks
   can be found. Each entry in the array is blocksize big, so to seek
   to an arbitrary location, we just divide the location by the
   blocksize and use that as the reference to the correct block in the
   file.

   If the index is not there we flag an error by returning null.
*/
uint64_t *sgzip_read_index(int fd,struct sgzip_obj *sgzip) ;

/* 
   reads the stream and calculates the index map.

   This is done by following all the blocks throughout the file and
   rebuilding the index. None of the blocks are decoded so this should be quick.
   We return an index_list list.
 */
uint64_t *sgzip_calculate_index_from_stream(int fd,const struct sgzip_obj *obj);

/* Write the index passed in at the current positon in the file. Note
   you would probably only want to do this after
   sgzip_calculate_index_from_stream so that the correct position is
   in the file */
void sgzip_write_index(int outfd,uint64_t *index) ;
void sgzip_decompress_fds(int fd,int outfd,struct sgzip_obj *sgzip);
