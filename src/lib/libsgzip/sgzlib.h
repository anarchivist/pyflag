/*************************************************
         sgzlib - A seekable Gzip file format

   Author:         Michael Cohen (scudette@users.sourceforge.net)
   Version: 0.2   
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

   Header  | Size of block | Compressed Block |		\
            Size of block | Compressed Block | .... |	\
            Index | Size of index			\
            total file size (64 bits) | Tail

   The header stores information about the blocksize used (The
   blocksize is the size of blocks in the uncompressed file). Whereas
   the "Size of Block" stores the size of the compressed block (which
   is obviously different for each block).

   The Index is an array of 64 bit ints representing the offsets into
   the compressed file for each uncompressed block. This is used for
   quickly searching the sgzipped file to locate a single block. Each
   offset in the index points to the Size of block entry for that
   block.

   Note that the information in the index is redundant, and hence the
   index may be alternatively calculated by reading each block
   offset. This may be used if the index was damaged for some reason
   (e.g. the file was truncated).

   The total file size is stored in the tail of the file - this allows
   sgzip to be used to for storing arbitrary file which do not
   necessarily have a size which is a multiple of block size.

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
/** This is a reimplementation of sgzip using CLASSES */

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
#include "class.h"
#include "packet.h" 

/** The sgzip file header */
struct sgzip_file_header {
  char magic[3];
  char version;
  uint32_t blocksize;
  char compression[4];
} __attribute__((packed));

#define SGZIP_FORMAT q(STRUCT_CHAR, STRUCT_CHAR, STRUCT_CHAR, STRUCT_CHAR, \
		       STRUCT_INT, STRUCT_CHAR, STRUCT_CHAR,		\
		       STRUCT_CHAR, STRUCT_CHAR)

CLASS(SgzipFile, Packet)
     struct sgzip_file_header packet;
     int fd;
     StringIO io;
     StringIO index_stream;
     uint64_t *index;
     int readptr;
     unsigned int max_chunks;

     // The compression level
     int level;

     // This is the size of the uncompressed image
     uint64_t size;

     // We keep one chunk in the cache to speed up little reads:
     int cached_block_offs;
     int cached_length;
     char *cache;
     // The opens an existing file:
     SgzipFile METHOD(SgzipFile, OpenFile, char *filename);

     // This creates a new file - fd must already be opened for writing
     SgzipFile METHOD(SgzipFile, CreateFile, int fd, int blocksize);
     int METHOD(SgzipFile, seek, off_t offset, int whence);
     int METHOD(SgzipFile, read, char *data, int len);
     int METHOD(SgzipFile, append, char *data, int len);
END_CLASS
