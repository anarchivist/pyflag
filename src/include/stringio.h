/******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG  $Version: 0.84RC5 Date: Wed Dec 12 00:45:27 HKT 2007$
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
# ******************************************************/
#ifndef _STRINGIO_H
#define _STRINGIO_H
#include "config.h"			       
#include "class.h"
#include <sys/types.h>
#include <stdint.h>

CLASS(StringIO,Object)
  /** This is the size of the internal buffer */
  int size;
  /** Current readptr */
  uint64_t readptr;
  char *data;
  
  /** constructor */
  StringIO METHOD(StringIO, Con);

  /** Writes data into the string_io at the current offset, growing the
    string_io if needed **/
  int METHOD(StringIO, write, char *data, int len);

  /** Write a format string into the stringio **/
  int METHOD(StringIO, sprintf, char *fmt, ...);

  /** Reads data from the current string location into the buffer (We
      presume it is large enough. We return how much data was actually
      read */
  int METHOD(StringIO, read, char *data, int len);

  /** These allow us to read and write to StringIOs rather than direct
    buffers */
  int METHOD(StringIO, write_stream, StringIO stream, int length);
  int METHOD(StringIO, read_stream, StringIO stream, int length);

  /** The seek method */
  uint64_t METHOD(StringIO, seek, int64_t offset, int whence);

  /** get_buffer: Returns a pointer/length to the buffer (relative to readptr) */
  void METHOD(StringIO, get_buffer, char **data, int *len);

  /** Return true if we are at the end of the file */
  int METHOD(StringIO, eof);

  /** Truncates the end of the stream to this size */
  void METHOD(StringIO, truncate, int len);

  /** Removes the first len bytes from the start of the stream. The
      stream is repositioned at its start */
  void METHOD(StringIO, skip, int len);

  /** find a substring, returns a pointer inside data */
  char *METHOD(StringIO, find, char *string);

  /** case insensitive version of find */
  char *METHOD(StringIO, ifind, char *string);

  /** Destructor */
  void METHOD(StringIO, destroy);
END_CLASS

/** This class is like a stringio except that all writes and reads
    come from the disk, the nice thing about it is that we manage a
    buffer of a reasonable size and flush it into the disk once the
    buffer is full - its like libcs file stream model but better.
 */
CLASS(DiskStringIO, StringIO)
     int fd;
     int fileoffset;
     DiskStringIO METHOD(DiskStringIO, OpenFile, char *filename, int mode);

     // This method flushes the buffer into the disk
     void METHOD(DiskStringIO, flush);
END_CLASS

/************************************************************
    CachedWriter is a class which makes it easy and efficient to write
    numerous files concurrently.

The problem with the stream reassembler is that we need to keep track
of many streams simultaneously. Each stream is written to its own
cache file, however, data is appended to each file in small chunks
(often up to a byte at the time).

It is prohibitive to reopen each stream file, append a small amount of
data, and close it. Due to the number of concurrent streams it is
impossible to keep all the files open at the same time (because we
will run out of file descriptors).

This class manages a stream in memory. When the stream becomes too
large, we flush the data to disk. This allows us to have numerous
pending streams open without running out of file descriptors.
***************************************************************/
  /** The maximum size to remain buffered */
#define MAX_DISK_STREAM_SIZE 40960

CLASS(CachedWriter, StringIO)
     char *filename;

     /** Total number of bytes written to the file so far */
     int written;

     /** A Flag to indicate if we already created the file */
     char created;

     // If fd>0, we just use this fd rather than closing and reopening it.
     int fd;

     CachedWriter METHOD(CachedWriter, Con, char *filename);
     CachedWriter METHOD(CachedWriter, from_fd, int fd);
     int METHOD(CachedWriter, get_offset);
END_CLASS

#endif
