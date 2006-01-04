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
#  Version: FLAG  $Version: 0.78 Date: Fri Aug 19 00:47:14 EST 2005$
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

#include "class.h"
#include <sys/types.h>

CLASS(StringIO,Object)
  /** This is the size of the internal buffer */
  int size;
  /** Current readptr */
  int readptr;
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
  int METHOD(StringIO, seek, int offset, int whence);

  /** get_buffer: Returns a pointer/length to the buffer (relative to readptr) */
  void METHOD(StringIO, get_buffer, char **data, int *len);

  /** Return true if we are at the end of the file */
  int METHOD(StringIO, eof);

  /** Truncates the file to this size */
  void METHOD(StringIO, truncate, int len);

  /** Destructor */
  void METHOD(StringIO, destroy);
END_CLASS

#endif
