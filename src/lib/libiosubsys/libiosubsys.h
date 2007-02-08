/*
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.84RC1 Date: Fri Feb  9 08:22:13 EST 2007$
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

#include "misc.h"
#include "class.h"
#include "list.h"
#include "stringio.h"
//#include "../sgzlib.h"
//#include "../libewf/libewf.h"

/** Options are kept as lists: */
CLASS(IOOptions, Object)
     char *name;
     char *value;
     struct list_head list;

     IOOptions METHOD(IOOptions, add, IOOptions list, char *name, char *value);
     char *METHOD(IOOptions, get_value, char *name);
END_CLASS

/** The base class of all IOSources.
    
This is also the standard IO source which will be subclassed by everyone else.
*/
CLASS(IOSource, Object)
// Name of driver - this is the name we shall be registered as.
     char *name;
     // Total size in bytes of this source
     uint64_t size;

     // Position of the last read_random
     uint64_t fpos;

     int fd;
     char *filename;

     char *METHOD(IOSource, help);

// Constructor: Given a list of options, we create an iosource of that class:
     IOSource METHOD(IOSource, Con, IOOptions opts); 

// This reads a length from offset into buf
     int METHOD(IOSource, read_random, char *buf, uint32_t len, uint64_t offs);
END_CLASS

CLASS(AdvIOSource, IOSource)
// This is the array of struct split_files:
     StringIO buffer;

     // User supplied offset into image
     int64_t offset;

     // Number of individual chunks
     int number;
END_CLASS

CLASS(SgzipIOSource, IOSource)
//     struct sgzip_obj sgzip;
     void *_handle;
     uint64_t *index;
     int64_t offset;
END_CLASS

CLASS(EWFIOSource, IOSource)
     StringIO buffer;
     int number_of_files;
     void *_handle;
     int64_t offset;
     //     LIBEWF_HANDLE *handle;
END_CLASS

// A central dispatcher to all drivers:
IOSource iosubsys_Open(char *name, IOOptions opts);

//A parser for option strings:
IOOptions iosubsys_parse_options(char *s);

// A parser for offset strings
int64_t parse_offsets(char *string);
