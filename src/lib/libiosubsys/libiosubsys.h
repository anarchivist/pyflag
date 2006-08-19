/*
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.82 Date: Sat Jun 24 23:38:33 EST 2006$
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
#include "../sgzlib.h"
#include "../libewf/libewf.h"

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
     char *name;
     char *description;
     int fd;

     char *METHOD(IOSource, help);

// Constructor: Given a list of options, we create an iosource of that class:
     IOSource METHOD(IOSource, Con, IOOptions opts); 

// This reads a length from offset into buf
     int METHOD(IOSource, read_random, char *buf, uint32_t len, uint64_t offs);
END_CLASS

CLASS(AdvIOSource, IOSource)
// This is the array of struct split_files:
     StringIO buffer;

     // Number of individual chunks
     int number;

     // Total size in bytes of this source
     uint64_t size;
END_CLASS

CLASS(SgzipIOSource, IOSource)
     struct sgzip_obj sgzip;
     uint64_t *index;
     uint64_t *offset;
END_CLASS

CLASS(EWFIOSource, IOSource)
     StringIO buffer;
     int number_of_files;
     LIBEWF_HANDLE *handle;
END_CLASS
