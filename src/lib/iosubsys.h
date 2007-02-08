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
#include <stdlib.h>
#include <stdint.h>

/***********************************************************
 * Linked list for IO subsystem options
 **************************************************/
struct IO_OPT {
  char *option;
  char *value;
  struct IO_OPT *next;
};

typedef struct IO_OPT IO_OPT;

/**********************************************
 * Generic IO Subsystem objects.
 *
 * This is the base class for all IO subsystems.
 **********************************************/
struct IO_INFO {
  /* The name of the subsystem */
  char *name;
  /* Its description */
  char *description;
  /* Total size of the derived class. The one with the above name and description. Note that if the class is extended its size may be longer than sizeof(IO_INFO) */
  int size;
  /* A constructor, this creates a new instance of the object based on the class */
  struct IO_INFO *(*constructor)(struct IO_INFO *class);
  /* Destructor: Responsible for cleaning up and returning memory */
  void (*destructor)(void *self);
  /* A help function describing all parameters to this subsystem */
  void (*help)(void);
  /* The function used to parse out options and initialise the subsystem */
  int (*initialise)(struct IO_INFO *self,IO_OPT *arg);
  /* The random read function */
  int (*read_random)(struct IO_INFO *self, char *buf, uint32_t len, uint64_t offs,
		               const char *comment);
  /* A function used to open the file (may not be needed?) */
  int (*open)(struct IO_INFO *self);
  /* close file function: (may go in the destructor?) */
  int (*close)(struct IO_INFO *self);
  /* indicates if the open method needs to be called. Generally the read_* methods will check this and if its not set, they will call the open functions */
  int ready;
  /* Current seek position */
  off_t fpos;
};

typedef struct IO_INFO IO_INFO;

/* Prototypes for displatcher functions */
IO_INFO *io_open(char *name);
void io_parse_options(IO_INFO *io,char *opts) ;
int io_close(IO_INFO *self);
void io_help(char *name) ;

#define CHECK_OPTION(i,x) !strncasecmp(i->option, #x, strlen(#x))
#define NEW(x) (x *)calloc(sizeof(x),1)

/* Parses the string for a number. Can interpret the following suffixed:

  k - means 1024 bytes
  M - Means 1024*1024 bytes
  S - Menas 512 bytes (sector size)
*/
uint64_t parse_offsets(char *string);
