/**********************************************************************
  This is an implementation of structure parsing code. This is used
  everywhere to serialise and unserialise data to/from network, files
  etc.

  These are the format defines currently supported. Following those
  are the required corresponding elements in the struct:

  STRUCT_CHAR (char)     - Char
  STRUCT_SHORT (uint16_t) - short (16 bits)
  STRUCT_INT (uint32_t) - int (32 bits)

  STRUCT_STRING_NULL_TERM (char *) - A null terminated string. (Memory
     will be allocated with talloc and this position in the struct will
     point to this string.)

  STRUCT_STRING_AND_LENGTH (uint16_t, char *) - A length/string
     combination. The length is a short, immediately followed by a string
     on the specified length. Memory will be allocated. Note that the
     corresponding struct will require a uint16_t followed by a char * to
     store both length and the string.
  STRUCT_STRING_AND_LENGTH32 (uint32_t, char *) - Same as STRUCT_STRING_AND_LENGTH

***********************************************************************/

#include "stringio.h"

#ifndef __STRUCT_H
#define __STRUCT_H

/** Format string characters */
#define STRUCT_NULL 0
#define STRUCT_CHAR 3

#define STRUCT_SHORT 4
#define FORMAT_SHORT "\x04"

#define STRUCT_INT 5
#define FORMAT_INT "\x05"

#define STRUCT_STRING_NULL_TERM 6
#define FORMAT_STRING_NULL_TERM "\x06"

#define STRUCT_STRING_AND_LENGTH 7
#define STRUCT_DNS_ZSTRING 8
#define STRUCT_ARGV_ARRAY 9

#define STRUCT_STRING_AND_LENGTH32 0x10
#define STRUCT_STRING_AND_LENGTHLE32 0x11

#define STRUCT_SHORT_LE 0x14
#define FORMAT_SHORT_LE "\x14"

#define STRUCT_INT_LE 0x15
#define FORMAT_INT_LE "\x15"



/**
   You might need to increase this if other files are registrying more
   packers/unpackers
*/
#define MAX_FORMATS 0x20

/** 
    pack and unpack the struct passed in as the void * into or from
    the StringIO. This is done according to the format string. 

    Also remember that the struct passed in as a char* should be
    packed!!!
 */
int pack(char *format, char *input, StringIO output);
int unpack(void *context, char *format, StringIO input, char *output);

/** Returns the size of the format string in bytes */
int calcsize(char *format);

/** This is a function used to register a format char:

    format is the format char to register,
    size is the number of bytes taken in the struct for this object
    packer and unpacker are function pointers
*/
void Struct_Register(unsigned char format, int size, 
		     int (*packer)(char *input, StringIO output),
		     int (*unpacker)(void *context, StringIO input, char *output)
		     );

void struct_init(void);

#endif
