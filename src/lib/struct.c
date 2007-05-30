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
#  Version: FLAG  $Version: 0.84RC4 Date: Wed May 30 20:48:31 EST 2007$
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
#include "struct.h"
#include <string.h>
#include <stdint.h>
#include <netinet/in.h>
#include "except.h"
#include "misc.h"

/********* Chars ****************/
static int Char_pack(char *input, StringIO output) {
  return CALL(output, write, (char *)(input), sizeof(char));
}

static int Char_unpack(void *context, StringIO input, char *output) {
  if(CALL(input, read, (char *)(output), sizeof(char)) < sizeof(char))
    return -1;
  return sizeof(char);
}

/********** Shorts *************/
static int Short_pack(char *input, StringIO output) {
  uint16_t i16 = *(uint16_t *)(input);
  i16=htons(i16);
  return CALL(output, write, (char *)&i16 , sizeof(i16));
}

static int Short_unpack(void *context, StringIO input, char *output) {
  uint16_t i16;

  if(CALL(input, read, (char *)&i16 , sizeof(i16)) < sizeof(i16))
    return -1;

  i16=ntohs(i16);
  *(uint16_t *)(output) = i16;
  return sizeof(i16);
}

// This is guaranteed to read little endians from input
static int LEShort_pack(char *input, StringIO output) {
  uint16_t i16 = *(uint16_t *)(input);

#ifdef WORDS_BIGENDIAN
  i16=htons(i16);
#endif

  return CALL(output, write, (char *)&i16 , sizeof(i16));
}

static int LEShort_unpack(void *context, StringIO input, char *output) {
  uint16_t i16;

  if(CALL(input, read, (char *)&i16 , sizeof(i16)) < sizeof(i16))
    return -1;

#ifdef WORDS_BIGENDIAN
  i16=ntohs(i16);
#endif

  *(uint16_t *)(output) = i16;
  return sizeof(i16);
}

/********** Ints *************/
static int Int_pack( char *input, StringIO output) {
  uint32_t i32 = *(uint32_t *)(input);
  i32=htonl(i32);
  return CALL(output, write, (char *)&i32 , sizeof(i32));
}

static int Int_unpack(void *context, StringIO input, char *output) {
  uint32_t i32;

  if(CALL(input, read, (char *)&i32 , sizeof(i32)) < sizeof(i32))
    return -1;

  i32=ntohl(i32);
  *(uint32_t *)(output) = i32;
  return sizeof(i32);
}

static int LEInt_pack( char *input, StringIO output) {
  uint32_t i32 = *(uint32_t *)(input);

#ifdef WORDS_BIGENDIAN
  i32=htonl(i32);
#endif

  return CALL(output, write, (char *)&i32 , sizeof(i32));
}

static int LEInt_unpack(void *context, StringIO input, char *output) {
  uint32_t i32;

  if(CALL(input, read, (char *)&i32 , sizeof(i32)) < sizeof(i32))
    return -1;

#ifdef WORDS_BIGENDIAN
  i32=ntohl(i32);
#endif

  *(uint32_t *)(output) = i32;
  return sizeof(i32);
}

/********** ZStrings *************/
static int NullString_pack(char *input, StringIO output) {
  int length = strlen(*(char **)(input)) + 1;
  CALL(output, write, *(char **)(input), length);  
  return sizeof(char *);
}

static int NullString_unpack(void *context, StringIO input, char *output) {
  StringIO temp = CONSTRUCT(StringIO, StringIO, Con, context);
  int length=0;
  char c;

  // Search the input for a null:
  while(CALL(input, read, &c, 1)) {
    length++;
    CALL(temp, write, &c, 1);
    if(c==0) {
      *(char **)(output) = temp->data;
      return sizeof(char *);
    };
  };

  //If we got here - there is no string:
  return -1;
}

/********** SizeStrings *************/
static int SizeString_pack(char *input, StringIO output) {
  uint16_t length = *(uint16_t *)(input);
  uint16_t i16;

  i16=htons(length);
  CALL(output, write, (char *)&i16, sizeof(uint16_t));
  CALL(output, write, *(char **)(input+sizeof(i16)), length);
  return sizeof(uint16_t)+sizeof(char *);
}

static int SizeString_unpack(void *context, StringIO input, char *output) {
  char *string;
  uint16_t i16;
  
  if(CALL(input, read, (char *)&i16, sizeof(uint16_t)) < sizeof(uint16_t))
    return -1;
  
  i16=ntohs(i16);

  *(uint16_t *)(output) = i16;	
  
  /** Allocate this much memory */
  string = talloc_size(context, i16);
  if(!string) return -1;

  *(char **)(output + sizeof(uint16_t)) = string;
  
  /** Copy the string into the buffer */
  if(CALL(input, read, string, i16) < i16) 
    return -1;

  return sizeof(uint16_t)+sizeof(char *);
}

static int SizeString32LE_pack(char *input, StringIO output) {
  uint32_t length = *(uint32_t *)(input);
  uint32_t i32=length;

#ifdef WORDS_BIGENDIAN
  i32=htons(length);
#endif

  CALL(output, write, (char *)&i32, sizeof(uint32_t));
  CALL(output, write, *(char **)(input + sizeof(i32)), length);
  return sizeof(uint32_t)+sizeof(char *);
}

static int SizeString32LE_unpack(void *context, StringIO input, char *output) {
  char *string;
  uint32_t i32;
  
  if(CALL(input, read, (char *)&i32, sizeof(uint32_t)) < sizeof(uint32_t))
    return -1;
  
#ifdef WORDS_BIGENDIAN
  i32=ntohs(i32);
#endif

  *(uint32_t *)(output) = i32;	
  
  /** Allocate this much memory */
  string = talloc_size(context, i32);
  if(!string) return -1;

  *(char **)(output + sizeof(uint32_t)) = string;
  
  /** Copy the string into the buffer */
  if(CALL(input, read, string, i32) < i32) 
    return -1;

  return sizeof(uint32_t)+sizeof(char *);
}

static int SizeString32_pack(char *input, StringIO output) {
  uint32_t length = *(uint32_t *)(input);
  uint32_t i32;

  i32=htons(length);

  CALL(output, write, (char *)&i32, sizeof(uint32_t));
  CALL(output, write, *(char **)(input+sizeof(i32)), length);
  return sizeof(uint32_t)+sizeof(char *);
}

static int SizeString32_unpack(void *context, StringIO input, char *output) {
  char *string;
  uint32_t i32;
  
  if(CALL(input, read, (char *)&i32, sizeof(uint32_t)) < sizeof(uint32_t))
    return -1;
  
  i32=ntohs(i32);

  *(uint32_t *)(output) = i32;	
  
  /** Allocate this much memory */
  string = talloc_size(context, i32);
  *(char **)(output + sizeof(uint32_t)) = string;
  
  /** Copy the string into the buffer */
  if(CALL(input, read, string, i32) < i32) 
    return -1;

  return sizeof(uint32_t)+sizeof(char *);
}

/********** Argv Array  *************/
static int ArgvArray_pack(char *input, StringIO output) {
  uint16_t argc = *(uint16_t *)(input);
  uint16_t i16;
  int i;
  char *str;

  i16=htons(argc);
  CALL(output, write, (char *)&i16, sizeof(uint16_t));

  /* write out the array of strings*/
  for(i=0; i<argc; i++) {
    str = (*(char ***)(input+sizeof(i16)))[i];
    CALL(output, write, str, strlen(str)+1);
  }
  return sizeof(uint16_t) + sizeof(char **);
}

static int ArgvArray_unpack(void *context, StringIO input, char *output) {
  char *data;
  int i, len;
  char **array;
  uint16_t i16;
  
  if(CALL(input, read, (char *)&i16, sizeof(uint16_t)) < sizeof(uint16_t))
    return -1;
  
  i16=ntohs(i16);

  *(uint16_t *)(output) = i16;

  /** Allocate the array (+1 for sentinel)*/
  array = (char **)talloc_size(context, (i16+1)*sizeof(char *));
  
  /** Now the strings */
  for(i=0; i<i16; i++) {
    CALL(input, get_buffer, &data, &len);
    array[i] = talloc_strdup(array, data);    
    CALL(input, seek, strlen(array[i])+1, SEEK_CUR);
  };

  /** insert NULL sentinel which may be a useful alternative to argc
      (eg. allowing argv to be passed straight to an execv) */
  array[i16] = NULL;

  *(char ***)(output+sizeof(i16))=array;
  return sizeof(uint16_t) + sizeof(char **);
}

static int (*packers[MAX_FORMATS])(char *input, StringIO output);
static int (*unpackers[MAX_FORMATS])(void *context, StringIO input, char *output);
static int struct_size[MAX_FORMATS];

void Struct_Register(unsigned char format, int size, 
		     int (*packer)(char *input, StringIO output),
		     int (*unpacker)(void *context, StringIO input, char *output)
		     ) {

  if(format > MAX_FORMATS) {
    DEBUG("format (%u) can not be registered, increase MAX_FORMATS to greater than %u.\n", format, MAX_FORMATS);
    exit(-1);
  };

  struct_size[(int)format]=size;
  packers[(int)format]=packer;
  unpackers[(int)format]=unpacker;
};

static int structs_initialised = 0;

void struct_init(void) {
  if(structs_initialised) return;

  structs_initialised = 1;

  /** Zero out the packers and unpackers */
  memset(packers, 0, sizeof(packers));
  memset(unpackers, 0, sizeof(unpackers));
  memset(struct_size, 0, sizeof(struct_size));

  Struct_Register(STRUCT_CHAR, sizeof(char), 
		  Char_pack, Char_unpack);

  Struct_Register(STRUCT_SHORT, sizeof(uint16_t), 
		  Short_pack, Short_unpack);

  Struct_Register(STRUCT_SHORT_LE, sizeof(uint16_t), 
		  LEShort_pack, LEShort_unpack);

  Struct_Register(STRUCT_INT, sizeof(uint32_t), 
		  Int_pack, Int_unpack);

  Struct_Register(STRUCT_INT_LE, sizeof(uint32_t), 
		  LEInt_pack, LEInt_unpack);

  Struct_Register(STRUCT_STRING_NULL_TERM, sizeof(char *), 
		  NullString_pack, NullString_unpack);

  Struct_Register(STRUCT_STRING_AND_LENGTH, sizeof(uint16_t)
		  +sizeof(char *), SizeString_pack, SizeString_unpack);

  Struct_Register(STRUCT_STRING_AND_LENGTH32, sizeof(uint32_t)
		  +sizeof(char *), SizeString32_pack, SizeString32_unpack);

  Struct_Register(STRUCT_STRING_AND_LENGTHLE32, sizeof(uint32_t)
		  +sizeof(char *), SizeString32LE_pack, SizeString32LE_unpack);

  Struct_Register(STRUCT_ARGV_ARRAY, sizeof(uint16_t)
		  +sizeof(char **), ArgvArray_pack, ArgvArray_unpack);
};

int calcsize(char *format) {
  char *x;
  int total=0;

  for(x=format; *x; x++) {
    total+=struct_size[(int)*x];
  };
  return total;
};

int pack(char *format, char *input, StringIO output) {
  char *x;
  int offset=0;

  // Make sure that structs are initialised
  struct_init();
  
  for(x=format; *x; x++) {
    if(packers[(int)*x])
      offset+=packers[(int)*x](input+offset, output);
  };

  return offset;
};

int unpack(void *context, char *format, StringIO input, char *output) {
  char *x;
  int offset=0;
  
  // Make sure that structs are initialised
  struct_init();

  for(x=format; *x; x++) {
    int result=0;

    if(unpackers[(int)*x])
      result=unpackers[(int)*x](context, input, output+offset);

    if(result<0) return -1;

    offset+=result;
  };

  return offset;
};
