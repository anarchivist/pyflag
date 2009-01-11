/*
 * Branched from Samba project, Subversion repository version #6903:
 *   http://viewcvs.samba.org/cgi-bin/viewcvs.cgi/trunk/source/include/regfio.h?rev=6903&view=auto
 *
 * Unix SMB/CIFS implementation.
 * Windows NT registry I/O library
 *
 * Copyright (C) 2005-2008 Timothy D. Morgan
 * Copyright (C) 2005 Gerald (Jerry) Carter
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * $Id: regfi.h 121 2008-08-09 17:22:26Z tim $
 */

/************************************************************
 * Most of this information was obtained from 
 * http://www.wednesday.demon.co.uk/dosreg.html
 * Thanks Nigel!
 ***********************************************************/

#ifndef _REGFI_H
#define _REGFI_H

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#include "smb_deps.h"
#include "void_stack.h"
#include "range_list.h"
#include "lru_cache.h"

/******************************************************************************/
/* Macros */
 
/* Registry data types */
#define REG_NONE                       0
#define REG_SZ		               1
#define REG_EXPAND_SZ                  2
#define REG_BINARY 	               3
#define REG_DWORD	               4
#define REG_DWORD_LE	               4  /* DWORD, little endian */
#define REG_DWORD_BE	               5  /* DWORD, big endian */
#define REG_LINK                       6
#define REG_MULTI_SZ  	               7
#define REG_RESOURCE_LIST              8
#define REG_FULL_RESOURCE_DESCRIPTOR   9
#define REG_RESOURCE_REQUIREMENTS_LIST 10
#define REG_QWORD                      11 /* 64-bit little endian */
/* XXX: Has MS defined a REG_QWORD_BE? */
/* Not a real type in the registry */
#define REG_KEY                        0x7FFFFFFF

#define REGF_BLOCKSIZE		   0x1000
#define REGF_ALLOC_BLOCK	   0x1000 /* Minimum allocation unit for HBINs */
#define REGF_MAX_DEPTH		   512

/* header sizes for various records */
#define REGF_MAGIC_SIZE		   4
#define HBIN_MAGIC_SIZE		   4
#define HBIN_HEADER_REC_SIZE	   0x20
#define REC_HDR_SIZE		   2

#define REGF_OFFSET_NONE           0xffffffff
#define REGFI_NK_MIN_LENGTH        0x4C
#define REGFI_VK_MIN_LENGTH        0x14
#define REGFI_SK_MIN_LENGTH        0x14
#define REGFI_HASH_LIST_MIN_LENGTH 0x4

/* Constants used for validation */
 /* Minimum time is Jan 1, 1990 00:00:00 */
#define REGFI_MTIME_MIN_HIGH       0x01B41E6D
#define REGFI_MTIME_MIN_LOW        0x26F98000
 /* Maximum time is Jan 1, 2290 00:00:00
  * (We hope no one is using Windows by then...) 
  */
#define REGFI_MTIME_MAX_HIGH       0x03047543
#define REGFI_MTIME_MAX_LOW        0xC80A4000


/* Flags for the vk records */
#define VK_FLAG_NAME_PRESENT	   0x0001
#define VK_DATA_IN_OFFSET	   0x80000000
#define VK_MAX_DATA_LENGTH         1024*1024

/* NK record types */
#define NK_TYPE_LINKKEY		   0x0010
#define NK_TYPE_NORMALKEY	   0x0020
#define NK_TYPE_ROOTKEY		   0x002c
 /* TODO: Unknown type that shows up in Vista registries */
#define NK_TYPE_UNKNOWN1           0x1020


/* HBIN block */
typedef struct regf_hbin 
{
  uint32 file_off;       /* my offset in the registry file */
  uint32 ref_count;      /* how many active records are pointing to this
                          * block (not used currently) 
			  */
  
  uint32 first_hbin_off; /* offset from first hbin block */
  uint32 block_size;     /* block size of this block 
                          * Should be a multiple of 4096 (0x1000)
			  */
  uint32 next_block;     /* relative offset to next block.  
			  * NOTE: This value may be unreliable!
			  */

  uint8 magic[HBIN_MAGIC_SIZE]; /* "hbin" */
} REGF_HBIN;


/* Hash List -- list of key offsets and hashed names for consistency */
typedef struct 
{
  uint32 nk_off;
  uint32 hash;
} REGF_HASH_LIST_ELEM;


typedef struct 
{
  uint32 offset;	/* Real offset of this record's cell in the file */
  uint32 cell_size;	 /* ((start_offset - end_offset) & 0xfffffff8) */
  REGF_HBIN* hbin;       /* pointer to HBIN record (in memory) containing 
			  * this nk record 
			  */
  uint32 hbin_off;	 /* offset from beginning of this hbin block */
  REGF_HASH_LIST_ELEM* hashes;
  
  uint8 magic[REC_HDR_SIZE];
  uint16 num_keys;
} REGF_HASH_LIST;


/* Key Value */
typedef struct 
{
  uint32 offset;	/* Real offset of this record's cell in the file */
  uint32 cell_size;	/* ((start_offset - end_offset) & 0xfffffff8) */

  REGF_HBIN* hbin;	/* pointer to HBIN record (in memory) containing 
			 * this nk record 
			 */
  uint8* data;
  uint16 name_length;
  char*  valuename;
  uint32 hbin_off;	/* offset from beginning of this hbin block */
  
  uint32 data_size;
  uint32 data_off;      /* offset of data cell (virtual) */
  uint32 type;
  uint8  magic[REC_HDR_SIZE];
  uint16 flag;
  uint16 unknown1;
  bool data_in_offset;
} REGF_VK_REC;


/* Key Security */
struct _regf_sk_rec;

typedef struct _regf_sk_rec 
{
  uint32 offset;        /* Real file offset of this record */
  uint32 cell_size;	/* ((start_offset - end_offset) & 0xfffffff8) */

  SEC_DESC* sec_desc;
  uint32 hbin_off;	/* offset from beginning of this hbin block */
  
  uint32 sk_off;	/* offset parsed from NK record used as a key
			 * to lookup reference to this SK record 
			 */
  
  uint32 prev_sk_off;
  uint32 next_sk_off;
  uint32 ref_count;
  uint32 desc_size;     /* size of security descriptor */
  uint16 unknown_tag;
  uint8  magic[REC_HDR_SIZE];
} REGF_SK_REC;


/* Key Name */
typedef struct
{
  uint32 offset;	/* Real offset of this record's cell in the file */
  uint32 cell_size;	/* Actual or estimated length of the cell.  
			 * Always in multiples of 8. 
			 */

  /* link in the other records here */
  REGF_VK_REC** values;
  REGF_HASH_LIST* subkeys;
  
  /* header information */
  /* XXX: should we be looking for types other than the root key type? */
  uint16 key_type;
  uint8  magic[REC_HDR_SIZE];
  NTTIME mtime;
  uint16 name_length;
  uint16 classname_length;
  char* classname;
  char* keyname;
  uint32 parent_off;	/* back pointer in registry hive */
  uint32 classname_off;	
  
  /* max lengths */
  uint32 max_bytes_subkeyname;	    /* max subkey name * 2 */
  uint32 max_bytes_subkeyclassname; /* max subkey classname length (as if) */
  uint32 max_bytes_valuename;	    /* max valuename * 2 */
  uint32 max_bytes_value;           /* max value data size */
  
  /* unknowns */
  uint32 unknown1;
  uint32 unknown2;
  uint32 unknown3;
  uint32 unk_index;		    /* nigel says run time index ? */
  
  /* children */
  uint32 num_subkeys;
  uint32 subkeys_off;	/* hash records that point to NK records */	
  uint32 num_values;
  uint32 values_off;	/* value lists which point to VK records */
  uint32 sk_off;	/* offset to SK record */  
} REGF_NK_REC;



/* REGF block */
typedef struct 
{
  /* run time information */
  int fd;	  /* file descriptor */
  /* For sanity checking (not part of the registry header) */
  uint32 file_length;
  void* mem_ctx;  /* memory context for run-time file access information */

  /* Experimental hbin lists */
  range_list* hbins;

  /* file format information */  
  uint8  magic[REGF_MAGIC_SIZE];/* "regf" */
  NTTIME mtime;
  uint32 data_offset;		/* offset to record in the first (or any?) 
				 * hbin block 
				 */
  uint32 last_block;		/* offset to last hbin block in file */

  uint32 checksum;		/* Stored checksum. */
  uint32 computed_checksum;     /* Our own calculation of the checksum.
				 * (XOR of bytes 0x0000 - 0x01FB) 
				 */
  
  /* unknown data structure values */
  uint32 unknown1;
  uint32 unknown2;
  uint32 unknown3;
  uint32 unknown4;
  uint32 unknown5;
  uint32 unknown6;
  uint32 unknown7;
} REGF_FILE;



typedef struct 
{
  REGF_FILE* f;
  void_stack* key_positions;
  lru_cache* sk_recs;
  REGF_NK_REC* cur_key;
  REGF_NK_REC* cur_subkey_p;
  uint32 cur_subkey;
  uint32 cur_value;
} REGFI_ITERATOR;


typedef struct 
{
  REGF_NK_REC* nk;
  uint32 cur_subkey;
  /* We could store a cur_value here as well, but didn't see 
   * the use in it right now.
   */
} REGFI_ITER_POSITION;


/******************************************************************************/
/* Function Declarations */
/*  Main API */
const char*           regfi_type_val2str(unsigned int val);
int                   regfi_type_str2val(const char* str);

char*                 regfi_get_sacl(SEC_DESC* sec_desc);
char*                 regfi_get_dacl(SEC_DESC* sec_desc);
char*                 regfi_get_owner(SEC_DESC* sec_desc);
char*                 regfi_get_group(SEC_DESC* sec_desc);

REGF_FILE*            regfi_open(void *ctx, const char* filename);
int                   regfi_close(REGF_FILE* r);

REGFI_ITERATOR*       regfi_iterator_new(REGF_FILE* fh);
/*
no longer needed
void                  regfi_iterator_free(REGFI_ITERATOR* i);
*/
bool                  regfi_iterator_down(REGFI_ITERATOR* i);
bool                  regfi_iterator_up(REGFI_ITERATOR* i);
bool                  regfi_iterator_to_root(REGFI_ITERATOR* i);

bool                  regfi_iterator_find_subkey(void *ctx, REGFI_ITERATOR* i, 
						 const char* subkey_name);
bool                  regfi_iterator_walk_path(REGFI_ITERATOR* i, 
					       const char** path);
const REGF_NK_REC*    regfi_iterator_cur_key(REGFI_ITERATOR* i);
const REGF_SK_REC*    regfi_iterator_cur_sk(REGFI_ITERATOR* i);
const REGF_NK_REC*    regfi_iterator_first_subkey(void *ctx, REGFI_ITERATOR* i);
const REGF_NK_REC*    regfi_iterator_cur_subkey(void *ctx, REGFI_ITERATOR* i);
const REGF_NK_REC*    regfi_iterator_next_subkey(void *ctx, REGFI_ITERATOR* i);

bool                  regfi_iterator_find_value(REGFI_ITERATOR* i, 
						const char* value_name);
const REGF_VK_REC*    regfi_iterator_first_value(REGFI_ITERATOR* i);
const REGF_VK_REC*    regfi_iterator_cur_value(REGFI_ITERATOR* i);
const REGF_VK_REC*    regfi_iterator_next_value(REGFI_ITERATOR* i);

/************************************/
/*  Low-layer data structure access */
/************************************/
REGF_FILE*            regfi_parse_regf(void *ctx, int fd, bool strict);
REGF_HBIN*            regfi_parse_hbin(void *ctx, REGF_FILE* file, uint32 offset, 
				       bool strict);


/* regfi_parse_nk: Parses an NK record.
 *
 * Arguments:
 *   f        -- the registry file structure
 *   offset   -- the offset of the cell (not the record) to be parsed.
 *   max_size -- the maximum size the NK cell could be. (for validation)
 *   strict   -- if true, rejects any malformed records.  Otherwise,
 *               tries to minimally validate integrity.
 * Returns:
 *   A newly allocated NK record structure, or NULL on failure.
 */
REGF_NK_REC*          regfi_parse_nk(void *ctx, REGF_FILE* file, uint32 offset, 
				     uint32 max_size, bool strict);


/* Private Functions */
REGF_NK_REC*          regfi_rootkey(REGF_FILE* file);
/*
  No longer needed
void                  regfi_key_free(REGF_NK_REC* nk);
*/
uint32                regfi_read(int fd, uint8* buf, uint32* length);



/****************/
/* Experimental */
/****************/
REGF_NK_REC* regfi_load_key(void *ctx, REGF_FILE* file, uint32 offset, bool strict);

REGF_HASH_LIST* regfi_load_hashlist(void *ctx, REGF_FILE* file, uint32 offset, 
				    uint32 num_keys, uint32 max_size, 
				    bool strict);

REGF_VK_REC** regfi_load_valuelist(void *ctx, REGF_FILE* file, uint32 offset, 
				   uint32 num_values, uint32 max_size, 
				   bool strict);

REGF_VK_REC* regfi_parse_vk(void *ctx, REGF_FILE* file, uint32 offset, 
			    uint32 max_size, bool strict);

uint8* regfi_parse_data(void *ctx, REGF_FILE* file, uint32 offset, 
			uint32 length, bool strict);

REGF_SK_REC* regfi_parse_sk(void *ctx, REGF_FILE* file, uint32 offset, uint32 max_size, bool strict);

range_list* regfi_parse_unalloc_cells(REGF_FILE* file);

REGF_HBIN* regfi_lookup_hbin(REGF_FILE* file, uint32 offset);

bool regfi_parse_cell(int fd, uint32 offset, uint8* hdr, uint32 hdr_len,
		      uint32* cell_length, bool* unalloc);

#endif	/* _REGFI_H */
