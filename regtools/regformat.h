#ifndef REGFORMAT_H
#define REGFORMAT_H
/*
 * regformat.h - structures/constants used in registry format (regutils package)
 * Copyright (C) 1998 Memorial University of Newfoundland
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */


#include <limits.h>

#if UINT_MAX != 0xffffffff
    this is not going to work
#endif

#define REG_HEADER_MAGIC	0x47455243	/* "CREG" */

/* Known bits in flags field of CREG, RGKN, RGDB (flags) */
#define REG_FLAG_CSUMVALID	0x4
/* unknown, but observed bits:
 *	0x1	CREG, RGDB
 *	0x8	RGDB
 *	0x2	RGKN
 */

struct reg_header {
    u_int	magic;
    u_int	uk4l;		/* unknown, offset 4, long */
    u_int	rgdb_offset;
    u_int	csum;
    u_short	nrgdb;
    u_short	flags;
    u_int	uk20l;
    u_int	uk24l;
    u_int	uk28l;
};

#define	RGKN_HEADER_MAGIC	0x4e4b4752	/* "RGKN" */
#define RGKN_INIT_SIZE		8192		/* initial size of rgkn */
#define RGKN_INCR_SIZE		4096		/* grow in this size blocks */

struct rgkn_header {
    u_int	magic;
    u_int	size;		/* rgkn size, incl header */
    u_int	root_offset;
    u_int	free_offset;
    u_int	flags;
    u_int	csum;
    u_int	uk24l;
    u_int	uk28l;
};

struct rgkn_key {
    u_int	inuse;
    u_int	hash;
    u_int	next_free;
    u_int	parent;
    u_int	child;
    u_int	next;
    u_short	id;
    u_short	rgdb;
};

#define NO_KEY		0xffffffff	/* next_free/parent/child/next fields */
#define FREE_SLOT	0x80000000	/* inuse field */

#define NO_ID		0xffff


#define RGDB_HEADER_MAGIC	0x42444752	/* "RGDB" */
#define NEW_RGDB_FLAG_VALUE	0x0000000d

struct rgdb_header {
    u_int	magic;
    u_int	size;
    u_int	unused_size;
    u_short	flags;
    u_short	section;
    u_int	free_offset;	/* -1 if unused_size == 0 */
    u_short	max_id;
    u_short	first_free_id;
    u_int	uk24l;
    u_int	csum;
};

struct rgdb_key {
    u_int	size;
    u_short	id;
    u_short	rgdb;
    u_int	used_size;
    u_short	name_len;
    u_short	nvalues;
    u_int	uk16l;
};

#define STRING_VALUE		1		/* ascii string */
#define HEX_VALUE		3		/* byte data */
#define DWORD_VALUE		4		/* double word (4 bytes) */
/* Non standard ones (seen after corel8 installation) */
#define USTRINGZ_VALUE		0x80000008	/* unicode string, null term */
#define STRINGZ_VALUE		0x80000006	/* ascii string, null term */
/* others:
	0x7		many null term strings
	0x0		8 bytes
 	0x80000001	many bytes, lots of nulls, different lengths
 	0x80000002	4 bytes; 2 bytes
 	0x8000000b	4 bytes; 2 bytes
 	0x80000009	4 bytes
 	0x80000007	unicode chars, null term
 */

struct rgdb_value {
    u_int	type;		/* *_VALUE */
    u_int	uk4l;
    u_short	name_len;
    u_short	data_len;
};

#endif /* REGFORMAT_H */
