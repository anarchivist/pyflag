/*
** get
** The Sleuth Kit 
**
** routines to get values in a structure that solves endian issues
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003 Brian Carrier.  All rights reserved 
**
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
*/

#include "fs_tools.h"
#include "error.h"

/*
 * The getuX functions are now defined as macros in fs_tools.h
 */

/*
 * try both endian orderings to figure out which one is equal to 'val'
 *
 * if neither of them do, then 1 is returned.  Else 0 is.
 * fs->flags will be set accordingly
 */
u_int8_t
guessu16(FS_INFO *fs, u_int8_t *x, u_int16_t val)
{
	/* try little */
	fs->flags &= ~FS_BIG_ENDIAN;
	fs->flags |= FS_LIT_ENDIAN;
	if (getu16(fs, x) == val)
		return 0;

	/* ok, big now */
	fs->flags &= ~FS_LIT_ENDIAN;
	fs->flags |= FS_BIG_ENDIAN;
	if (getu16(fs, x) == val)
		return 0;

	/* didn't find it */
	return 1;
}

/*
 * same idea as guessu16 except that val is a 32-bit value
 *
 * return 1 on error and 0 else
 */
u_int8_t
guessu32(FS_INFO *fs, u_int8_t *x, u_int32_t val)
{
	/* try little */
	fs->flags &= ~FS_BIG_ENDIAN;
	fs->flags |= FS_LIT_ENDIAN;
	if (getu32(fs, x) == val)
		return 0;

	/* ok, big now */
	fs->flags &= ~FS_LIT_ENDIAN;
	fs->flags |= FS_BIG_ENDIAN;
	if (getu32(fs, x) == val)
		return 0;

	return 1;
}

