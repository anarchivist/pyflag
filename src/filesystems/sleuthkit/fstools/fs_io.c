/*
 * The Sleuth Kit
 *
 * $Date: 2006/12/05 21:39:52 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2006 Brian Carrier, Basis Technology.  All Rights reserved
 * Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
 * 
 * Copyright (c) 1997,1998,1999, International Business Machines          
 * Corporation and others. All Rights Reserved.
 *
 *
 * LICENSE
 *	This software is distributed under the IBM Public License.
 * AUTHOR(S)
 *	Wietse Venema
 *	IBM T.J. Watson Research
 *	P.O. Box 704
 *	Yorktown Heights, NY 10598, USA
--*/

#include <errno.h>
#include "fs_tools_i.h"


/* fs_read_block - read a block given the address - calls the read_random at the img layer */

SSIZE_T
fs_read_block(FS_INFO * fs, DATA_BUF * buf, OFF_T len, DADDR_T addr)
{
    OFF_T offs;
    SSIZE_T cnt;

    if (len % fs->dev_bsize) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_READ;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "fs_read_block: length %" PRIuOFF " not a multiple of %d",
	    len, fs->dev_bsize);
	return -1;
    }


    if (len > buf->size) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_READ;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "fs_read_block: Buffer too small - %"
	    PRIuOFF " > %Zd", len, buf->size);
	return -1;
    }

    if (addr > fs->last_block) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_READ;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "fs_read_block: Address is too large: %" PRIuDADDR ")", addr);
	return -1;
    }

    buf->addr = addr;
    offs = (OFF_T) addr *fs->block_size;

    cnt =
	fs->img_info->read_random(fs->img_info, fs->offset, buf->data, len,
	offs);
    buf->used = cnt;
    return cnt;
}

SSIZE_T
fs_read_block_nobuf(FS_INFO * fs, char *buf, OFF_T len, DADDR_T addr)
{
    if (len % fs->dev_bsize) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_READ;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "fs_read_block_nobuf: length %" PRIuOFF
	    " not a multiple of %d", len, fs->dev_bsize);
	return -1;
    }

    if (addr > fs->last_block) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_READ;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "fs_read_block: Address is too large: %" PRIuDADDR ")", addr);
	return -1;
    }

    return fs->img_info->read_random(fs->img_info, fs->offset, buf, len,
	(OFF_T) addr * fs->block_size);
}


static uint8_t
fs_load_file_act(FS_INFO * fs, DADDR_T addr, char *buf, size_t size,
    int flags, void *ptr)
{
    FS_LOAD_FILE *buf1 = (FS_LOAD_FILE *) ptr;
    size_t cp_size;

    if (size > buf1->left)
	cp_size = buf1->left;
    else
	cp_size = size;

    memcpy(buf1->cur, buf, cp_size);
    buf1->left -= cp_size;
    buf1->cur = (char *) ((uintptr_t) buf1->cur + cp_size);

    if (buf1->left > 0)
	return WALK_CONT;
    else
	return WALK_STOP;
}

/* Read the contents of the file pointed to by fsi.  Flags are the same
 * as used by FILE_WALK...
 * */
char *
fs_load_file(FS_INFO * fs, FS_INODE * fsi, uint32_t type, uint16_t id,
    int flags)
{
    FS_LOAD_FILE lf;

    if (NULL == (lf.base = (char *) mymalloc((size_t) fsi->size))) {
	return NULL;
    }
    lf.left = lf.total = (size_t) fsi->size;
    lf.cur = lf.base;

    if (fs->file_walk(fs, fsi, type, id, flags, fs_load_file_act,
	    (void *) &lf)) {
	free(lf.base);
	strncat(tsk_errstr2, " - fs_load_file",
	    TSK_ERRSTR_L - strlen(tsk_errstr2));
	return NULL;
    }

    /* Not all of the file was copied */
    if (lf.left > 0) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_FWALK;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "fs_load_file: Error reading file %" PRIuINUM, fsi->addr);
	free(lf.base);
	return NULL;
    }

    return lf.base;
}

// This size is based on the speed of the hard drive
// and the expected amount of fragmentation. 
#define FS_READ_FILE_CACHE_SZ	8 * 1024
typedef struct {
    char *base;
    char *cur;
    size_t size_to_copy;
    size_t size_left;
    size_t offset_left;
    char cache[FS_READ_FILE_CACHE_SZ];
    DADDR_T cache_base;
    uint8_t cache_inuse;
} FS_READ_FILE;

static uint8_t
fs_read_file_act(FS_INFO * fs, DADDR_T addr, char *buf, size_t size,
    int flags, void *ptr)
{
    FS_READ_FILE *buf1 = (FS_READ_FILE *) ptr;
    size_t cp_size;
    size_t blk_offset;

    /* Is this block too early in the stream? */
    if (buf1->offset_left > size) {
	buf1->offset_left -= size;
	return WALK_CONT;
    }

    blk_offset = buf1->offset_left;
    buf1->offset_left = 0;

    /* How much of the block are we going to copy? */
    if ((size - blk_offset) > buf1->size_left)
	cp_size = buf1->size_left;
    else
	cp_size = size - blk_offset;

    memcpy(buf1->cur, &buf[blk_offset], cp_size);
    buf1->cur = (char *) ((uintptr_t) buf1->cur + cp_size);

    buf1->size_left -= cp_size;
    if (buf1->size_left > 0)
	return WALK_CONT;
    else
	return WALK_STOP;
}

static uint8_t
fs_read_file_act_aonly(FS_INFO * fs, DADDR_T addr, char *buf, size_t size,
    int flags, void *ptr)
{
    FS_READ_FILE *buf1 = (FS_READ_FILE *) ptr;
    size_t cp_size;
    size_t blk_offset;

    /* Is this block too early in the stream? */
    if (buf1->offset_left > size) {
	buf1->offset_left -= size;
	return WALK_CONT;
    }

    blk_offset = buf1->offset_left;
    buf1->offset_left = 0;

    /* How much of the block are we going to copy? */
    if ((size - blk_offset) > buf1->size_left)
	cp_size = buf1->size_left;
    else
	cp_size = size - blk_offset;

    /* If the block is sparse, then simply write zeros */
    if (flags & FS_FLAG_DATA_SPARSE) {
	memset(buf1->cur, 0, cp_size);
    }
    else {
	/* First check if it is in the cache */
	if ((buf1->cache_inuse) &&
	    (addr >= buf1->cache_base) &&
	    ((addr - buf1->cache_base) * fs->block_size <
		FS_READ_FILE_CACHE_SZ)) {

	    size_t cache_offset =
		blk_offset + (addr - buf1->cache_base) * fs->block_size;

	    /* Check if the data we want starts in the cache, but is not fully in
	     * it.  From the check that starts the cache for the first time, we 
	     * know that cp_size will be less than the cache size (if we assume
	     * that all sizes in the call back are the same -- which is true 
	     * except for compressed NTFS -- which do not use this callback)
	     */
	    if (cache_offset + cp_size > FS_READ_FILE_CACHE_SZ) {
		fs_read_random(fs, buf1->cache, FS_READ_FILE_CACHE_SZ,
		    (addr * fs->block_size));
		buf1->cache_base = addr;
		cache_offset = blk_offset;
	    }
	    memcpy(buf1->cur, &buf1->cache[cache_offset], cp_size);
	}
	/* This case can start the cache and will be used when the data in the
	 * cache is not what we want 
	 * Make sure that we only use the cache we need more than 1 block and
	 * if the size of each callback is less than the cache size. */
	else if ((buf1->size_left > fs->block_size) &&
	    (size < FS_READ_FILE_CACHE_SZ)) {
	    fs_read_random(fs, buf1->cache, FS_READ_FILE_CACHE_SZ,
		(addr * fs->block_size));

	    buf1->cache_inuse = 1;
	    buf1->cache_base = addr;
	    memcpy(buf1->cur, &buf1->cache[blk_offset], cp_size);
	}
	/* Fallback case where we simply read into the buffer and ignore
	 * the cache */
	else {
	    fs_read_random(fs, buf1->cur, cp_size,
		(addr * fs->block_size) + blk_offset);
	}
    }

    buf1->cur = (char *) ((uintptr_t) buf1->cur + cp_size);

    buf1->size_left -= cp_size;
    if (buf1->size_left > 0)
	return WALK_CONT;
    else
	return WALK_STOP;
}


/* Internal method for reading files using a standard read type interface.
 * This is called by the two wrapper functions (the difference the two is
 * based on if a type and id are used (only NTFS uses them)
 */
static SSIZE_T
fs_read_file_int(FS_INFO * fs, FS_INODE * fsi, uint32_t type, uint16_t id,
    SSIZE_T offset, SSIZE_T size, char *buf, int flagsBase)
{
    FS_READ_FILE lf;
    int flags = flagsBase;

    lf.base = lf.cur = buf;
    lf.size_to_copy = lf.size_left = size;
    lf.offset_left = offset;
    lf.cache_inuse = 0;

    if (fsi->flags & FS_FLAG_META_UNALLOC) {
	flags |= FS_FLAG_FILE_RECOVER;
    }

    /* For compressed files, we must do a normal walk.  For non-compressed
     * files, we can simply do an AONLY walk and then read only the blocks 
     * that we need
     */
    if (fsi->flags & FS_FLAG_META_COMP) {
	if (fs->file_walk(fs, fsi, type, id, flags, fs_read_file_act,
		(void *) &lf)) {
	    strncat(tsk_errstr2, " - fs_read_file",
		TSK_ERRSTR_L - strlen(tsk_errstr2));
	    return -1;
	}
    }
    else {
	flags |= FS_FLAG_FILE_AONLY;
	if (fs->file_walk(fs, fsi, type, id, flags, fs_read_file_act_aonly,
		(void *) &lf)) {
	    strncat(tsk_errstr2, " - fs_read_file",
		TSK_ERRSTR_L - strlen(tsk_errstr2));
	    return -1;
	}
    }

    return lf.size_to_copy - lf.size_left;
}

SSIZE_T
fs_read_file_noid(FS_INFO * fs, FS_INODE * fsi,
    SSIZE_T offset, SSIZE_T size, char *buf)
{
    return fs_read_file_int(fs, fsi, 0, 0, offset, size, buf,
	FS_FLAG_FILE_NOID);
}

SSIZE_T
fs_read_file_noid_slack(FS_INFO * fs, FS_INODE * fsi,
    SSIZE_T offset, SSIZE_T size, char *buf)
{
    return fs_read_file_int(fs, fsi, 0, 0, offset, size, buf,
	FS_FLAG_FILE_NOID|FS_FLAG_FILE_SLACK);
}

/* return -1 on error or else the size of the data read
 */
SSIZE_T
fs_read_file(FS_INFO * fs, FS_INODE * fsi, uint32_t type, uint16_t id,
    SSIZE_T offset, SSIZE_T size, char *buf)
{
    return fs_read_file_int(fs, fsi, type, id, offset, size, buf, 0);
}
SSIZE_T
fs_read_file_slack(FS_INFO * fs, FS_INODE * fsi, uint32_t type, uint16_t id,
    SSIZE_T offset, SSIZE_T size, char *buf)
{
    return fs_read_file_int(fs, fsi, type, id, offset, size, buf, FS_FLAG_FILE_SLACK);
}
