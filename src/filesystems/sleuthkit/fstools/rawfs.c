/*
** The Sleuth Kit
**
** $Date: 2006/12/05 21:39:52 $
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2006 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2004-2005 Brian Carrier.  All rights reserved 
**
**
** This software is distributed under the Common Public License 1.0
** 
*/

#include "fs_tools_i.h"



/**************************************************************************
 *
 * INODE WALKING
 *
 **************************************************************************/

/* rawfs_inode_walk - inode iterator 
 *
 * return 1 on error and 0 on success
 */
uint8_t
rawfs_inode_walk(FS_INFO * fs, INUM_T start_inum, INUM_T end_inum,
    int flags, FS_INODE_WALK_FN action, void *ptr)
{
    tsk_error_reset();
    tsk_errno = TSK_ERR_FS_FUNC;
    snprintf(tsk_errstr, TSK_ERRSTR_L,
	"Illegal analysis method for raw data ");
    return 1;
}

static FS_INODE *
rawfs_inode_lookup(FS_INFO * fs, INUM_T inum)
{
    tsk_error_reset();
    tsk_errno = TSK_ERR_FS_FUNC;
    snprintf(tsk_errstr, TSK_ERRSTR_L,
	"Illegal analysis method for raw data");
    return NULL;
}


/**************************************************************************
 *
 * BLOCK WALKING
 *
 **************************************************************************/

/* rawpfs_block_walk - block iterator 
 *
 * flags used: ALIGN, META, ALLOC, UNALLOC
 *
 * return 1 on error and 0 on success
 */

uint8_t
rawfs_block_walk(FS_INFO * fs, DADDR_T start_blk, DADDR_T end_blk,
    int flags, FS_BLOCK_WALK_FN action, void *ptr)
{
    DATA_BUF *data_buf;
    DADDR_T addr;

    // clean up any error messages that are lying around
    tsk_error_reset();

    /*
     * Sanity checks.
     */
    if (start_blk < fs->first_block || start_blk > fs->last_block) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_WALK_RNG;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "rawfs_block_walk: Start block number: %" PRIuDADDR,
	    start_blk);
	return 1;
    }

    if (end_blk < fs->first_block || end_blk > fs->last_block
	|| end_blk < start_blk) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_WALK_RNG;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "rawfs_block_walk: Last block number: %" PRIuDADDR, end_blk);
	return 1;
    }

    /* If allocated is not wanted, then exit now */
    if (!(flags & FS_FLAG_DATA_ALLOC)) {
	return 0;
    }

    if ((data_buf = data_buf_alloc(fs->block_size)) == NULL) {
	return 1;
    }

    for (addr = start_blk; addr <= end_blk; addr++) {
	SSIZE_T cnt;
	int retval;

	cnt = fs_read_block(fs, data_buf, fs->block_size, addr);
	if (cnt != fs->block_size) {
	    if (cnt != -1) {
		tsk_error_reset();
		tsk_errno = TSK_ERR_FS_READ;
	    }
	    snprintf(tsk_errstr2, TSK_ERRSTR_L,
		"rawfs_block_walk: Block %" PRIuDADDR, addr);
	    data_buf_free(data_buf);
	    return 1;
	}

	retval = action(fs, addr, data_buf->data,
	    FS_FLAG_DATA_ALLOC | FS_FLAG_DATA_CONT, ptr);
	if (retval == WALK_STOP) {
	    data_buf_free(data_buf);
	    return 0;
	}
	else if (retval == WALK_ERROR) {
	    data_buf_free(data_buf);
	    return 1;
	}
    }

    /*
     * Cleanup.
     */
    data_buf_free(data_buf);
    return 0;
}

/**************************************************************************
 *
 * FILE WALKING
 *
 **************************************************************************/


/*  
 *  return 1 on error and 0 on success
 */
uint8_t
rawfs_file_walk(FS_INFO * fs, FS_INODE * inode, uint32_t type, uint16_t id,
    int flags, FS_FILE_WALK_FN action, void *ptr)
{
    tsk_error_reset();
    tsk_errno = TSK_ERR_FS_FUNC;
    snprintf(tsk_errstr, TSK_ERRSTR_L,
	" Illegal analysis method for raw data ");
    return 1;
}

/*
 * return 1 on error and 0 on success
 */
uint8_t
rawfs_dent_walk(FS_INFO * fs, INUM_T inode, int flags,
    FS_DENT_WALK_FN action, void *ptr)
{
    tsk_error_reset();
    tsk_errno = TSK_ERR_FS_FUNC;
    snprintf(tsk_errstr, TSK_ERRSTR_L,
	"Illegal analysis method for raw data");
    return 1;
}


/*
 * return 1 on error and 0 on success
 */
static uint8_t
rawfs_fsstat(FS_INFO * fs, FILE * hFile)
{
    tsk_fprintf(hFile, "Raw Data\n");
    tsk_fprintf(hFile, "Block Size: %d\n", fs->block_size);
    tsk_fprintf(hFile, "Block Range: 0 - %" PRIuDADDR "\n",
	fs->last_block);
    return 0;
}


/************************* istat *******************************/

/*
 * return 1 on error and 0 on success
 */
static uint8_t
rawfs_istat(FS_INFO * fs, FILE * hFile, INUM_T inum, DADDR_T numblock,
    int32_t sec_skew)
{
    tsk_error_reset();
    tsk_errno = TSK_ERR_FS_FUNC;
    snprintf(tsk_errstr, TSK_ERRSTR_L,
	" Illegal analysis method for raw data ");
    return 1;
}


/* return 1 on error and 0 on success
 */
uint8_t
rawfs_jopen(FS_INFO * fs, INUM_T inum)
{
    tsk_error_reset();
    tsk_errno = TSK_ERR_FS_FUNC;
    snprintf(tsk_errstr, TSK_ERRSTR_L, "RAW does not have a journal");
    return 1;
}

/*
 * return 1 on error and 0 on success
 */
uint8_t
rawfs_jentry_walk(FS_INFO * fs, int flags, FS_JENTRY_WALK_FN action,
    void *ptr)
{
    tsk_error_reset();
    tsk_errno = TSK_ERR_FS_FUNC;
    snprintf(tsk_errstr, TSK_ERRSTR_L, "RAW does not have a journal ");
    return 1;
}


/*
 * return 1 on error and 0 on success
 */
uint8_t
rawfs_jblk_walk(FS_INFO * fs, DADDR_T start, DADDR_T end, int flags,
    FS_JBLK_WALK_FN action, void *ptr)
{
    tsk_error_reset();
    tsk_errno = TSK_ERR_FS_FUNC;
    snprintf(tsk_errstr, TSK_ERRSTR_L, "RAW does not have a journal ");
    return 1;
}



/* rawfs_close - close a fast file system */
static void
rawfs_close(FS_INFO * fs)
{
    free(fs);
}


/* rawfs_open - open a file as raw 
 *
 * Return NULL on error
 * */
FS_INFO *
rawfs_open(IMG_INFO * img_info, SSIZE_T offset)
{
    OFF_T len;
    FS_INFO *fs;

    // clean up any error messages that are lying around
    tsk_error_reset();

    fs = (FS_INFO *) mymalloc(sizeof(FS_INFO));
    if (fs == NULL)
	return NULL;


    /* All we need to set are the block sizes and max block size etc. */
    fs->img_info = img_info;
    fs->offset = offset;

    fs->ftype = RAW;
    fs->flags = 0;

    fs->inum_count = 0;
    fs->root_inum = 0;
    fs->first_inum = 0;
    fs->last_inum = 0;

    len = img_info->get_size(img_info);
    fs->block_count = len / 512;
    if (len % 512)
	fs->block_count++;

    fs->first_block = 0;
    fs->last_block = fs->block_count - 1;
    fs->block_size = 512;
    fs->dev_bsize = 512;

    fs->inode_walk = rawfs_inode_walk;
    fs->block_walk = rawfs_block_walk;
    fs->inode_lookup = rawfs_inode_lookup;
    fs->dent_walk = rawfs_dent_walk;
    fs->file_walk = rawfs_file_walk;
    fs->fsstat = rawfs_fsstat;
    fs->istat = rawfs_istat;
    fs->close = rawfs_close;
    fs->jblk_walk = rawfs_jblk_walk;
    fs->jentry_walk = rawfs_jentry_walk;
    fs->jopen = rawfs_jopen;
    fs->journ_inum = 0;

    return (fs);
}
