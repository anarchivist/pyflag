/*
** The Sleuth Kit 
**
** $Date: 2007/04/04 20:06:58 $
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

/* swapfs_inode_walk - inode iterator 
 *
 * return 1 on error and 0 on success
 */
uint8_t
swapfs_inode_walk(TSK_FS_INFO * fs, INUM_T start_inum, INUM_T end_inum,
    TSK_FS_INODE_FLAG_ENUM flags, TSK_FS_INODE_WALK_CB action, void *ptr)
{
    tsk_error_reset();
    tsk_errno = TSK_ERR_FS_FUNC;
    snprintf(tsk_errstr, TSK_ERRSTR_L,
        "Illegal analysis method for swap space data");
    return 1;
}

static TSK_FS_INODE *
swapfs_inode_lookup(TSK_FS_INFO * fs, INUM_T inum)
{
    tsk_error_reset();
    tsk_errno = TSK_ERR_FS_FUNC;
    snprintf(tsk_errstr, TSK_ERRSTR_L,
        "Illegal analysis method for swap space data");
    return NULL;
}


/**************************************************************************
 *
 * BLOCK WALKING
 *
 **************************************************************************/

/* swapfs_block_walk - block iterator 
 *
 * flags used: ALLOC
 *
 * return 1 on error and 0 on success
 */

uint8_t
swapfs_block_walk(TSK_FS_INFO * fs, DADDR_T start_blk, DADDR_T end_blk,
    TSK_FS_BLOCK_FLAG_ENUM flags, TSK_FS_BLOCK_WALK_CB action, void *ptr)
{
    TSK_DATA_BUF *data_buf;
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
            "swapfs_block_walk: Start block number: %" PRIuDADDR,
            start_blk);
        return 1;
    }

    if (end_blk < fs->first_block || end_blk > fs->last_block
        || end_blk < start_blk) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_WALK_RNG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "swapfs_block_walk: Last block number: %" PRIuDADDR, end_blk);
        return 1;
    }

    /* All swap has is allocated blocks... exit if not wanted */
    if (!(flags & TSK_FS_BLOCK_FLAG_ALLOC)) {
        return 0;
    }

    if ((data_buf = tsk_data_buf_alloc(fs->block_size)) == NULL) {
        return 1;
    }

    for (addr = start_blk; addr <= end_blk; addr++) {
        SSIZE_T cnt;
        int retval;

        cnt = tsk_fs_read_block(fs, data_buf, fs->block_size, addr);
        if (cnt != fs->block_size) {
            if (cnt != -1) {
                tsk_error_reset();
                tsk_errno = TSK_ERR_FS_READ;
            }
            snprintf(tsk_errstr2, TSK_ERRSTR_L,
                "swapfs_block_walk: Block %" PRIuDADDR, addr);
            tsk_data_buf_free(data_buf);
            return 1;
        }

        retval = action(fs, addr, data_buf->data,
            TSK_FS_BLOCK_FLAG_ALLOC | TSK_FS_BLOCK_FLAG_CONT, ptr);

        if (retval == TSK_WALK_STOP) {
            tsk_data_buf_free(data_buf);
            return 0;
        }
        else if (retval == TSK_WALK_ERROR) {
            tsk_data_buf_free(data_buf);
            return 1;
        }
    }

    /*
     * Cleanup.
     */
    tsk_data_buf_free(data_buf);
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
swapfs_file_walk(TSK_FS_INFO * fs, TSK_FS_INODE * inode, uint32_t type,
    uint16_t id, TSK_FS_FILE_FLAG_ENUM flags,
    TSK_FS_FILE_WALK_CB action, void *ptr)
{
    tsk_error_reset();
    tsk_errno = TSK_ERR_FS_FUNC;
    snprintf(tsk_errstr, TSK_ERRSTR_L,
        "Illegal analysis method for swap space data");
    return 1;
}

/*
 * return 1 on error and 0 on success
 */
uint8_t
swapfs_dent_walk(TSK_FS_INFO * fs, INUM_T inode,
    TSK_FS_DENT_FLAG_ENUM flags, TSK_FS_DENT_TYPE_WALK_CB action,
    void *ptr)
{
    tsk_error_reset();
    tsk_errno = TSK_ERR_FS_FUNC;
    snprintf(tsk_errstr, TSK_ERRSTR_L,
        "Illegal analysis method for swap space data");
    return 1;
}


/*
 * return 1 on error and 0 on success
 */
static uint8_t
swapfs_fsstat(TSK_FS_INFO * fs, FILE * hFile)
{
    tsk_fprintf(hFile, "Swap Space\n");
    tsk_fprintf(hFile, "Page Size: %d\n", fs->block_size);
    tsk_fprintf(hFile, "Page Range: 0 - %" PRIuDADDR "\n", fs->last_block);
    return 0;
}


/************************* istat *******************************/

/* Return 1 on error and 0 on success */
static uint8_t
swapfs_istat(TSK_FS_INFO * fs, FILE * hFile, INUM_T inum, DADDR_T numblock,
    int32_t sec_skew)
{
    tsk_error_reset();
    tsk_errno = TSK_ERR_FS_FUNC;
    snprintf(tsk_errstr, TSK_ERRSTR_L,
        "Illegal analysis method for swap space data");
    return 1;
}


/* Return 1 on error and 0 on success */
uint8_t
swapfs_jopen(TSK_FS_INFO * fs, INUM_T inum)
{
    tsk_error_reset();
    tsk_errno = TSK_ERR_FS_FUNC;
    snprintf(tsk_errstr, TSK_ERRSTR_L, "SWAP does not have a journal\n");
    return 1;
}

/* Return 1 on error and 0 on success */
uint8_t
swapfs_jentry_walk(TSK_FS_INFO * fs, int flags,
    TSK_FS_JENTRY_WALK_CB action, void *ptr)
{
    tsk_error_reset();
    tsk_errno = TSK_ERR_FS_FUNC;
    snprintf(tsk_errstr, TSK_ERRSTR_L, "SWAP does not have a journal\n");
    return 1;
}


/* Return 1 on error and 0 on success */
uint8_t
swapfs_jblk_walk(TSK_FS_INFO * fs, INUM_T start, INUM_T end, int flags,
    TSK_FS_JBLK_WALK_CB action, void *ptr)
{
    tsk_error_reset();
    tsk_errno = TSK_ERR_FS_FUNC;
    snprintf(tsk_errstr, TSK_ERRSTR_L, "SWAP does not have a journal\n");
    return 1;
}



/* swapfs_close - close a fast file system */
static void
swapfs_close(TSK_FS_INFO * fs)
{
    free(fs);
}


/* swaps_open - open a swap file
 * Return TSK_FS_INFO on success and NULL on error
 * */

TSK_FS_INFO *
swapfs_open(TSK_IMG_INFO * img_info, SSIZE_T offset)
{
    OFF_T len;
    TSK_FS_INFO *fs;

    // clean up any error messages that are lying around
    tsk_error_reset();

    fs = (TSK_FS_INFO *) tsk_malloc(sizeof(*fs));
    if (fs == NULL)
        return NULL;


    /* All we need to set are the block sizes and max bloc size etc. */
    fs->img_info = img_info;
    fs->offset = offset;
    fs->ftype = TSK_FS_INFO_TYPE_SWAP;
    fs->duname = "Page";
    fs->flags = 0;

    fs->inum_count = 0;
    fs->root_inum = 0;
    fs->first_inum = 0;
    fs->last_inum = 0;

    len = img_info->get_size(img_info);
    fs->block_count = len / 4096;
    if (len % 4096)
        fs->block_count++;

    fs->first_block = 0;
    fs->last_block = fs->block_count - 1;
    fs->block_size = 4096;
    fs->dev_bsize = 512;

    fs->inode_walk = swapfs_inode_walk;
    fs->block_walk = swapfs_block_walk;
    fs->inode_lookup = swapfs_inode_lookup;
    fs->dent_walk = swapfs_dent_walk;
    fs->file_walk = swapfs_file_walk;
    fs->fsstat = swapfs_fsstat;
    fs->istat = swapfs_istat;
    fs->close = swapfs_close;
    fs->jblk_walk = swapfs_jblk_walk;
    fs->jentry_walk = swapfs_jentry_walk;
    fs->jopen = swapfs_jopen;
    fs->journ_inum = 0;


    return (fs);
}
