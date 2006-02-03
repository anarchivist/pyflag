/*
** The Sleuth Kit 
**
** $Date: 2005/09/02 23:34:03 $
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2004-2005 Brian Carrier.  All rights reserved 
**
**
** This software is distributed under the Common Public License 1.0
**
*/

#include "fs_tools.h"


/**************************************************************************
 *
 * INODE WALKING
 *
 **************************************************************************/

/* swapfs_inode_walk - inode iterator 
 *
 */
void
swapfs_inode_walk(FS_INFO * fs, INUM_T start_inum, INUM_T end_inum,
		  int flags, FS_INODE_WALK_FN action, void *ptr)
{
    error("swapfs: Illegal analysis method for swap space data");
    return;
}

static FS_INODE *
swapfs_inode_lookup(FS_INFO * fs, INUM_T inum)
{
    error("swapfs: Illegal analysis method for swap space data");
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
 */

void
swapfs_block_walk(FS_INFO * fs, DADDR_T start_blk, DADDR_T end_blk,
		  int flags, FS_BLOCK_WALK_FN action, void *ptr)
{
    char *myname = "swapfs_block_walk";
    DATA_BUF *data_buf = data_buf_alloc(fs->block_size);
    DADDR_T addr;

    /*
     * Sanity checks.
     */
    if (start_blk < fs->first_block || start_blk > fs->last_block)
	error("%s: invalid start block number: %lu", myname, start_blk);

    if (end_blk < fs->first_block || end_blk > fs->last_block
	|| end_blk < start_blk)
	error("%s: invalid last block number: %lu", myname, end_blk);

    /* All we have is ALLOC */
    if (!(flags & FS_FLAG_DATA_ALLOC))
	return;

    for (addr = start_blk; addr <= end_blk; addr++) {

	if (fs_read_block(fs, data_buf, fs->block_size, addr) !=
	    fs->block_size) {
	    error("swapfs_block_walk: Error reading block at %" PRIuDADDR
		  ": %m", addr);
	}

	if (WALK_STOP == action(fs, addr, data_buf->data,
				FS_FLAG_DATA_ALLOC | FS_FLAG_DATA_CONT,
				ptr)) {
	    data_buf_free(data_buf);
	    return;
	}
    }

    /*
     * Cleanup.
     */
    data_buf_free(data_buf);
    return;
}

/**************************************************************************
 *
 * FILE WALKING
 *
 **************************************************************************/


/*  
 */
void
swapfs_file_walk(FS_INFO * fs, FS_INODE * inode, uint32_t type,
		 uint16_t id, int flags, FS_FILE_WALK_FN action, void *ptr)
{
    error("swapfs: Illegal analysis method for swap space data");
    return;
}

void
swapfs_dent_walk(FS_INFO * fs, INUM_T inode, int flags,
		 FS_DENT_WALK_FN action, void *ptr)
{
    error("swapfs: Illegal analysis method for swap space data");
    return;
}


static void
swapfs_fsstat(FS_INFO * fs, FILE * hFile)
{
    fprintf(hFile, "Swap Space\n");
    fprintf(hFile, "Page Size: %d\n", fs->block_size);
    return;
}


/************************* istat *******************************/

static void
swapfs_istat(FS_INFO * fs, FILE * hFile, INUM_T inum, int numblock,
	     int32_t sec_skew)
{
    error("swapfs: Illegal analysis method for swap space data");
    return;
}


void
swapfs_jopen(FS_INFO * fs, INUM_T inum)
{
    fprintf(stderr, "Error: SWAP does not have a journal\n");
    exit(1);
}

void
swapfs_jentry_walk(FS_INFO * fs, int flags, FS_JENTRY_WALK_FN action,
		   void *ptr)
{
    fprintf(stderr, "Error: SWAP does not have a journal\n");
    exit(1);
}


void
swapfs_jblk_walk(FS_INFO * fs, INUM_T start, INUM_T end, int flags,
		 FS_JBLK_WALK_FN action, void *ptr)
{
    fprintf(stderr, "Error: SWAP does not have a journal\n");
    exit(1);
}



/* swapfs_close - close a fast file system */
static void
swapfs_close(FS_INFO * fs)
{
    free(fs);
}


/* swaps_open - open a fast file system */

FS_INFO *
swapfs_open(IMG_INFO * img_info, unsigned char ftype)
{
    FS_INFO *fs = (FS_INFO *) mymalloc(sizeof(*fs));
    OFF_T len;

    if ((ftype & FSMASK) != SWAPFS_TYPE)
	error("Invalid FS Type in swapfs_open");


    /* All we need to set are the block sizes and max bloc size etc. */

    fs->img_info = img_info;
    fs->ftype = ftype;
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
