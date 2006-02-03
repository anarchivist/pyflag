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

/* rawfs_inode_walk - inode iterator 
 *
 */
void
rawfs_inode_walk(FS_INFO * fs, INUM_T start_inum, INUM_T end_inum,
		 int flags, FS_INODE_WALK_FN action, void *ptr)
{
    error("rawfs: Illegal analysis method for raw data");
    return;
}

static FS_INODE *
rawfs_inode_lookup(FS_INFO * fs, INUM_T inum)
{
    error("rawfs: Illegal analysis method for raw data");
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
 */

void
rawfs_block_walk(FS_INFO * fs, DADDR_T start_blk, DADDR_T end_blk,
		 int flags, FS_BLOCK_WALK_FN action, void *ptr)
{
    char *myname = "rawfs_block_walk";
    DATA_BUF *data_buf = data_buf_alloc(fs->block_size);
    DADDR_T addr;

    /*
     * Sanity checks.
     */
    if (start_blk < fs->first_block || start_blk > fs->last_block)
	error("%s: invalid start block number: %" PRIuDADDR "", myname,
	      start_blk);

    if (end_blk < fs->first_block || end_blk > fs->last_block
	|| end_blk < start_blk)
	error("%s: invalid last block number: %" PRIuDADDR "", myname,
	      end_blk);

    if (!(flags & FS_FLAG_DATA_ALLOC))
	return;

    for (addr = start_blk; addr <= end_blk; addr++) {
	if (fs_read_block(fs, data_buf, fs->block_size, addr) !=
	    fs->block_size) {
	    error("rawfs_block_walk: Error reading block at %" PRIuDADDR
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
rawfs_file_walk(FS_INFO * fs, FS_INODE * inode, uint32_t type, uint16_t id,
		int flags, FS_FILE_WALK_FN action, void *ptr)
{
    error("rawfs: Illegal analysis method for raw data");
    return;
}

void
rawfs_dent_walk(FS_INFO * fs, INUM_T inode, int flags,
		FS_DENT_WALK_FN action, void *ptr)
{
    error("rawfs: Illegal analysis method for raw data");
    return;
}


static void
rawfs_fsstat(FS_INFO * fs, FILE * hFile)
{
    fprintf(hFile, "Raw Data\n");
    fprintf(hFile, "Block Size: %d\n", fs->block_size);
    return;
}


/************************* istat *******************************/

static void
rawfs_istat(FS_INFO * fs, FILE * hFile, INUM_T inum, int numblock,
	    int32_t sec_skew)
{
    error("rawfs: Illegal analysis method for raw data");
    return;
}





void
rawfs_jopen(FS_INFO * fs, INUM_T inum)
{
    fprintf(stderr, "Error: RAW does not have a journal\n");
    exit(1);
}

void
rawfs_jentry_walk(FS_INFO * fs, int flags, FS_JENTRY_WALK_FN action,
		  void *ptr)
{
    fprintf(stderr, "Error: RAW does not have a journal\n");
    exit(1);
}


void
rawfs_jblk_walk(FS_INFO * fs, DADDR_T start, DADDR_T end, int flags,
		FS_JBLK_WALK_FN action, void *ptr)
{
    fprintf(stderr, "Error: RAW does not have a journal\n");
    exit(1);
}



/* rawfs_close - close a fast file system */
static void
rawfs_close(FS_INFO * fs)
{
    free(fs);
}


/* rawfs_open - open a fast file system */

FS_INFO *
rawfs_open(IMG_INFO * img_info, unsigned char ftype)
{
    FS_INFO *fs = (FS_INFO *) mymalloc(sizeof(FS_INFO));
    OFF_T len;

    if ((ftype & FSMASK) != RAWFS_TYPE)
	error("Invalid FS Type in rawfs_open");


    /* All we need to set are the block sizes and max bloc size etc. */
    fs->img_info = img_info;

    fs->ftype = ftype;
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
