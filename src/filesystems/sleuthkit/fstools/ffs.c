/*
** The Sleuth Kit 
**
** $Date: 2005/09/02 19:53:27 $
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002-2003 Brian Carrier, @stake Inc.  All rights reserved
** 
** Copyright (c) 1997,1998,1999, International Business Machines          
** Corporation and others. All Rights Reserved.
*/

/* TCT 
 * LICENSE
 *	This software is distributed under the IBM Public License.
 * AUTHOR(S)
 *	Wietse Venema
 *	IBM T.J. Watson Research
 *	P.O. Box 704
 *	Yorktown Heights, NY 10598, USA
 --*/

#include "fs_tools.h"
#include "ffs.h"



/* ffs_group_load - load cylinder group descriptor info into cache */
static void
ffs_group_load(FFS_INFO * ffs, FFS_GRPNUM_T grp_num)
{
    DADDR_T addr;
    FS_INFO *fs = (FS_INFO *) & ffs->fs_info;

    /*
     * Sanity check
     */
    if (grp_num < 0 || grp_num >= ffs->groups_count)
	error("invalid cylinder group number: %" PRI_FFSGRP "", grp_num);

    /*
     * Allocate/read cylinder group info on the fly. Trust that a cylinder
     * group always fits within a logical disk block (as promised in the
     * 4.4BSD <ufs/ffs/fs.h> include file).
     */
    if (ffs->grp_buf == NULL)
	ffs->grp_buf = data_buf_alloc(ffs->ffsbsize_b);

    addr = cgtod_lcl(fs, ffs->fs.sb1, grp_num);
    if (ffs->grp_buf->addr != addr) {
	if (fs_read_block(fs, ffs->grp_buf, ffs->grp_buf->size, addr) !=
	    ffs->grp_buf->size) {
	    error("ffs_group_load: Error reading group %d at %"
		  PRIuDADDR ":  %m", grp_num, addr);
	}
    }

    ffs->grp_num = grp_num;
}


/* 
 * ffs_dinode_load - read disk inode and load into local cache (ffs->dino_buf)
 */

static void
ffs_dinode_load(FFS_INFO * ffs, INUM_T inum)
{
    DADDR_T addr;
    OFF_T offs;
    FS_INFO *fs = (FS_INFO *) & ffs->fs_info;

    /*
     * Sanity check.
     */
    if (inum < fs->first_inum || inum > fs->last_inum)
	error("invalid inode number: %" PRIuINUM "", inum);

    /*
     * Allocate/read the inode table buffer on the fly.
     */
    if (ffs->itbl_buf == NULL)
	ffs->itbl_buf = data_buf_alloc(ffs->ffsbsize_b);


    /* UFS2 is different because it does not initialize all inodes
     * when the file system is created.  Therefore we need to check
     * the group descriptor to find out if this is in the valid
     * range
     */
    if (fs->ftype == FFS_2) {
	ffs_cgd2 *cg2;
	FFS_GRPNUM_T grp_num;

	if (ffs->dino_buf == NULL)
	    ffs->dino_buf = (char *) mymalloc(sizeof(ffs_inode2));
	else if (ffs->dino_inum == inum)
	    return;

	/* Lookup the cylinder group descriptor if it isn't
	 * cached
	 */
	grp_num = itog_lcl(fs, ffs->fs.sb1, inum);
	if ((ffs->grp_buf == NULL) || (grp_num != ffs->grp_num))
	    ffs_group_load(ffs, grp_num);

	cg2 = (ffs_cgd2 *) ffs->grp_buf->data;

	/* If the inode is not init, then do not worry about it */
	if ((inum - grp_num * getu32(fs, ffs->fs.sb2->cg_inode_num)) >=
	    getu32(fs, cg2->cg_initediblk)) {
	    memset((char *) ffs->dino_buf, 0, sizeof(ffs_inode2));
	}

	else {
	    /* Get the base and offset addr for the inode in the tbl */
	    addr = itod_lcl(fs, ffs->fs.sb1, inum);

	    if (ffs->itbl_buf->addr != addr) {
		if (fs_read_block
		    (fs, ffs->itbl_buf, ffs->itbl_buf->size,
		     addr) != ffs->itbl_buf->size) {
		    error
			("ffs_dinode_load: Error reading FFS2 inode table at %"
			 PRIuDADDR ":  %m", addr);
		}
	    }

	    offs = itoo_lcl(fs, ffs->fs.sb2, inum) * sizeof(ffs_inode2);

	    memcpy((char *) ffs->dino_buf, ffs->itbl_buf->data + offs,
		   sizeof(ffs_inode2));
	}
    }
    else {
	if (ffs->dino_buf == NULL)
	    ffs->dino_buf = (char *) mymalloc(sizeof(ffs_inode1));
	else if (ffs->dino_inum == inum)
	    return;

	addr = itod_lcl(fs, ffs->fs.sb1, inum);
	if (ffs->itbl_buf->addr != addr) {
	    if (fs_read_block(fs, ffs->itbl_buf, ffs->itbl_buf->size, addr)
		!= ffs->itbl_buf->size) {
		error
		    ("ffs_dinode_load: Error reading FFS1 inode table at %"
		     PRIuDADDR ":  %m", addr);
	    }
	}

	offs = itoo_lcl(fs, ffs->fs.sb1, inum) * sizeof(ffs_inode1);

	memcpy((char *) ffs->dino_buf, ffs->itbl_buf->data + offs,
	       sizeof(ffs_inode1));
    }

    ffs->dino_inum = inum;

    return;
}



/* ffs_dinode_copy - copy cached disk inode to generic inode  
 */
static void
ffs_dinode_copy(FFS_INFO * ffs, FS_INODE * fs_inode)
{
    int i, j;
    unsigned int count;
    FS_INFO *fs = &(ffs->fs_info);
    FFS_GRPNUM_T grp_num;
    ffs_cgd *cg;
    unsigned char *inosused = NULL;
    INUM_T ibase;

    fs_inode->flags = 0;
    fs_inode->seq = 0;
    fs_inode->addr = ffs->dino_inum;

    /* If the symlink field is set from a previous run, then free it */
    if (fs_inode->link) {
	free(fs_inode->link);
	fs_inode->link = NULL;
    }

    /* OpenBSD and FreeBSD style */
    if (fs->ftype == FFS_1) {
	ffs_inode1 *in = (ffs_inode1 *) ffs->dino_buf;

	fs_inode->mode = getu16(fs, in->di_mode);
	fs_inode->nlink = gets16(fs, in->di_nlink);
	fs_inode->size = getu64(fs, in->di_size);
	fs_inode->uid = getu32(fs, in->di_uid);
	fs_inode->gid = getu32(fs, in->di_gid);

	fs_inode->mtime = gets32(fs, in->di_mtime);
	fs_inode->atime = gets32(fs, in->di_atime);
	fs_inode->ctime = gets32(fs, in->di_ctime);

	if (fs_inode->direct_count != FFS_NDADDR ||
	    fs_inode->indir_count != FFS_NIADDR)
	    fs_inode_realloc(fs_inode, FFS_NDADDR, FFS_NIADDR);

	for (i = 0; i < FFS_NDADDR; i++)
	    fs_inode->direct_addr[i] = gets32(fs, in->di_db[i]);

	for (i = 0; i < FFS_NIADDR; i++)
	    fs_inode->indir_addr[i] = gets32(fs, in->di_ib[i]);


	/* set the link string (if the file is a link) 
	 * The size check is a sanity check so that we don't try and allocate
	 * a huge amount of memory for a bad inode value
	 */
	if (((fs_inode->mode & FS_INODE_FMT) == FS_INODE_LNK) &&
	    (fs_inode->size < FFS_MAXPATHLEN) && (fs_inode->size >= 0)) {

	    fs_inode->link = mymalloc(fs_inode->size + 1);

	    count = 0;		/* index into the link array */

	    /* it is located directly in the pointers  
	     * Only the new style inode has this "fast link"
	     */
	    if (fs_inode->size < 4 * (FFS_NDADDR + FFS_NIADDR)) {
		char *ptr;

		/* Direct block pointer locations */
		for (i = 0; i < FFS_NDADDR && count < fs_inode->size; i++) {
		    ptr = (char *) &in->di_db[i];
		    for (j = 0; j < 4 && count < fs_inode->size; j++)
			fs_inode->link[count++] = ptr[j];
		}

		/* indirect block pointers */
		for (i = 0; i < FFS_NIADDR && count < fs_inode->size; i++) {
		    ptr = (char *) &in->di_ib[i];
		    for (j = 0; j < 4 && count < fs_inode->size; j++)
			fs_inode->link[count++] = ptr[j];
		}

		fs_inode->link[count] = '\0';

		/* clear the values to avoid other code from reading them */
		for (i = 0; i < FFS_NDADDR; i++)
		    fs_inode->direct_addr[i] = 0;

		for (i = 0; i < FFS_NIADDR; i++)
		    fs_inode->indir_addr[i] = 0;
	    }

	    /* it is in blocks (the regular way) */
	    else {
		DATA_BUF *data_buf = data_buf_alloc(fs->block_size);
		char *ptr = fs_inode->link;

		/* there is a max link length of 1000, so we should never
		 * need the indirect blocks
		 */
		for (i = 0; i < FFS_NDADDR && count < fs_inode->size; i++) {
		    /* Do we need the entire block, or just part of it? */
		    int read_count =
			(fs_inode->size - count <
			 fs->block_size) ? fs_inode->size -
			count : fs->block_size;

		    if (fs_read_block(fs, data_buf, fs->block_size,
				      fs_inode->direct_addr[i]) !=
			fs->block_size) {
			error
			    ("ffs_dinode_copy: Error reading FFS1A symlink destination at %"
			     PRIuDADDR ":  %m", fs_inode->direct_addr[i]);
		    }

		    memcpy(ptr, data_buf->data, read_count);
		    count += read_count;
		    ptr = (char *) ((uintptr_t) ptr + read_count);
		}
		/* terminate the string */
		*ptr = '\0';

		data_buf_free(data_buf);
	    }
	}			/* end of symlink */
    }
    /* FFS_1B - Solaris */
    else if (fs->ftype == FFS_1B) {
	ffs_inode1b *in = (ffs_inode1b *) ffs->dino_buf;

	fs_inode->mode = getu16(fs, in->di_mode);
	fs_inode->nlink = gets16(fs, in->di_nlink);
	fs_inode->size = getu64(fs, in->di_size);
	fs_inode->uid = getu32(fs, in->di_uid);
	fs_inode->gid = getu32(fs, in->di_gid);

	fs_inode->mtime = gets32(fs, in->di_mtime);
	fs_inode->atime = gets32(fs, in->di_atime);
	fs_inode->ctime = gets32(fs, in->di_ctime);

	if (fs_inode->direct_count != FFS_NDADDR ||
	    fs_inode->indir_count != FFS_NIADDR)
	    fs_inode_realloc(fs_inode, FFS_NDADDR, FFS_NIADDR);

	for (i = 0; i < FFS_NDADDR; i++)
	    fs_inode->direct_addr[i] = gets32(fs, in->di_db[i]);

	for (i = 0; i < FFS_NIADDR; i++)
	    fs_inode->indir_addr[i] = gets32(fs, in->di_ib[i]);

	if (((fs_inode->mode & FS_INODE_FMT) == FS_INODE_LNK) &&
	    (fs_inode->size < FFS_MAXPATHLEN) && (fs_inode->size >= 0)) {

	    /* This inode type doesn't have fast links */
	    DATA_BUF *data_buf = data_buf_alloc(fs->block_size);
	    char *ptr;
	    fs_inode->link = ptr = mymalloc(fs_inode->size + 1);

	    count = 0;		/* index into the link array */

	    /* there is a max link length of 1000, so we should never
	     * need the indirect blocks
	     */
	    for (i = 0; i < FFS_NDADDR && count < fs_inode->size; i++) {
		/* Do we need the entire block, or just part of it? */
		int read_count =
		    (fs_inode->size - count <
		     fs->block_size) ? fs_inode->size -
		    count : fs->block_size;

		if (fs_read_block(fs, data_buf, fs->block_size,
				  fs_inode->direct_addr[i]) !=
		    fs->block_size) {
		    error
			("ffs_dinode_copy: Error reading FFS1B symlink destination at %"
			 PRIuDADDR ":  %m", fs_inode->direct_addr[i]);
		}

		memcpy(ptr, data_buf->data, read_count);
		count += read_count;
		ptr = (char *) ((uintptr_t) ptr + read_count);
	    }

	    /* terminate the string */
	    *ptr = '\0';

	    data_buf_free(data_buf);
	}
    }
    else if (fs->ftype == FFS_2) {
	ffs_inode2 *in = (ffs_inode2 *) ffs->dino_buf;

	fs_inode->mode = getu16(fs, in->di_mode);
	fs_inode->nlink = gets16(fs, in->di_nlink);
	fs_inode->size = getu64(fs, in->di_size);
	fs_inode->uid = getu32(fs, in->di_uid);
	fs_inode->gid = getu32(fs, in->di_gid);

	fs_inode->mtime = (time_t) gets64(fs, in->di_mtime);
	fs_inode->atime = (time_t) gets64(fs, in->di_atime);
	fs_inode->ctime = (time_t) gets64(fs, in->di_ctime);

	if (fs_inode->direct_count != FFS_NDADDR ||
	    fs_inode->indir_count != FFS_NIADDR)
	    fs_inode_realloc(fs_inode, FFS_NDADDR, FFS_NIADDR);

	for (i = 0; i < FFS_NDADDR; i++)
	    fs_inode->direct_addr[i] = gets64(fs, in->di_db[i]);

	for (i = 0; i < FFS_NIADDR; i++)
	    fs_inode->indir_addr[i] = gets64(fs, in->di_ib[i]);


	/* set the link string (if the file is a link) 
	 * The size check is a sanity check so that we don't try and allocate
	 * a huge amount of memory for a bad inode value
	 */
	if (((fs_inode->mode & FS_INODE_FMT) == FS_INODE_LNK) &&
	    (fs_inode->size < FFS_MAXPATHLEN) && (fs_inode->size >= 0)) {

	    fs_inode->link = mymalloc(fs_inode->size + 1);

	    count = 0;		/* index into the link array */

	    /* it is located directly in the pointers  
	     * Only the new style inode has this "fast link"
	     */
	    if (fs_inode->size < 8 * (FFS_NDADDR + FFS_NIADDR)) {
		char *ptr;

		/* Direct block pointer locations */
		for (i = 0; i < FFS_NDADDR && count < fs_inode->size; i++) {
		    ptr = (char *) &in->di_db[i];
		    for (j = 0; j < 8 && count < fs_inode->size; j++)
			fs_inode->link[count++] = ptr[j];
		}

		/* indirect block pointers */
		for (i = 0; i < FFS_NIADDR && count < fs_inode->size; i++) {
		    ptr = (char *) &in->di_ib[i];
		    for (j = 0; j < 8 && count < fs_inode->size; j++)
			fs_inode->link[count++] = ptr[j];
		}

		fs_inode->link[count] = '\0';

		/* clear the values to avoid other code from reading them */
		for (i = 0; i < FFS_NDADDR; i++)
		    fs_inode->direct_addr[i] = 0;

		for (i = 0; i < FFS_NIADDR; i++)
		    fs_inode->indir_addr[i] = 0;
	    }

	    /* it is in blocks (the regular way) */
	    else {
		DATA_BUF *data_buf = data_buf_alloc(fs->block_size);
		char *ptr = fs_inode->link;

		/* there is a max link length of 1000, so we should never
		 * need the indirect blocks
		 */
		for (i = 0; i < FFS_NDADDR && count < fs_inode->size; i++) {
		    /* Do we need the entire block, or just part of it? */
		    int read_count =
			(fs_inode->size - count <
			 fs->block_size) ? fs_inode->size -
			count : fs->block_size;

		    if (fs_read_block(fs, data_buf, fs->block_size,
				      fs_inode->direct_addr[i]) !=
			fs->block_size) {
			error
			    ("ffs_dinode_copy: Error reading FFS2 symlink destination at %"
			     PRIuDADDR ":  %m", fs_inode->direct_addr[i]);
		    }

		    memcpy(ptr, data_buf->data, read_count);
		    count += read_count;
		    ptr = (char *) ((uintptr_t) ptr + read_count);
		}
		/* terminate the string */
		*ptr = '\0';

		data_buf_free(data_buf);
	    }
	}			/* end of symlink */
    }
    else {
	error("copy_inode: Unknown FFS Type");
    }

    /* set the flags */
    grp_num = itog_lcl(fs, ffs->fs.sb1, ffs->dino_inum);
    if ((ffs->grp_buf == NULL) || (grp_num != ffs->grp_num))
	ffs_group_load(ffs, grp_num);

    cg = (ffs_cgd *) ffs->grp_buf->data;

    inosused = (unsigned char *) cg_inosused_lcl(fs, cg);
    ibase = grp_num * gets32(fs, ffs->fs.sb1->cg_inode_num);

    /* get the alloc flag */
    fs_inode->flags = (isset(inosused, ffs->dino_inum - ibase) ?
		       FS_FLAG_META_ALLOC : FS_FLAG_META_UNALLOC);

    /* link flag */
    fs_inode->flags |= (fs_inode->nlink ?
			FS_FLAG_META_LINK : FS_FLAG_META_UNLINK);

    /* used/unused */
    fs_inode->flags |= (fs_inode->ctime ?
			FS_FLAG_META_USED : FS_FLAG_META_UNUSED);

}



/* ffs_inode_lookup - lookup inode, external interface */
static FS_INODE *
ffs_inode_lookup(FS_INFO * fs, INUM_T inum)
{
    FFS_INFO *ffs = (FFS_INFO *) fs;
    FS_INODE *fs_inode;

    /* Lookup the inode and store it in ffs */
    ffs_dinode_load(ffs, inum);

    /* copy it to the FS_INODE structure */
    fs_inode = fs_inode_alloc(FFS_NDADDR, FFS_NIADDR);
    ffs_dinode_copy(ffs, fs_inode);

    return (fs_inode);
}



/**************************************************************************
 *
 * INODE WALKING
 *
 **************************************************************************/

/* ffs_inode_walk - inode iterator 
 *
 * flags used: FS_FLAG_META_USED, FS_FLAG_META_UNUSED, 
 *  FS_FLAG_META_LINK, FS_FLAG_META_UNLINK, 
 *  FS_FLAG_META_ALLOC, FS_FLAG_META_UNALLOC
 */
void
ffs_inode_walk(FS_INFO * fs, INUM_T start_inum, INUM_T end_inum, int flags,
	       FS_INODE_WALK_FN action, void *ptr)
{
    char *myname = "ffs_inode_walk";
    FFS_INFO *ffs = (FFS_INFO *) fs;
    FFS_GRPNUM_T grp_num;
    ffs_cgd *cg = NULL;
    INUM_T inum;
    unsigned char *inosused = NULL;
    FS_INODE *fs_inode = fs_inode_alloc(FFS_NDADDR, FFS_NIADDR);
    int myflags;
    INUM_T ibase = 0;

    /*
     * Sanity checks.
     */
    if (start_inum < fs->first_inum || start_inum > fs->last_inum)
	error("%s: invalid start inode number: %" PRIuINUM "", myname,
	      start_inum);
    if (end_inum < fs->first_inum || end_inum > fs->last_inum
	|| end_inum < start_inum)
	error("%s: invalid end inode number: %" PRIuINUM "", myname,
	      end_inum);

    /*
     * Iterate. This is easy because inode numbers are contiguous, unlike
     * data blocks which are interleaved with cylinder group blocks.
     */
    for (inum = start_inum; inum <= end_inum; inum++) {

	/*
	 * Be sure to use the proper cylinder group data.
	 */
	grp_num = itog_lcl(fs, ffs->fs.sb1, inum);

	if ((ffs->grp_buf == NULL) || (grp_num != ffs->grp_num)) {
	    ffs_group_load(ffs, grp_num);
	    cg = NULL;
	}

	/* Load up the cached one if the needed one was already loaded or if a new was just loaded */
	if (cg == NULL) {
	    cg = (ffs_cgd *) ffs->grp_buf->data;
	    inosused = (unsigned char *) cg_inosused_lcl(fs, cg);
	    ibase = grp_num * gets32(fs, ffs->fs.sb1->cg_inode_num);
	}

	/*
	 * Apply the allocated/unallocated restriction.
	 */
	myflags = (isset(inosused, inum - ibase) ?
		   FS_FLAG_META_ALLOC : FS_FLAG_META_UNALLOC);
	if ((flags & myflags) != myflags)
	    continue;

	ffs_dinode_load(ffs, inum);


	if ((fs->ftype == FFS_1) || (fs->ftype == FFS_1B)) {
	    /* both inode forms are the same for the required fields */
	    ffs_inode1 *in1 = (ffs_inode1 *) ffs->dino_buf;

	    /*
	     * Apply the linked/unlinked restriction.
	     */
	    myflags |= (gets16(fs, in1->di_nlink) ?
			FS_FLAG_META_LINK : FS_FLAG_META_UNLINK);
	    if ((flags & myflags) != myflags)
		continue;

	    /*
	     * Apply the used/unused restriction.
	     */
	    myflags |= (gets32(fs, in1->di_ctime) ?
			FS_FLAG_META_USED : FS_FLAG_META_UNUSED);
	    if ((flags & myflags) != myflags)
		continue;
	}
	else {
	    ffs_inode2 *in2 = (ffs_inode2 *) ffs->dino_buf;

	    /*
	     * Apply the linked/unlinked restriction.
	     */
	    myflags |= (gets16(fs, in2->di_nlink) ?
			FS_FLAG_META_LINK : FS_FLAG_META_UNLINK);
	    if ((flags & myflags) != myflags)
		continue;

	    /*
	     * Apply the used/unused restriction.
	     */
	    myflags |= (gets64(fs, in2->di_ctime) ?
			FS_FLAG_META_USED : FS_FLAG_META_UNUSED);
	    if ((flags & myflags) != myflags)
		continue;
	}

	/*
	 * Fill in a file system-independent inode structure and pass control
	 * to the application.
	 */
	ffs_dinode_copy(ffs, fs_inode);
	fs_inode->flags = myflags;
	if (WALK_STOP == action(fs, fs_inode, myflags, ptr)) {
	    fs_inode_free(fs_inode);
	    return;
	}
    }

    /*
     * Cleanup.
     */
    fs_inode_free(fs_inode);
}


/**************************************************************************
 *
 * BLOCK WALKING
 *
 **************************************************************************/

/* ffs_block_walk - block iterator 
 *
 * flags: FS_FLAG_DATA_ALLOC, FS_FLAG_DATA_UNALLOC, FS_FLAG_DATA_CONT,
 *  FS_FLAG_DATA_META, FS_FLAG_DATA_ALIGN
 */

void
ffs_block_walk(FS_INFO * fs, DADDR_T start_blk, DADDR_T end_blk, int flags,
	       FS_BLOCK_WALK_FN action, void *ptr)
{
    char *myname = "ffs_block_walk";
    FFS_INFO *ffs = (FFS_INFO *) fs;
    DATA_BUF *data_buf = data_buf_alloc(fs->block_size * ffs->ffsbsize_f);
    FFS_GRPNUM_T grp_num;
    ffs_cgd *cg = 0;
    DADDR_T dbase = 0;
    DADDR_T dmin = 0;		/* first data block in group */
    DADDR_T sblock = 0;		/* super block in group */
    DADDR_T addr;
    DADDR_T faddr;
    unsigned char *freeblocks = NULL;
    int myflags;
    int want;
    int frags;
    char *null_block = NULL;

    /*
     * Sanity checks.
     */
    if (start_blk < fs->first_block || start_blk > fs->last_block)
	error("%s: invalid start block number: %" PRIuDADDR "", myname,
	      start_blk);

    if (end_blk < fs->first_block || end_blk > fs->last_block
	|| end_blk < start_blk)
	error("%s: invalid end block number: %" PRIuDADDR "", myname,
	      end_blk);

    if ((flags & FS_FLAG_DATA_ALIGN) && (start_blk % ffs->ffsbsize_f) != 0)
	error("%s: specify -b or specify block-aligned start block",
	      myname);

    /*
     * Other initialization.
     */
    if (flags & FS_FLAG_DATA_ALIGN) {
	null_block = mymalloc(fs->block_size);
	memset(null_block, 0, fs->block_size);
    }

    /*
     * Iterate. This is not as tricky as it could be, because the free list
     * map covers the entire disk partition, including blocks occupied by
     * cylinder group maps, boot blocks, and other non-data blocks.
     * 
     * Examine the disk one logical block at a time. A logical block may be
     * composed of a number of fragment blocks. For example, the 4.4BSD
     * filesystem has logical blocks of 8 fragments.
     */
    for (addr = start_blk; addr <= end_blk; addr += ffs->ffsbsize_f) {

	/*
	 * Be sure to use the right cylinder group information.
	 */
	grp_num = dtog_lcl(fs, ffs->fs.sb1, addr);
	if (cg == 0 || (unsigned int) gets32(fs, cg->cg_cgx) != grp_num) {
	    ffs_group_load(ffs, grp_num);
	    cg = (ffs_cgd *) ffs->grp_buf->data;
	    freeblocks = (unsigned char *) cg_blksfree_lcl(fs, cg);
	    dbase = cgbase_lcl(fs, ffs->fs.sb1, grp_num);
	    dmin = cgdmin_lcl(fs, ffs->fs.sb1, grp_num);
	    sblock = cgsblock_lcl(fs, ffs->fs.sb1, grp_num);
	}
	if (addr < dbase)
	    remark("impossible: cyl group %lu: block %lu < cgbase %lu",
		   (unsigned long) grp_num, (unsigned long) addr,
		   (unsigned long) dbase);

	/*
	 * Prepare for file systems that have a partial last logical block.
	 */
	frags = (end_blk + 1 - addr > ffs->ffsbsize_f ?
		 ffs->ffsbsize_f : end_blk + 1 - addr);

	/*
	 * See if this logical block contains any fragments of interest. If
	 * not, skip the entire logical block.
	 */
	for (want = 0, faddr = addr; want == 0 && faddr < addr + frags;
	     faddr++) {
	    want =
		(flags &
		 (isset(freeblocks, faddr - dbase) ? FS_FLAG_DATA_UNALLOC :
		  FS_FLAG_DATA_ALLOC));
	}
	if (want == 0)
	    continue;

	/*
	 * Pass blocks of interest to the application, optionally padding the
	 * data with null blocks in order to maintain logical block
	 * alignment.
	 *
	 * Beware: FFS stores file data in the blocks between the start of a
	 * cylinder group and the start of its super block.
	 */
	for (faddr = addr; faddr < addr + frags; faddr++) {
	    myflags = (isset(freeblocks, faddr - dbase) ?
		       FS_FLAG_DATA_UNALLOC : FS_FLAG_DATA_ALLOC);
	    if (faddr >= sblock && faddr < dmin)
		myflags |= FS_FLAG_DATA_META;
	    else
		myflags |= FS_FLAG_DATA_CONT;

	    if ((myflags & FS_FLAG_DATA_META)
		&& (myflags & FS_FLAG_DATA_UNALLOC))
		remark("impossible: unallocated meta block %lu!!",
		       (unsigned long) faddr);

	    if ((flags & myflags) != myflags) {
		/* we dont' want this fragment, but there is another we want,
		 * so we only print it if ALIGN is set */
		if (flags & FS_FLAG_DATA_ALIGN) {
		    if (WALK_STOP ==
			action(fs, faddr, null_block, myflags, ptr)) {
			free(null_block);
			data_buf_free(data_buf);
			return;
		    }
		}
	    }
	    else {
		if (data_buf->addr < 0
		    || faddr >= data_buf->addr + ffs->ffsbsize_f) {
		    if (fs_read_block(fs, data_buf, fs->block_size * frags,
				      addr) != fs->block_size * frags) {
			error("ffs_block_walk: Error reading block at %"
			      PRIuDADDR ":  %m", addr);
		    }
		}
		if (WALK_STOP == action(fs, faddr,
					data_buf->data +
					fs->block_size * (faddr -
							  data_buf->addr),
					myflags, ptr)) {
		    data_buf_free(data_buf);
		    return;
		}
	    }
	}
    }

    /*
     * Cleanup.
     */
    if (flags & FS_FLAG_DATA_ALIGN)
	free(null_block);
    data_buf_free(data_buf);
}

/**************************************************************************
 *
 * FILE WALKING
 *
 **************************************************************************/

/*
 * return the amount read or 0 if the action wanted to stop 
 */
static OFF_T
ffs_file_walk_direct(FS_INFO * fs, DATA_BUF * buf,
		     OFF_T length, DADDR_T addr, int flags,
		     FS_FILE_WALK_FN action, void *ptr)
{
    OFF_T read_count;
    int myflags;

    read_count = (length < buf->size ? length : buf->size);

    if (addr > fs->last_block) {
	if (flags & FS_FLAG_FILE_NOABORT) {
	    if (verbose) {
		fprintf(stderr,
			"Invalid direct block address (too large): %"
			PRIuDADDR "", addr);
	    }
	    return 0;
	}
	else {
	    error("Invalid direct block address (too large): %" PRIuDADDR
		  "", addr);
	}
    }

    /* Check if this goes over the end of the image 
     * This exists when the image size is not a multiple of the block
     * size and read_count is for a full block.
     * 
     */
    if (addr + (read_count / fs->block_size) > fs->last_block) {
	read_count = (fs->last_block - addr + 1) * fs->block_size;
    }

    if (addr == 0) {
	if (0 == (flags & FS_FLAG_FILE_NOSPARSE)) {
	    myflags = FS_FLAG_DATA_CONT;

	    if ((flags & FS_FLAG_FILE_AONLY) == 0)
		memset(buf->data, 0, read_count);

	    if (WALK_STOP == action(fs, addr, buf->data, read_count,
				    myflags, ptr))
		return 0;
	}
    }
    else {
	myflags = FS_FLAG_DATA_CONT;

	if ((flags & FS_FLAG_FILE_AONLY) == 0) {
	    if (fs_read_block(fs, buf, roundup(read_count, FFS_DEV_BSIZE),
			      addr) != roundup(read_count,
					       FFS_DEV_BSIZE)) {
		error("ffs_file_walk_direct: Error reading block at %"
		      PRIuDADDR ":  %m", addr);
	    }
	}

	if (WALK_STOP ==
	    action(fs, addr, buf->data, read_count, myflags, ptr))
	    return 0;
    }
    return (read_count);
}


/*
 * Process the data at block addr as a list of pointers at level _level_
 *
 */
static OFF_T
ffs_file_walk_indir(FS_INFO * fs, DATA_BUF * buf[], OFF_T length,
		    DADDR_T addr, int level, int flags,
		    FS_FILE_WALK_FN action, void *ptr)
{
    char *myname = "ffs_file_walk_indir";
    OFF_T todo_count = length;
    unsigned int n;

    if (verbose)
	fprintf(stderr, "%s: level %d block %" PRIuDADDR "\n", myname,
		level, addr);

    if (addr > fs->last_block) {
	if (flags & FS_FLAG_FILE_NOABORT) {
	    if (verbose) {
		fprintf(stderr,
			"Invalid indirect block address (too large): %"
			PRIuDADDR "", addr);
	    }
	    return 0;
	}
	else {
	    error("Invalid indirect block address (too large): %" PRIuDADDR
		  "", addr);
	}
    }

    /*
     * Read a block of disk addresses.
     */
    if (addr == 0) {
	memset(buf[level]->data, 0, buf[level]->size);
    }
    else {
	if (fs_read_block(fs, buf[level], buf[level]->size, addr) !=
	    buf[level]->size) {
	    error("ffs_file_walk_indir: Error reading block at %" PRIuDADDR
		  ":  %m", addr);
	}
    }


    /* we only call the action  if the META flag is set */
    if (flags & FS_FLAG_FILE_META) {
	int myflags = FS_FLAG_DATA_META;
	action(fs, addr, buf[level]->data, buf[level]->size, myflags, ptr);
    }


    /*   
     * For each disk address, copy a direct block or process an indirect
     * block.
     */
    if ((fs->ftype == FFS_1) || (fs->ftype == FFS_1B)) {

	uint32_t *iaddr = (uint32_t *) buf[level]->data;
	for (n = 0;
	     todo_count > 0 && n < buf[level]->size / sizeof(*iaddr);
	     n++) {

	    OFF_T prevcnt = todo_count;

	    if (getu32(fs, (uint8_t *) & iaddr[n]) > fs->last_block) {
		if (flags & FS_FLAG_FILE_NOABORT) {
		    if (verbose) {
			fprintf(stderr,
				"Invalid address in indirect list (too large): %"
				PRIu32 "", getu32(fs,
						  (uint8_t *) & iaddr[n]));
		    }
		    return 0;
		}
		else {
		    error("Invalid address in indirect list (too large): %"
			  PRIuDADDR "", getu32(fs,
					       (uint8_t *) & iaddr[n]));
		}
	    }

	    if (level == 1)
		todo_count -= ffs_file_walk_direct(fs, buf[0], todo_count,
						   (DADDR_T) getu32(fs,
								    (uint8_t
								     *) &
								    iaddr
								    [n]),
						   flags, action, ptr);
	    else
		todo_count -= ffs_file_walk_indir(fs, buf, todo_count,
						  (DADDR_T) getu32(fs,
								   (uint8_t
								    *) &
								   iaddr
								   [n]),
						  level - 1, flags, action,
						  ptr);
	    /* This occurs when 0 is returned, which means we want to exit */
	    if (prevcnt == todo_count)
		return 0;
	}
    }
    else {
	uint64_t *iaddr = (uint64_t *) buf[level]->data;
	for (n = 0;
	     todo_count > 0 && n < buf[level]->size / sizeof(*iaddr);
	     n++) {

	    OFF_T prevcnt = todo_count;

	    if (getu64(fs, (uint8_t *) & iaddr[n]) > fs->last_block) {
		if (flags & FS_FLAG_FILE_NOABORT) {
		    if (verbose) {
			fprintf(stderr,
				"Invalid address in indirect list (too large): %"
				PRIuDADDR "", getu64(fs,
						     (uint8_t *) &
						     iaddr[n]));
		    }
		    return 0;
		}
		else {
		    error("Invalid address in indirect list (too large): %"
			  PRIuDADDR "", getu64(fs,
					       (uint8_t *) & iaddr[n]));
		}
	    }

	    if (level == 1)
		todo_count -= ffs_file_walk_direct(fs, buf[0], todo_count,
						   (DADDR_T) getu64(fs,
								    (uint8_t
								     *) &
								    iaddr
								    [n]),
						   flags, action, ptr);
	    else
		todo_count -= ffs_file_walk_indir(fs, buf, todo_count,
						  (DADDR_T) getu64(fs,
								   (uint8_t
								    *) &
								   iaddr
								   [n]),
						  level - 1, flags, action,
						  ptr);

	    /* This occurs when 0 is returned, which means we want to exit */
	    if (prevcnt == todo_count)
		return 0;
	}
    }

    return (length - todo_count);
}

/*  
 *  
 * flag values: FS_FLAG_FILE_SPARSE, FS_FLAG_FILE_AONLY, FS_FLAG_FILE_SLACK
 *  FS_FLAG_FILE_NOABORT, FS_FLAG_FILE_META
 *
 * nothing special is done for FS_FLAG_FILE_RECOVER
 *
 * Action uses: FS_FLAG_DATA_CONT, FS_FLAG_DATA_META
 * @@@ DATA_ALLOC and _UNALLOC are not implemented
 *  
 * The type and id fields are ignored with FFS
 */
void
ffs_file_walk(FS_INFO * fs, FS_INODE * inode, uint32_t type, uint16_t id,
	      int flags, FS_FILE_WALK_FN action, void *ptr)
{
    FFS_INFO *ffs = (FFS_INFO *) fs;
    OFF_T length, read_b;
    DATA_BUF **buf;
    int n;
    int level;

    if (verbose)
	fprintf(stderr, "ffs_file_walk: Processing file %" PRIuINUM "\n",
		inode->addr);

    /*
     * Initialize a buffer for each level of indirection that is supported by
     * this inode. The level 0 buffer is sized to the logical block size used
     * for files. The level 1.. buffers are sized to the block size used for
     * indirect blocks.
     */
    buf = (DATA_BUF **) mymalloc(sizeof(*buf) * (inode->indir_count + 1));
    buf[0] = data_buf_alloc(ffs->ffsbsize_b);

    length = inode->size;
    /* If we want the slack of the last fragment, then roundup */
    if (flags & FS_FLAG_FILE_SLACK)
	length = roundup(length, fs->block_size);

    /*
     * Read the file blocks. First the direct blocks, then the indirect ones.
     */
    for (n = 0; length > 0 && n < inode->direct_count; n++) {
	read_b = ffs_file_walk_direct(fs, buf[0], length,
				      inode->direct_addr[n], flags, action,
				      ptr);

	if (!read_b) {
	    length = 0;
	    break;
	}
	length -= read_b;
    }

    /* if there is still data left, read the indirect */
    if (length > 0) {

	/* allocate buffers */
	for (level = 1; level <= inode->indir_count; level++)
	    buf[level] = data_buf_alloc(ffs->ffsbsize_b);

	for (level = 1; length > 0 && level <= inode->indir_count; level++) {
	    read_b = ffs_file_walk_indir(fs, buf, length,
					 inode->indir_addr[level - 1],
					 level, flags, action, ptr);

	    if (!read_b)
		break;
	    length -= read_b;
	}

	/*
	 * Cleanup.
	 */
	for (level = 1; level <= inode->indir_count; level++)
	    data_buf_free(buf[level]);
    }

    data_buf_free(buf[0]);
    free((char *) buf);

    return;
}


static void
ffs_fscheck(FS_INFO * fs, FILE * hFile)
{
    error("fscheck not implemented for ffs yet");
}

static void
ffs_fsstat(FS_INFO * fs, FILE * hFile)
{
    unsigned int i;
    time_t tmptime;
    ffs_csum1 *csum1 = NULL;
    ffs_cgd *cgd = NULL;

    FFS_INFO *ffs = (FFS_INFO *) fs;
    ffs_sb1 *sb1 = ffs->fs.sb1;
    ffs_sb2 *sb2 = ffs->fs.sb2;
    int flags;

    fprintf(hFile, "FILE SYSTEM INFORMATION\n");
    fprintf(hFile, "--------------------------------------------\n");

    if ((fs->ftype == FFS_1) || (fs->ftype == FFS_1B)) {
	fprintf(hFile, "File System Type: UFS 1\n");
	tmptime = getu32(fs, sb1->wtime);
	fprintf(hFile, "Last Written: %s",
		(tmptime > 0) ? asctime(localtime(&tmptime)) : "empty");
	fprintf(hFile, "Last Mount Point: %s\n", sb1->last_mnt);

	flags = sb1->fs_flags;
    }
    else {
	fprintf(hFile, "File System Type: UFS 2\n");
	tmptime = getu32(fs, sb2->wtime);
	fprintf(hFile, "Last Written: %s",
		(tmptime > 0) ? asctime(localtime(&tmptime)) : "empty");
	fprintf(hFile, "Last Mount Point: %s\n", sb2->last_mnt);
	fprintf(hFile, "Volume Name: %s\n", sb2->volname);
	fprintf(hFile, "System UID: %" PRIu64 "\n",
		getu64(fs, sb2->swuid));
	flags = getu32(fs, sb2->fs_flags);
    }

    if (flags) {
	int cnt = 0;

	fprintf(hFile, "Flags: ");

	if (flags & FFS_SB_FLAG_UNCLEAN)
	    fprintf(hFile, "%s Unclean", (cnt++ == 0 ? "" : ","));

	if (flags & FFS_SB_FLAG_SOFTDEP)
	    fprintf(hFile, "%s Soft Dependencies",
		    (cnt++ == 0 ? "" : ","));

	if (flags & FFS_SB_FLAG_NEEDFSCK)
	    fprintf(hFile, "%s Needs fsck", (cnt++ == 0 ? "" : ","));

	if (flags & FFS_SB_FLAG_INDEXDIR)
	    fprintf(hFile, "%s Index directories",
		    (cnt++ == 0 ? "" : ","));

	if (flags & FFS_SB_FLAG_ACL)
	    fprintf(hFile, "%s ACLs", (cnt++ == 0 ? "" : ","));

	if (flags & FFS_SB_FLAG_MULTILABEL)
	    fprintf(hFile, "%s TrustedBSD MAC Multi-label",
		    (cnt++ == 0 ? "" : ","));

	if (flags & FFS_SB_FLAG_UPDATED)
	    fprintf(hFile, "%s Updated Flag Location",
		    (cnt++ == 0 ? "" : ","));

	fprintf(hFile, "\n");
    }



    fprintf(hFile, "\nMETADATA INFORMATION\n");
    fprintf(hFile, "--------------------------------------------\n");

    fprintf(hFile, "Inode Range: %" PRIuINUM " - %" PRIuINUM "\n",
	    fs->first_inum, fs->last_inum);
    fprintf(hFile, "Root Directory: %" PRIuINUM "\n", fs->root_inum);
    if ((fs->ftype == FFS_1) || (fs->ftype == FFS_1B)) {
	fprintf(hFile, "Num of Avail Inodes: %" PRIu32 "\n",
		getu32(fs, sb1->cstotal.ino_free));
	fprintf(hFile, "Num of Directories: %" PRIu32 "\n",
		getu32(fs, sb1->cstotal.dir_num));
    }
    else {
	fprintf(hFile, "Num of Avail Inodes: %" PRIu64 "\n",
		getu64(fs, sb2->cstotal.ino_free));
	fprintf(hFile, "Num of Directories: %" PRIu64 "\n",
		getu64(fs, sb2->cstotal.dir_num));
    }


    fprintf(hFile, "\nCONTENT INFORMATION\n");
    fprintf(hFile, "--------------------------------------------\n");

    fprintf(hFile, "Fragment Range: %" PRIuDADDR " - %" PRIuDADDR "\n",
	    fs->first_block, fs->last_block);

    fprintf(hFile, "Block Size: %u\n", ffs->ffsbsize_b);
    fprintf(hFile, "Fragment Size: %u\n", fs->block_size);

    if ((fs->ftype == FFS_1) || (fs->ftype == FFS_1B)) {
	fprintf(hFile, "Num of Avail Full Blocks: %" PRIu32 "\n",
		getu32(fs, sb1->cstotal.blk_free));
	fprintf(hFile, "Num of Avail Fragments: %" PRIu32 "\n",
		getu32(fs, sb1->cstotal.frag_free));
    }
    else {
	fprintf(hFile, "Num of Avail Full Blocks: %" PRIu64 "\n",
		getu64(fs, sb2->cstotal.blk_free));
	fprintf(hFile, "Num of Avail Fragments: %" PRIu64 "\n",
		getu64(fs, sb2->cstotal.frag_free));
    }

    fprintf(hFile, "\nCYLINDER GROUP INFORMATION\n");
    fprintf(hFile, "--------------------------------------------\n");

    fprintf(hFile, "Number of Cylinder Groups: %" PRIu32 "\n",
	    ffs->groups_count);
    fprintf(hFile, "Inodes per group: %" PRId32 "\n",
	    gets32(fs, sb1->cg_inode_num));
    fprintf(hFile, "Fragments per group: %" PRId32 "\n",
	    gets32(fs, sb1->cg_frag_num));


    /* UFS 1 and 2 use the same ssize field  and use the same csum1 */
    if (getu32(fs, sb1->cg_ssize_b)) {
	csum1 = (ffs_csum1 *) mymalloc(getu32(fs, sb1->cg_ssize_b));
	if ((fs->ftype == FFS_1) || (fs->ftype == FFS_1B)) {
	    if (fs_read_block_nobuf
		(fs, (char *) csum1, getu32(fs, sb1->cg_ssize_b),
		 (DADDR_T) getu32(fs, sb1->cg_saddr)) != getu32(fs,
								sb1->
								cg_ssize_b))
	    {
		error
		    ("ffs_fsstat: Error reading FFS1 group descriptor at %"
		     PRIu32 ":  %m", getu32(fs, sb1->cg_saddr));
	    }
	}
	else {
	    if (fs_read_block_nobuf
		(fs, (char *) csum1, getu32(fs, sb2->cg_ssize_b),
		 (DADDR_T) getu64(fs, sb2->cg_saddr)) != getu32(fs,
								sb2->
								cg_ssize_b))
	    {
		error
		    ("ffs_fsstat: Error reading FFS2 group descriptor at %"
		     PRIu64 ":  %m", getu64(fs, sb2->cg_saddr));
	    }
	}
    }

    for (i = 0; i < ffs->groups_count; i++) {

	ffs_group_load(ffs, i);
	cgd = (ffs_cgd *) ffs->grp_buf->data;

	fprintf(hFile, "\nGroup %d:\n", i);
	if (cgd) {
	    if ((fs->ftype == FFS_1) || (fs->ftype == FFS_1B)) {
		tmptime = getu32(fs, cgd->wtime);
	    }
	    else {
		ffs_cgd2 *cgd2 = (ffs_cgd2 *) cgd;
		tmptime = (uint32_t) getu64(fs, cgd2->wtime);
	    }
	    fprintf(hFile, "  Last Written: %s",
		    (tmptime >
		     0) ? asctime(localtime(&tmptime)) : "empty");
	}

	fprintf(hFile, "  Inode Range: %" PRIu32 " - %" PRIu32 "\n",
		(gets32(fs, sb1->cg_inode_num) * i),
		((uint32_t) ((gets32(fs, sb1->cg_inode_num) * (i + 1)) - 1)
		 <
		 fs->
		 last_inum) ? (uint32_t) ((gets32(fs, sb1->cg_inode_num) *
					   (i + 1)) -
					  1) : (uint32_t) fs->last_inum);

	fprintf(hFile,
		"  Fragment Range: %" PRIuDADDR " - %" PRIuDADDR "\n",
		cgbase_lcl(fs, sb1, i),
		((cgbase_lcl(fs, sb1, i + 1) - 1) <
		 fs->last_block) ? (cgbase_lcl(fs, sb1,
					       i + 1) -
				    1) : fs->last_block);

	/* The first group is special because the first 16 sectors are
	 * reserved for the boot block.  
	 * the next contains the primary Super Block 
	 */
	if (!i) {
	    fprintf(hFile, "    Boot Block: 0 - %" PRIu32 "\n",
		    (uint32_t) (15 * 512 / fs->block_size));


	    fprintf(hFile, "    Super Block: %" PRIu32 " - %" PRIu32 "\n",
		    (uint32_t) (16 * 512 / fs->block_size),
		    (uint32_t) ((16 * 512 / fs->block_size) +
				ffs->ffsbsize_f - 1));
	}

	fprintf(hFile,
		"    Super Block: %" PRIuDADDR " - %" PRIuDADDR "\n",
		cgsblock_lcl(fs, sb1, i),
		(cgsblock_lcl(fs, sb1, i) + ffs->ffsbsize_f - 1));


	fprintf(hFile, "    Group Desc: %" PRIuDADDR " - %" PRIuDADDR "\n",
		cgtod_lcl(fs, sb1, i),
		(cgtod_lcl(fs, sb1, i) + ffs->ffsbsize_f - 1));


	if (fs->ftype == FFS_2) {
	    fprintf(hFile,
		    "    Inode Table: %" PRIuDADDR " - %" PRIuDADDR "\n",
		    cgimin_lcl(fs, sb1, i),
		    (cgimin_lcl(fs, sb1, i) +
		     ((roundup
		       (gets32(fs, sb1->cg_inode_num) * sizeof(ffs_inode2),
			fs->block_size)
		       / fs->block_size) - 1)));
	}
	else {
	    fprintf(hFile,
		    "    Inode Table: %" PRIuDADDR " - %" PRIuDADDR "\n",
		    cgimin_lcl(fs, sb1, i),
		    (cgimin_lcl(fs, sb1, i) +
		     ((roundup
		       (gets32(fs, sb1->cg_inode_num) * sizeof(ffs_inode1),
			fs->block_size)
		       / fs->block_size) - 1)));
	}

	fprintf(hFile, "    Data Fragments: ");

	/* For all groups besides the first, the space before the
	 * super block is also used for data
	 */
	if (i)
	    fprintf(hFile, "%" PRIuDADDR " - %" PRIuDADDR ", ",
		    cgbase_lcl(fs, sb1, i), cgsblock_lcl(fs, sb1, i) - 1);

	fprintf(hFile, "%" PRIuDADDR " - %" PRIuDADDR "\n",
		cgdmin_lcl(fs, sb1, i),
		((cgbase_lcl(fs, sb1, i + 1) - 1) < fs->last_block) ?
		(cgbase_lcl(fs, sb1, i + 1) - 1) : fs->last_block);


	if ((csum1)
	    && ((i + 1) * sizeof(ffs_csum1) < getu32(fs, sb1->cg_ssize_b))) {
	    fprintf(hFile,
		    "  Global Summary (from the superblock summary area):\n");
	    fprintf(hFile, "    Num of Dirs: %" PRIu32 "\n",
		    getu32(fs, &csum1[i].dir_num));
	    fprintf(hFile, "    Num of Avail Blocks: %" PRIu32 "\n",
		    getu32(fs, &csum1[i].blk_free));
	    fprintf(hFile, "    Num of Avail Inodes: %" PRIu32 "\n",
		    getu32(fs, &csum1[i].ino_free));
	    fprintf(hFile, "    Num of Avail Frags: %" PRIu32 "\n",
		    getu32(fs, &csum1[i].frag_free));
	}

	if (cgd) {
	    fprintf(hFile,
		    "  Local Summary (from the group descriptor):\n");
	    fprintf(hFile, "    Num of Dirs: %" PRIu32 "\n",
		    getu32(fs, &cgd->cs.dir_num));
	    fprintf(hFile, "    Num of Avail Blocks: %" PRIu32 "\n",
		    getu32(fs, &cgd->cs.blk_free));
	    fprintf(hFile, "    Num of Avail Inodes: %" PRIu32 "\n",
		    getu32(fs, &cgd->cs.ino_free));
	    fprintf(hFile, "    Num of Avail Frags: %" PRIu32 "\n",
		    getu32(fs, &cgd->cs.frag_free));

	    fprintf(hFile, "    Last Block Allocated: %" PRIuDADDR "\n",
		    getu32(fs, &cgd->last_alloc_blk) +
		    cgbase_lcl(fs, sb1, i));

	    fprintf(hFile, "    Last Fragment Allocated: %" PRIuDADDR "\n",
		    getu32(fs, &cgd->last_alloc_frag) +
		    cgbase_lcl(fs, sb1, i));

	    fprintf(hFile, "    Last Inode Allocated: %" PRIu32 "\n",
		    getu32(fs, &cgd->last_alloc_ino) +
		    (gets32(fs, sb1->cg_inode_num) * i));

	}
    }

    return;
}





/************************* istat *******************************/

/* indirect block accounting */
#define FFS_INDIR_SIZ   64

typedef struct {
    FILE *hFile;
    int idx;
    DADDR_T indirl[FFS_INDIR_SIZ];
    unsigned char indir_idx;
} FFS_PRINT_ADDR;


static uint8_t
print_addr_act(FS_INFO * fs, DADDR_T addr, char *buf,
	       unsigned int size, int flags, void *ptr)
{
    FFS_PRINT_ADDR *print = (FFS_PRINT_ADDR *) ptr;

    if (flags & FS_FLAG_DATA_CONT) {
	int i, s;
	/* cycle through the fragments if they exist */
	for (i = 0, s = size; s > 0; s -= fs->block_size, i++) {

	    /* sparse file */
	    if (addr)
		fprintf(print->hFile, "%" PRIuDADDR " ", addr + i);
	    else
		fprintf(print->hFile, "0 ");

	    if (++(print->idx) == 8) {
		fprintf(print->hFile, "\n");
		print->idx = 0;
	    }
	}
    }

    /* this must be an indirect block pointer, so put it in the list */
    else if (flags & FS_FLAG_DATA_META) {
	if (print->indir_idx < FFS_INDIR_SIZ)
	    print->indirl[(print->indir_idx)++] = addr;
    }
    return WALK_CONT;
}



static void
ffs_istat(FS_INFO * fs, FILE * hFile, INUM_T inum, int numblock,
	  int32_t sec_skew)
{
    FFS_INFO *ffs = (FFS_INFO *) fs;
    FS_INODE *fs_inode;
    char ls[12];
    FFS_PRINT_ADDR print;

    fs_inode = ffs_inode_lookup(fs, inum);
    fprintf(hFile, "inode: %" PRIuINUM "\n", inum);
    fprintf(hFile, "%sAllocated\n",
	    (fs_inode->flags & FS_FLAG_META_ALLOC) ? "" : "Not ");

    fprintf(hFile, "Group: %" PRI_FFSGRP "\n", ffs->grp_num);

    if (fs_inode->link)
	fprintf(hFile, "symbolic link to: %s\n", fs_inode->link);

    fprintf(hFile, "uid / gid: %d / %d\n",
	    (int) fs_inode->uid, (int) fs_inode->gid);


    make_ls(fs_inode->mode, ls, 12);
    fprintf(hFile, "mode: %s\n", ls);

    fprintf(hFile, "size: %" PRIuOFF "\n", fs_inode->size);
    fprintf(hFile, "num of links: %lu\n", (ULONG) fs_inode->nlink);


    if (sec_skew != 0) {
	fprintf(hFile, "\nAdjusted Inode Times:\n");
	fs_inode->mtime -= sec_skew;
	fs_inode->atime -= sec_skew;
	fs_inode->ctime -= sec_skew;

	fprintf(hFile, "Accessed:\t%s", ctime(&fs_inode->atime));
	fprintf(hFile, "File Modified:\t%s", ctime(&fs_inode->mtime));
	fprintf(hFile, "Inode Modified:\t%s", ctime(&fs_inode->ctime));

	fs_inode->mtime += sec_skew;
	fs_inode->atime += sec_skew;
	fs_inode->ctime += sec_skew;

	fprintf(hFile, "\nOriginal Inode Times:\n");
    }
    else {
	fprintf(hFile, "\nInode Times:\n");
    }

    fprintf(hFile, "Accessed:\t%s", ctime(&fs_inode->atime));
    fprintf(hFile, "File Modified:\t%s", ctime(&fs_inode->mtime));
    fprintf(hFile, "Inode Modified:\t%s", ctime(&fs_inode->ctime));

    if (fs->ftype == FFS_2) {
	ffs_inode2 *in = (ffs_inode2 *) ffs->dino_buf;
	/* Are there extended attributes */
	if (getu32(fs, in->di_extsize) > 0) {
	    ffs_extattr *ea;
	    uint32_t size;
	    char name[257];
	    DATA_BUF *data_buf = data_buf_alloc(ffs->ffsbsize_b);

	    size = getu32(fs, in->di_extsize);
	    fprintf(hFile, "\nExtended Attributes:\n");
	    fprintf(hFile,
		    "Size: %" PRIu32 " (%" PRIu64 ", %" PRIu64 ")\n", size,
		    getu64(fs, in->di_extb[0]), getu64(fs,
						       in->di_extb[1]));


	    /* Process first block */
	    // @@@ Incorporate values into this as well
	    if ((getu64(fs, in->di_extb[0]) >= fs->first_block) &&
		(getu64(fs, in->di_extb[0]) <= fs->last_block)) {
		uintptr_t end;

		if (fs_read_block(fs, data_buf, ffs->ffsbsize_b,
				  getu64(fs,
					 in->di_extb[0])) !=
		    ffs->ffsbsize_b) {
		    error
			("ffs_istat: Error reading FFS2 extended attribute 0 at %"
			 PRIu64 ":  %m", getu64(fs, in->di_extb[0]));
		}

		ea = (ffs_extattr *) data_buf->data;

		if (size > ffs->ffsbsize_b) {
		    end = (uintptr_t) ea + ffs->ffsbsize_b;
		    size -= ffs->ffsbsize_b;
		}
		else {
		    end = (uintptr_t) ea + size;
		    size = 0;
		}

		for (; (uintptr_t) ea < end;
		     ea =
		     (ffs_extattr *) ((uintptr_t) ea +
				      getu32(fs, ea->reclen))) {
		    memcpy(name, ea->name, ea->nlen);
		    name[ea->nlen] = '\0';
		    fprintf(hFile, "%s\n", name);
		}
	    }
	    if ((getu64(fs, in->di_extb[1]) >= fs->first_block) &&
		(getu64(fs, in->di_extb[1]) <= fs->last_block)) {
		uintptr_t end;

		if (fs_read_block(fs, data_buf, ffs->ffsbsize_b,
				  getu64(fs,
					 in->di_extb[1])) !=
		    ffs->ffsbsize_b) {
		    error
			("ffs_istat: Error reading FFS2 extended attribute 1 at %"
			 PRIu64 ":  %m", getu64(fs, in->di_extb[1]));
		}

		ea = (ffs_extattr *) data_buf->data;

		if (size > ffs->ffsbsize_b)
		    end = (uintptr_t) ea + ffs->ffsbsize_b;
		else
		    end = (uintptr_t) ea + size;

		for (; (uintptr_t) ea < end;
		     ea =
		     (ffs_extattr *) ((uintptr_t) ea +
				      getu32(fs, ea->reclen))) {
		    memcpy(name, ea->name, ea->nlen);
		    name[ea->nlen] = '\0';
		    fprintf(hFile, "%s\n", name);
		}
	    }
	}
    }



    /* A bad hack to force a specified number of blocks */
    if (numblock > 0)
	fs_inode->size = numblock * ffs->ffsbsize_b;

    fprintf(hFile, "\nDirect Blocks:\n");


    print.indir_idx = 0;
    print.idx = 0;
    print.hFile = hFile;

    fs->file_walk(fs, fs_inode, 0, 0,
		  FS_FLAG_FILE_AONLY | FS_FLAG_FILE_META |
		  FS_FLAG_FILE_NOID | FS_FLAG_FILE_NOABORT,
		  print_addr_act, (void *) &print);

    if (print.idx != 0)
	fprintf(hFile, "\n");

    /* print indirect blocks */
    if (print.indir_idx > 0) {
	int i, printidx;
	fprintf(hFile, "\nIndirect Blocks:\n");

	printidx = 0;

	for (i = 0; i < print.indir_idx; i++) {
	    unsigned int a;
	    /* Cycle through the fragments in the block */
	    for (a = 0; a < ffs->ffsbsize_f; a++) {
		fprintf(hFile, "%" PRIuDADDR " ", print.indirl[i] + a);
		if (++printidx == 8) {
		    fprintf(hFile, "\n");
		    printidx = 0;
		}
	    }
	}
	if (printidx != 0)
	    fprintf(hFile, "\n");
    }

    fs_inode_free(fs_inode);
    return;
}

void
ffs_jopen(FS_INFO * fs, INUM_T inum)
{
    fprintf(stderr, "Error: UFS does not have a journal\n");
    exit(1);
}

void
ffs_jentry_walk(FS_INFO * fs, int flags, FS_JENTRY_WALK_FN action,
		void *ptr)
{
    fprintf(stderr, "Error: UFS does not have a journal\n");
    exit(1);
}


void
ffs_jblk_walk(FS_INFO * fs, DADDR_T start, DADDR_T end, int flags,
	      FS_JBLK_WALK_FN action, void *ptr)
{
    fprintf(stderr, "Error: UFS does not have a journal\n");
    exit(1);
}



/* ffs_close - close a fast file system */
static void
ffs_close(FS_INFO * fs)
{
    FFS_INFO *ffs = (FFS_INFO *) fs;

    if (ffs->grp_buf)
	data_buf_free(ffs->grp_buf);

    if (ffs->itbl_buf)
	data_buf_free(ffs->itbl_buf);

    if (ffs->dino_buf)
	free(ffs->dino_buf);

    free((char *) ffs->fs.sb1);
    free(ffs);
}

/* ffs_open - open a fast file system */

FS_INFO *
ffs_open(IMG_INFO * img_info, unsigned char ftype, uint8_t test)
{
    char *myname = "ffs_open";
    FFS_INFO *ffs = (FFS_INFO *) mymalloc(sizeof(*ffs));
    unsigned int len;
    FS_INFO *fs = &(ffs->fs_info);

    if ((ftype & FSMASK) != FFS_TYPE)
	error("Invalid FS Type in ffs_open");

    fs->ftype = ftype;
    fs->flags = 0;


    fs->img_info = img_info;

    /* Both sbs are the same size */
    len = roundup(sizeof(ffs_sb1), FFS_DEV_BSIZE);
    ffs->fs.sb1 = (ffs_sb1 *) mymalloc(len);

    /* check the magic and figure out the endian ordering */

    /* Try UFS2 first - I read somewhere that some upgrades
     * kept the original UFS1 superblock in addition to 
     * the new one */
    if (fs_read_random
	(fs, (char *) ffs->fs.sb2, sizeof(ffs_sb2),
	 (OFF_T) UFS2_SBOFF) != sizeof(ffs_sb2)) {
	error("%s: Error reading superblock at %" PRIuDADDR ": %m",
	      myname, (OFF_T) UFS2_SBOFF);
    }

    /* If that didn't work, try the 256KB UFS2 location */
    if (guessu32(fs, ffs->fs.sb2->magic, UFS2_FS_MAGIC)) {
	if (fs_read_random
	    (fs, (char *) ffs->fs.sb2, sizeof(ffs_sb2),
	     (OFF_T) UFS2_SBOFF2) != sizeof(ffs_sb2)) {
	    error("%s: Error reading superblock at %" PRIuDADDR ": %m",
		  myname, (OFF_T) UFS2_SBOFF2);
	}

	/* Try UFS1 if that did not work */
	if (guessu32(fs, ffs->fs.sb2->magic, UFS2_FS_MAGIC)) {
	    if (fs_read_random
		(fs, (char *) ffs->fs.sb1, len, (OFF_T) UFS1_SBOFF)
		!= len) {
		error("%s: Error reading superblock at %" PRIuDADDR ": %m",
		      myname, (OFF_T) UFS1_SBOFF);
	    }
	    if (guessu32(fs, ffs->fs.sb1->magic, UFS1_FS_MAGIC)) {
		free(ffs->fs.sb1);
		free(ffs);
		if (test)
		    return NULL;
		else
		    error("Error:  not a FFS file system");
	    }
	    else {
		// @@@ NEED TO DIFFERENTIATE BETWEEN A & B - UID/GID location in inode
		fs->ftype = FFS_1;
	    }
	}
	else {
	    fs->ftype = FFS_2;
	}
    }
    else {
	fs->ftype = FFS_2;
    }


    /*
     * Translate some filesystem-specific information to generic form.
     */

    if (fs->ftype == FFS_2) {
	fs->block_count = gets64(fs, ffs->fs.sb2->frag_num);
	fs->block_size = gets32(fs, ffs->fs.sb2->fsize_b);
	ffs->ffsbsize_b = gets32(fs, ffs->fs.sb2->bsize_b);
	ffs->ffsbsize_f = gets32(fs, ffs->fs.sb2->bsize_frag);
	ffs->groups_count = gets32(fs, ffs->fs.sb2->cg_num);
    }
    else {
	fs->block_count = gets32(fs, ffs->fs.sb1->frag_num);
	fs->block_size = gets32(fs, ffs->fs.sb1->fsize_b);
	ffs->ffsbsize_b = gets32(fs, ffs->fs.sb1->bsize_b);
	ffs->ffsbsize_f = gets32(fs, ffs->fs.sb1->bsize_frag);
	ffs->groups_count = gets32(fs, ffs->fs.sb1->cg_num);
    }



    fs->first_block = 0;
    fs->last_block = fs->block_count - 1;
    fs->dev_bsize = FFS_DEV_BSIZE;

    if ((fs->block_size % 512) || (ffs->ffsbsize_b % 512)) {
	free(ffs->fs.sb1);
	free(ffs);
	if (test)
	    return NULL;
	else
	    error
		("Error: not a FFS file system (invalid fragment or block size)");
    }

    if ((ffs->ffsbsize_b / fs->block_size) != ffs->ffsbsize_f) {
	free(ffs->fs.sb1);
	free(ffs);
	if (test)
	    return NULL;
	else
	    error
		("Error: not a FFS file system (frag / block size mismatch)");
    }


    if (fs->ftype == FFS_2) {
	fs->inum_count =
	    ffs->groups_count * gets32(fs, ffs->fs.sb2->cg_inode_num);
    }
    else {
	fs->inum_count =
	    ffs->groups_count * gets32(fs, ffs->fs.sb1->cg_inode_num);
    }

    fs->root_inum = FFS_ROOTINO;
    fs->first_inum = FFS_FIRSTINO;
    fs->last_inum = fs->inum_count - 1;


    /*
     * Other initialization: caches, callbacks.
     */
    ffs->grp_buf = NULL;
    ffs->grp_num = 0xffffffff;

    ffs->dino_buf = NULL;
    ffs->dino_inum = 0xffffffff;

    ffs->itbl_buf = NULL;

    fs->inode_walk = ffs_inode_walk;
    fs->block_walk = ffs_block_walk;
    fs->inode_lookup = ffs_inode_lookup;
    fs->dent_walk = ffs_dent_walk;
    fs->file_walk = ffs_file_walk;
    fs->fsstat = ffs_fsstat;
    fs->fscheck = ffs_fscheck;
    fs->istat = ffs_istat;
    fs->close = ffs_close;
    fs->jblk_walk = ffs_jblk_walk;
    fs->jentry_walk = ffs_jentry_walk;
    fs->jopen = ffs_jopen;
    fs->journ_inum = 0;



    /*
     * Print some stats.
     */
    if (verbose)
	fprintf(stderr,
		"inodes %" PRIuINUM " root ino %" PRIuINUM " cyl groups %"
		PRId32 " blocks %" PRIuDADDR "\n", fs->inum_count,
		fs->root_inum, ffs->groups_count, fs->block_count);

    return (fs);
}
