/*
** The Sleuth Kit 
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003-2004 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002-2003 Brian Carrier, @stake Inc.  All rights reserved
** 
** Copyright (c) 1997,1998,1999, International Business Machines          
** Corporation and others. All Rights Reserved.
*/

/* TCT */
/*++
 * NAME
 *	ffs_open 3
 * SUMMARY
 *	fast file system support
 * SYNOPSIS
 *	#include "fstools.h"
 *
 *	FS_INFO *ffs_open(const char *name)
 * DESCRIPTION
 *	ffs_open() opens the named block device and makes it accessible
 *	for the standard file system operations described in fs_open(3).
 * BUGS
 *	On-disk layout and byte order differ per FFS implementation,
 *	therefore this code is likely to fail when confronted with
 *	foreign file systems.
 * LICENSE
 *	This software is distributed under the IBM Public License.
 * AUTHOR(S)
 *	Wietse Venema
 *	IBM T.J. Watson Research
 *	P.O. Box 704
 *	Yorktown Heights, NY 10598, USA
 --*/

#include "fs_tools.h"
#include "fs_types.h"
#include "ffs.h"
#include "mymalloc.h"
#include "error.h"
#include "fs_io.h"

/* ffs_cgroup_lookup - look up cached cylinder group info */

static ffs_cgd 
*ffs_cgroup_lookup(FFS_INFO *ffs, CGNUM_T cgnum)
{
	DADDR_T addr;
	FS_INFO *fs = (FS_INFO *)&ffs->fs_info;

    /*
     * Sanity check
     */
    if (cgnum < 0 || cgnum >= gets32(fs, ffs->fs.sb1->cg_num))
		error("invalid cylinder group number: %lu", (ULONG) cgnum);

    /*
     * Allocate/read cylinder group info on the fly. Trust that a cylinder
     * group always fits within a logical disk block (as promised in the
     * 4.4BSD <ufs/ffs/fs.h> include file).
     */
	if (ffs->cg_buf == 0)
		ffs->cg_buf = fs_buf_alloc(ffs->ffsbsize_b);

	addr = cgtod_lcl(fs, ffs->fs.sb1, cgnum);
	if (ffs->cg_buf->addr != addr) 
		fs->read_block(fs, ffs->cg_buf, ffs->cg_buf->size, addr,
		      "cylinder block");
   
	ffs->cg_num = cgnum;

	return (ffs_cgd *)ffs->cg_buf->data;
}

/* ffs_cgroup_free - destroy cylinder group info cache */
static void 
ffs_cgroup_free(FFS_INFO *ffs)
{
    if (ffs->cg_buf)
		fs_buf_free(ffs->cg_buf);
}

/* 
 * ffs_dinode_lookup - look up cached disk inode 
 * Place result in ffs->dinode
 */

static void
ffs_dinode_lookup(FFS_INFO *ffs, INUM_T inum)
{
    DADDR_T addr;
    OFF_T     offs;
	FS_INFO *fs = (FS_INFO *)&ffs->fs_info;

    /*
     * Sanity check.
     */
    if (inum < fs->first_inum || inum > fs->last_inum)
		error("invalid inode number: %lu", (ULONG) inum);

    /*
     * Allocate/read the inode buffer on the fly.
	 */
	if (ffs->dino_buf == 0)
		ffs->dino_buf = fs_buf_alloc(ffs->ffsbsize_b);

    addr = itod_lcl(fs, ffs->fs.sb1, inum);
    if (ffs->dino_buf->addr != addr)
		fs->read_block(fs, ffs->dino_buf, ffs->dino_buf->size, addr,
		      "inode block");

    /*
     * Copy the inode, in order to avoid alignment problems when accessing
     * structure members.
     */
    offs = itoo_lcl(fs, ffs->fs.sb1, inum) * sizeof(ffs_inode1);

    memcpy((char *) ffs->dinode, ffs->dino_buf->data + offs, 
 	  sizeof(ffs_inode1));

	ffs->inum = inum;

	return;
}

/* ffs_dinode_free - destroy disk inode cache */
static void 
ffs_dinode_free(FFS_INFO *ffs)
{
    if (ffs->dino_buf)
		fs_buf_free(ffs->dino_buf);

	ffs->inum = 0;
}


/* ffs_copy_inode - copy disk inode to generic inode 
 * 
 */

static void 
ffs_copy_inode(FFS_INFO *ffs, FS_INODE *fs_inode)
{
    int     i, j, count;
	FS_INFO *fs = &(ffs->fs_info);
	CGNUM_T cg_num;
	ffs_cgd *cg;
	unsigned char *inosused = NULL;
	INUM_T ibase;

	fs_inode->flags = 0;
	fs_inode->seq = 0;

	/* If the symlink field is set from a previous run, then free it */
	if (fs_inode->link) {
		free(fs_inode->link);
		fs_inode->link = NULL;
	}

	/* OpenBSD and FreeBSD style */
	if (fs->ftype == FFS_1) {
		ffs_inode1	*in = (ffs_inode1 *)ffs->dinode;

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

			fs_inode->link = mymalloc(fs_inode->size+1);

			count = 0;	/* index into the link array */

			/* it is located directly in the pointers  
			 * Only the new style inode has this "fast link"
			 */
			if (fs_inode->size < 4 * (FFS_NDADDR + FFS_NIADDR)) {
				char *ptr;

				/* Direct block pointer locations */
				for (i = 0; i < FFS_NDADDR && count < fs_inode->size; i++) {
					ptr = (char *)&in->di_db[i];
					for (j = 0; j < 4 && count < fs_inode->size; j++) 
						fs_inode->link[count++] = ptr[j];
				}

				/* indirect block pointers */
				for (i = 0; i < FFS_NIADDR && count < fs_inode->size; i++) {
					ptr = (char *)&in->di_ib[i];
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
				FS_BUF *fs_buf = fs_buf_alloc(fs->block_size);
				char *ptr = fs_inode->link;

				/* there is a max link length of 1000, so we should never
				 * need the indirect blocks
				 */
				for (i = 0; i < FFS_NDADDR && count < fs_inode->size; i++) {
					/* Do we need the entire block, or just part of it? */
					int read_count = (fs_inode->size - count < fs->block_size)?
						fs_inode->size - count : fs->block_size;

					fs->read_block(fs, fs_buf, fs->block_size, 
					  fs_inode->direct_addr[i], "link block");

					memcpy (ptr, fs_buf->data, read_count);
					count += read_count;
					ptr = (char *)(int)ptr + read_count;
				 }
				 /* terminate the string */
				 *ptr = '\0';

				 fs_buf_free(fs_buf);
			}
		} /* end of symlink */
	}
	/* FFS_2 */
	else {
		ffs_inode2	*in = (ffs_inode2 *)ffs->dinode;

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
			fs_inode_realloc(fs_inode, FFS_NDADDR, 
			  FFS_NIADDR);

		for (i = 0; i < FFS_NDADDR; i++)
			fs_inode->direct_addr[i] = gets32(fs, in->di_db[i]);

		for (i = 0; i < FFS_NIADDR; i++)
			fs_inode->indir_addr[i] = gets32(fs, in->di_ib[i]);

		if (((fs_inode->mode & FS_INODE_FMT) == FS_INODE_LNK) &&
		  (fs_inode->size < FFS_MAXPATHLEN) && (fs_inode->size >= 0)) {

			/* This inode type doesn't have fast links */
			FS_BUF *fs_buf = fs_buf_alloc(fs->block_size);
			char *ptr;
			fs_inode->link = ptr = mymalloc(fs_inode->size+1);

			count = 0;	/* index into the link array */

			/* there is a max link length of 1000, so we should never
			 * need the indirect blocks
			 */
			for (i = 0; i < FFS_NDADDR && count < fs_inode->size; i++) {
				/* Do we need the entire block, or just part of it? */
				int read_count = (fs_inode->size - count < fs->block_size)?
					fs_inode->size - count : fs->block_size;

				fs->read_block(fs, fs_buf, fs->block_size, 
				  fs_inode->direct_addr[i], "link block");

				memcpy (ptr, fs_buf->data, read_count);
				count += read_count;
				ptr = (char *)(int)ptr + read_count;
			 }

			/* terminate the string */
			*ptr = '\0';

			 fs_buf_free(fs_buf);
		 }
	}

	/* set the flags */
	cg_num = itog_lcl(fs, ffs->fs.sb1, ffs->inum);
	cg = ffs_cgroup_lookup(ffs, cg_num);
	inosused = (unsigned char *) cg_inosused_lcl(fs, cg);
	ibase = cg_num * gets32(fs, ffs->fs.sb1->cg_inode_num);

	/* get the alloc flag */
	fs_inode->flags = (isset(inosused, ffs->inum - ibase) ?
	  FS_FLAG_META_ALLOC : FS_FLAG_META_UNALLOC);

	/* link flag */
	fs_inode->flags |= (fs_inode->nlink ?
	  FS_FLAG_META_LINK : FS_FLAG_META_UNLINK);
  
	/* used/unused */
	fs_inode->flags |= (fs_inode->ctime ? 
	  FS_FLAG_META_USED : FS_FLAG_META_UNUSED);

} /* end of ffs_copy_inode */



/* ffs_inode_lookup - lookup inode, external interface */

static FS_INODE *
ffs_inode_lookup(FS_INFO *fs, INUM_T inum)
{
    FFS_INFO *ffs = (FFS_INFO *) fs;
	FS_INODE	*fs_inode;

	/* Lookup the inode and store it in ffs */
    ffs_dinode_lookup(ffs, inum);

	/* copy it to the FS_INODE structure */
    fs_inode = fs_inode_alloc(FFS_NDADDR, FFS_NIADDR);
    ffs_copy_inode(ffs, fs_inode);

    return (fs_inode);

} /* end of ffs_inode_lookup */



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
ffs_inode_walk(FS_INFO *fs, INUM_T start, INUM_T last, int flags,
		               FS_INODE_WALK_FN action, char *ptr)
{
    char   *myname = "ffs_inode_walk";
    FFS_INFO *ffs = (FFS_INFO *) fs;
    CGNUM_T cg_num;
    ffs_cgd *cg = 0;
    INUM_T  inum;
    unsigned char *inosused = NULL;
    FS_INODE *fs_inode = fs_inode_alloc(FFS_NDADDR, FFS_NIADDR);
    int     myflags;
    INUM_T  ibase = 0;
	ffs_inode1	*in;

    /*
     * Sanity checks.
     */
    if (start < fs->first_inum || start > fs->last_inum)
		error("%s: invalid start inode number: %lu", myname, (ULONG) start);
    if (last < fs->first_inum || last > fs->last_inum || last < start)
		error("%s: invalid last inode number: %lu", myname, (ULONG) last);

    /*
     * Iterate. This is easy because inode numbers are contiguous, unlike
     * data blocks which are interleaved with cylinder group blocks.
     */
    for (inum = start; inum <= last; inum++) {

		/*
	 	* Be sure to use the proper cylinder group data.
	 	*/
		cg_num = itog_lcl(fs, ffs->fs.sb1, inum);

		if (cg == 0 || gets32(fs, cg->cg_cgx) != cg_num) {
			cg = ffs_cgroup_lookup(ffs, cg_num);
			inosused = (unsigned char *) cg_inosused_lcl(fs, cg);
			ibase = cg_num * gets32(fs, ffs->fs.sb1->cg_inode_num);
		}

		/*
		 * Apply the allocated/unallocated restriction.
		 */
		myflags = (isset(inosused, inum - ibase) ?
			   FS_FLAG_META_ALLOC : FS_FLAG_META_UNALLOC);
		if ((flags & myflags) != myflags)
			continue;

		ffs_dinode_lookup(ffs, inum);

		/* both inode forms are the same for the required fields */
		in = (ffs_inode1 *)ffs->dinode;

		/*
		 * Apply the linked/unlinked restriction.
		 */
		myflags |= (gets16(fs, in->di_nlink) ? 
		  FS_FLAG_META_LINK : FS_FLAG_META_UNLINK);
		if ((flags & myflags) != myflags)
			continue;

		/*
		 * Apply the used/unused restriction.
		 */
		myflags |= (gets32(fs, in->di_ctime) ? 
		  FS_FLAG_META_USED : FS_FLAG_META_UNUSED);
		if ((flags & myflags) != myflags)
			continue;

		/*
		 * Fill in a file system-independent inode structure and pass control
		 * to the application.
		 */
		ffs_copy_inode(ffs, fs_inode);
		fs_inode->flags = myflags;
		if (WALK_STOP == action(fs, inum, fs_inode, myflags, ptr)) {
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
ffs_block_walk(FS_INFO *fs, DADDR_T start, DADDR_T last, int flags,
		               FS_BLOCK_WALK_FN action, char *ptr)
{
    char   *myname = "ffs_block_walk";
    FFS_INFO *ffs = (FFS_INFO *) fs;
    FS_BUF *fs_buf = fs_buf_alloc(fs->block_size * ffs->ffsbsize_f);
    CGNUM_T cg_num;
    ffs_cgd *cg = 0;
    DADDR_T dbase = 0;
    DADDR_T dmin = 0;           /* first data block in group */
    DADDR_T sblock = 0;         /* super block in group */
    DADDR_T addr;
    DADDR_T faddr;
    unsigned char *freeblocks = NULL;
    int     myflags;
    int     want;
    int     frags;
    char   *null_block = NULL;

    /*
     * Sanity checks.
     */
    if (start < fs->first_block || start > fs->last_block)
		error("%s: invalid start block number: %lu", myname, (ULONG) start);

    if (last < fs->first_block || last > fs->last_block || last < start)
		error("%s: invalid last block number: %lu", myname, (ULONG) last);

    if ((flags & FS_FLAG_DATA_ALIGN) && (start % ffs->ffsbsize_f) != 0)
		error("%s: specify -b or specify block-aligned start block", myname);

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
    for (addr = start; addr <= last; addr += ffs->ffsbsize_f) {

	/*
	 * Be sure to use the right cylinder group information.
	 */
	cg_num = dtog_lcl(fs, ffs->fs.sb1, addr);
	if (cg == 0 || gets32(fs, cg->cg_cgx) != cg_num) {
		cg = ffs_cgroup_lookup(ffs, cg_num);
		freeblocks = (unsigned char *) cg_blksfree_lcl(fs, cg);
		dbase = cgbase_lcl(fs, ffs->fs.sb1, cg_num);
		dmin = cgdmin_lcl(fs, ffs->fs.sb1, cg_num);
		sblock = cgsblock_lcl(fs, ffs->fs.sb1, cg_num);
	}
	if (addr < dbase)
		remark("impossible: cyl group %lu: block %lu < cgbase %lu",
		   (unsigned long) cg_num, (unsigned long) addr,
		   (unsigned long) dbase);


	/*
	 * Prepare for file systems that have a partial last logical block.
	 */
	frags = (last + 1 - addr > ffs->ffsbsize_f ?
		 ffs->ffsbsize_f : last + 1 - addr);

	/*
	 * See if this logical block contains any fragments of interest. If
	 * not, skip the entire logical block.
	 */
	for (want = 0, faddr = addr; want == 0 && faddr < addr + frags; faddr++)
	    want = (flags & (isset(freeblocks, faddr - dbase) ?
			     FS_FLAG_DATA_UNALLOC : FS_FLAG_DATA_ALLOC));
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

        if ((myflags & FS_FLAG_DATA_META) && (myflags & FS_FLAG_DATA_UNALLOC))
			remark("impossible: unallocated meta block %lu!!",
				   (unsigned long) faddr);

	    if ((flags & myflags) != myflags) {
			/* we dont' want this fragment, but there is another we want,
			 * so we only print it if ALIGN is set */
			if (flags & FS_FLAG_DATA_ALIGN)
		    	if (WALK_STOP == action(fs, faddr, null_block, myflags, ptr)) {
					free(null_block);
    				fs_buf_free(fs_buf);
					return;
				}
	    } else {
			if (fs_buf->addr < 0 || faddr >= fs_buf->addr + ffs->ffsbsize_f) {
				fs->read_block(fs, fs_buf, fs->block_size * frags, addr,
				  "data block");
			}
			if (WALK_STOP == action(fs, faddr,
			  fs_buf->data + fs->block_size * (faddr - fs_buf->addr),
			  myflags, ptr)) {
    				fs_buf_free(fs_buf);
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
    fs_buf_free(fs_buf);
}

/**************************************************************************
 *
 * FILE WALKING
 *
 **************************************************************************/

/*
 * return the amount read or 0 if the action wanted to stop 
 */
static int
ffs_file_walk_direct(FS_INFO *fs, FS_BUF *buf,
  size_t length, DADDR_T addr, int flags, FS_FILE_WALK_FN action, char *ptr)
{
    int     read_count;
    int     myflags;

	read_count = (length < buf->size ? length : buf->size);

    if (addr > fs->last_block) {
        if (flags & FS_FLAG_FILE_NOABORT)  {
			if (verbose) {
				fprintf (logfp, 
				  "Invalid direct block address (too large): %lu",
				  (ULONG)addr);
			}
            return 0;
		}
		else {
			error ("Invalid direct block address (too large): %lu",
			  (ULONG)addr);
		}
    }    

	/* Check if this goes over the end of the image 
	 * This exists when the image size is not a multiple of the block
	 * size and read_count is for a full block.
	 * 
	 */
	if (addr + (read_count/fs->block_size) > fs->last_block) {
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
    } else {
		myflags = FS_FLAG_DATA_CONT;

		if ((flags & FS_FLAG_FILE_AONLY) == 0)
			fs->read_block(fs, buf, roundup(read_count, FFS_DEV_BSIZE), addr,
			  "data block");

		if (WALK_STOP == action(fs, addr, buf->data, read_count, myflags, ptr))
			return 0;
    }
    return (read_count);
}


/*
 * Process the data at block addr as a list of pointers at level _level_
 *
 */
static int
ffs_file_walk_indir(FS_INFO *fs, FS_BUF *buf[], size_t length,
  DADDR_T addr, int level, int flags, FS_FILE_WALK_FN action, char *ptr)
{   
    char   *myname = "ffs_file_walk_indir";
    size_t   todo_count = length;
    DADDR_T *iaddr;
    int     n;

    if (verbose)
        fprintf(logfp, "%s: level %d block %lu\n", myname, level, (ULONG) addr)
;   
    
    if (addr > fs->last_block) {
        if (flags & FS_FLAG_FILE_NOABORT)  {
			if (verbose) {
				fprintf (logfp, 
        		  "Invalid indirect block address (too large): %lu",
				  (ULONG)addr);
			}
            return 0;
		}
		else  {
        	error ("Invalid indirect block address (too large): %lu",
			  (ULONG)addr);
		}
    }    

    /*
     * Read a block of disk addresses.
     */ 
    if (addr == 0)
        memset(buf[level]->data, 0, buf[level]->size); 
    else
        fs->read_block(fs, buf[level], buf[level]->size, addr,
              "disk address block");

	/* we only call the action  if the META flag is set */
    if (flags & FS_FLAG_FILE_META) {
        int myflags = FS_FLAG_DATA_META;
        action(fs, addr, buf[level]->data, buf[level]->size, myflags, ptr);
    }

    /*   
     * For each disk address, copy a direct block or process an indirect
     * block.
     */     
    iaddr = (DADDR_T *) buf[level]->data; 
    for (n = 0; todo_count > 0 && n < buf[level]->size / sizeof(*iaddr); n++) {
		int prevcnt = todo_count;

		if (getu32(fs, (u_int8_t *)&iaddr[n]) > fs->last_block) {
			if (flags & FS_FLAG_FILE_NOABORT) {
				if (verbose) {
					fprintf (logfp, 
					  "Invalid address in indirect list (too large): %lu",
					  (ULONG)getu32(fs, (u_int8_t *)&iaddr[n]));
				}
				return 0;
			}
			else {
				error ("Invalid address in indirect list (too large): %lu",
                  (ULONG)getu32(fs, (u_int8_t *)&iaddr[n]));
			}
        } 

        if (level == 1)
            todo_count -= ffs_file_walk_direct(fs, buf[0], todo_count,
              getu32(fs, (u_int8_t *)&iaddr[n]), flags, action, ptr);
        else
            todo_count -= ffs_file_walk_indir(fs, buf, todo_count,
              getu32(fs, (u_int8_t *)&iaddr[n]), level - 1, flags, action, ptr)
;
		/* This occurs when 0 is returned, which means we want to exit */
		if (prevcnt == todo_count)
			return 0;
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
ffs_file_walk(FS_INFO *fs, FS_INODE *inode, u_int32_t type, u_int16_t id,
    int flags, FS_FILE_WALK_FN action, char *ptr)
{    
	FFS_INFO *ffs = (FFS_INFO *) fs;
	size_t   length;
	FS_BUF **buf;
	int     n;
	int     level, retval;
              
    /*
     * Initialize a buffer for each level of indirection that is supported by
     * this inode. The level 0 buffer is sized to the logical block size used
     * for files. The level 1.. buffers are sized to the block size used for
     * indirect blocks.
     */
    buf = (FS_BUF **) mymalloc(sizeof(*buf) * (inode->indir_count + 1));
    buf[0] = fs_buf_alloc(ffs->ffsbsize_b);
    
    length = inode->size;
	/* If we want the slack of the last fragment, then roundup */
    if (flags & FS_FLAG_FILE_SLACK)
		length = roundup(length, fs->block_size);

    /*
     * Read the file blocks. First the direct blocks, then the indirect ones.
     */     
    for (n = 0; length > 0 && n < inode->direct_count; n++) {
        retval = ffs_file_walk_direct(fs, buf[0], length, 
		  inode->direct_addr[n], flags, action, ptr);

		if (!retval) {
			length  = 0;
			break;
		}
		length -= retval;
	}

	/* if there is still data left, read the indirect */
	if (length > 0) {

		/* allocate buffers */
		for (level = 1; level <= inode->indir_count; level++)
			buf[level] = fs_buf_alloc(ffs->ffsbsize_b);

		for (level = 1; length > 0 && level <= inode->indir_count; level++) {
			retval = ffs_file_walk_indir(fs, buf, length,
			  inode->indir_addr[level - 1], level, flags, action, ptr);

			if (!retval)
				break;
			length -= retval;
		}

		/*
		 * Cleanup.
		 */
		for (level = 1; level <= inode->indir_count; level++)
			fs_buf_free(buf[level]);
	}

	fs_buf_free(buf[0]);
    free((char *) buf);

    return;
}


static void
ffs_fscheck(FS_INFO *fs, FILE *hFile)
{
	error ("fscheck not implemented for ffs yet");
}

static void
ffs_fsstat(FS_INFO *fs, FILE *hFile)
{
	int i;
	time_t tmptime;
	ffs_csum  *csum = NULL;
	ffs_cgd	 *cgd = NULL;

	FFS_INFO *ffs = (FFS_INFO *) fs;
	ffs_sb1 *sb1 = ffs->fs.sb1;
	ffs_sb2 *sb2 = ffs->fs.sb2;

	fprintf(hFile, "FILE SYSTEM INFORMATION\n");
	fprintf(hFile, "--------------------------------------------\n");   

	if (ffs->ver == FFS_UFS1) {
		fprintf(hFile, "File System Type: UFS 1\n");
		tmptime = getu32(fs, sb1->wtime);
		fprintf(hFile, "Last Written: %s", asctime(localtime(&tmptime)));
		fprintf(hFile, "Last Mount Point: %s\n",
		  sb1->last_mnt);
	}
	else {
		fprintf(hFile, "File System Type: UFS 2\n");
		tmptime = getu32(fs, sb2->wtime);
		fprintf(hFile, "Last Written: %s", asctime(localtime(&tmptime)));
		fprintf(hFile, "Last Mount Point: %s\n",
		  sb2->last_mnt);
		fprintf(hFile, "Volume Name: %s\n",
		  sb2->volname);
		fprintf(hFile, "System UID: %"PRIu64"\n",
		  getu64(fs, sb2->swuid));
	}



	fprintf(hFile, "\nMETADATA INFORMATION\n");
	fprintf(hFile, "--------------------------------------------\n");

	fprintf(hFile, "Inode Range: %lu - %lu\n", 
	  (ULONG)fs->first_inum, (ULONG)fs->last_inum);
	fprintf(hFile, "Root Directory: %lu\n", (ULONG)fs->root_inum);
	fprintf(hFile, "Num of Avail Inodes: %"PRIu32"\n",
		       getu32(fs, sb1->cstotal.ino_free));	
	fprintf(hFile, "Num of Directories: %"PRIu32"\n",
		       getu32(fs, sb1->cstotal.dir_num));	


	fprintf(hFile, "\nCONTENT INFORMATION\n");
	fprintf(hFile, "--------------------------------------------\n");

	fprintf(hFile, "Fragment Range: %lu - %lu\n", 
	  (ULONG)fs->first_block, (ULONG)fs->last_block);

	fprintf(hFile, "Block Size: %lu\n", (ULONG)ffs->ffsbsize_b);
	fprintf(hFile, "Fragment Size: %lu\n", (ULONG)fs->block_size);

	fprintf(hFile, "Num of Avail Full Blocks: %"PRIu32"\n",
		       getu32(fs, sb1->cstotal.blk_free));	
	fprintf(hFile, "Num of Avail Fragments: %"PRIu32"\n",
		       getu32(fs, sb1->cstotal.frag_free));	

	fprintf(hFile, "\nCYLINDER GROUP INFORMATION\n");
	fprintf(hFile, "--------------------------------------------\n");

	fprintf(hFile, "Number of Cylinder Groups: %d\n", gets32(fs, sb1->cg_num));
	fprintf(hFile, "Inodes per group: %d\n", gets32(fs, sb1->cg_inode_num));
	fprintf(hFile, "Fragments per group: %d\n", gets32(fs, sb1->cg_frag_num));


	if (getu32(fs, sb1->cg_ssize_b)) {
		csum = (ffs_csum *)mymalloc(getu32(fs, sb1->cg_ssize_b));
		fs->io->read_random(fs->io, (char *) csum, getu32(fs, sb1->cg_ssize_b),
		  getu32(fs, sb1->cg_saddr) * fs->block_size, "group descriptor");
	}

	for (i = 0; i < gets32(fs, sb1->cg_num); i++) {

		cgd = ffs_cgroup_lookup(ffs, i);

		fprintf(hFile, "\nGroup %d:\n", i);
		if (cgd) {
			tmptime = getu32(fs, cgd->wtime);
			fprintf(hFile, "  Last Written: %s", asctime(localtime(&tmptime)));
		}
		
		fprintf(hFile, "  Inode Range: %lu - %lu\n", 
		  (ULONG)(gets32(fs, sb1->cg_inode_num) * i),
		  (((ULONG)(gets32(fs, sb1->cg_inode_num) * (i + 1)) - 1) < fs->last_inum) ?
		  ((ULONG)(gets32(fs, sb1->cg_inode_num) * (i + 1)) - 1) : fs->last_inum) ;

		fprintf(hFile, "  Fragment Range: %lu - %lu\n",
		  (ULONG)cgbase_lcl(fs, sb1, i), 
		  (((ULONG)cgbase_lcl(fs, sb1, i + 1) - 1) < fs->last_block) ?
		  ((ULONG)cgbase_lcl(fs, sb1, i + 1) - 1) : fs->last_block);

		/* The first group is special because the first 16 sectors are
		 * reserved for the boot block.  
		 * the next contains the primary Super Block 
		 */
		if (!i) {
			fprintf(hFile, "    Boot Block: 0 - %lu\n",
			  (ULONG)(15 * 512 / fs->block_size));

			fprintf(hFile, "    Super Block: %lu - %lu\n",
			  (ULONG)(16 * 512 / fs->block_size),
			  (ULONG)(16 * 512 / fs->block_size) + 
			  ((roundup(sizeof(ffs_sb1), fs->block_size) / fs->block_size) - 1));
		}

		fprintf(hFile, "    Super Block: %lu - %lu\n",
		  (ULONG)cgsblock_lcl(fs, sb1, i),
		  (ULONG)(cgsblock_lcl(fs, sb1, i) + 
		  ((roundup(sizeof(ffs_sb1), fs->block_size) / fs->block_size) - 1)));

		fprintf(hFile, "    Group Desc: %lu - %lu\n", 
		  (ULONG)cgtod_lcl(fs, sb1, i),
		  (ULONG)(cgtod_lcl(fs, sb1, i) + 
		  ((roundup(sizeof(ffs_cgd), fs->block_size) / fs->block_size) - 1)));

		fprintf(hFile, "    Inode Table: %lu - %lu\n", 
		  (ULONG)cgimin_lcl(fs, sb1, i),
		  (ULONG)(cgimin_lcl(fs, sb1, i) + 
		  ((roundup(gets32(fs, sb1->cg_inode_num)*sizeof(ffs_inode1), fs->block_size) 
		  / fs->block_size) - 1)));

		fprintf(hFile, "    Data Fragments: ");

		/* For all groups besides the first, the space before the
		 * super block is also used for data
		 */
		if (i)
			fprintf(hFile, "%lu - %lu, ",
			  (ULONG)cgbase_lcl(fs, sb1, i), 
			  (ULONG)cgsblock_lcl(fs, sb1, i) - 1);
			  
		fprintf(hFile, "%lu - %lu\n",
		  (ULONG)cgdmin_lcl(fs, sb1, i),
		  (((ULONG)cgbase_lcl(fs, sb1, i + 1) - 1) < fs->last_block) ?
		  ((ULONG)cgbase_lcl(fs, sb1, i + 1) - 1) : fs->last_block);


		if ((csum) && ((i+1)*sizeof(ffs_csum) < getu32(fs, sb1->cg_ssize_b)) ) {
			fprintf(hFile, "  Global Summary (from the super block):\n");
			fprintf(hFile, "    Num of Dirs: %"PRIu32"\n", 
				getu32(fs, &csum[i].dir_num));
			fprintf(hFile, "    Num of Avail Blocks: %"PRIu32"\n", 
				getu32(fs, &csum[i].blk_free));
			fprintf(hFile, "    Num of Avail Inodes: %"PRIu32"\n", 
				getu32(fs, &csum[i].ino_free));
			fprintf(hFile, "    Num of Avail Frags: %"PRIu32"\n", 
				getu32(fs, &csum[i].frag_free));
		}


		if (cgd) {
			fprintf(hFile, "  Local Summary (from the group descriptor):\n");
			fprintf(hFile, "    Num of Dirs: %"PRIu32"\n", 
				getu32(fs, &cgd->cs.dir_num));
			fprintf(hFile, "    Num of Avail Blocks: %"PRIu32"\n", 
				getu32(fs, &cgd->cs.blk_free));
			fprintf(hFile, "    Num of Avail Inodes: %"PRIu32"\n", 
				getu32(fs, &cgd->cs.ino_free));
			fprintf(hFile, "    Num of Avail Frags: %"PRIu32"\n", 
				getu32(fs, &cgd->cs.frag_free));

			fprintf(hFile, "    Last Block Allocated: %"PRIu32"\n", 
				getu32(fs, &cgd->last_alloc_blk) +
		  		cgbase_lcl(fs, sb1, i));

			fprintf(hFile, "    Last Fragment Allocated: %"PRIu32"\n", 
				getu32(fs, &cgd->last_alloc_frag) +
		  		cgbase_lcl(fs, sb1, i));

			fprintf(hFile, "    Last Inode Allocated: %"PRIu32"\n", 
				getu32(fs, &cgd->last_alloc_ino) + 
				(gets32(fs, sb1->cg_inode_num) * i));

		}


	}

	return;
}





/************************* istat *******************************/

static int printidx = 0;
#define WIDTH   8

/* indirect block accounting */
#define INDIR_SIZ   64
static DADDR_T indirl[INDIR_SIZ];
static  unsigned char   indir_idx;


static u_int8_t
print_addr_act (FS_INFO *fs, DADDR_T addr, char *buf,
  int size, int flags, char *ptr)
{   
	FILE *hFile = (FILE *)ptr;

    if (flags & FS_FLAG_DATA_CONT) {
        int i, s;
        /* cycle through the fragments if they exist */
        for (i = 0, s = size; s > 0; s-= fs->block_size, i++) {

            /* sparse file */
            if (addr)
                fprintf(hFile, "%lu ", (unsigned long) addr + i);
            else  
                fprintf (hFile, "0 ");

            if (++printidx == WIDTH) {
                fprintf(hFile, "\n");
                printidx = 0;
            }
        }
    }

    /* this must be an indirect block pointer, so put it in the list */
    else if (flags & FS_FLAG_DATA_META) {
        if (indir_idx < INDIR_SIZ)
            indirl[indir_idx++] = addr;
    }
    return WALK_CONT;
}


static void
ffs_istat (FS_INFO *fs, FILE *hFile, INUM_T inum, int numblock, 
  int32_t sec_skew)
{
	FFS_INFO *ffs = (FFS_INFO *) fs;
	FS_INODE *fs_inode;
	char ls[12];

	fs_inode = ffs_inode_lookup (fs, inum);
	fprintf(hFile, "inode: %lu\n", (ULONG) inum);
	fprintf(hFile, "%sAllocated\n", 
	  (fs_inode->flags&FS_FLAG_META_ALLOC)?"":"Not ");

	fprintf(hFile, "Group: %lu\n", (ULONG)ffs->cg_num);

    if (fs_inode->link)
        fprintf(hFile, "symbolic link to: %s\n", fs_inode->link);

    fprintf(hFile, "uid / gid: %d / %d\n", 
	  (int)fs_inode->uid, (int)fs_inode->gid);


    make_ls(fs_inode->mode, ls, 12);
    fprintf(hFile, "mode: %s\n", ls);

	fprintf(hFile, "size: %llu\n", (ULLONG) fs_inode->size);
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
	else
		fprintf(hFile, "\nInode Times:\n");

	fprintf(hFile, "Accessed:\t%s", ctime(&fs_inode->atime));
	fprintf(hFile, "File Modified:\t%s", ctime(&fs_inode->mtime));
	fprintf(hFile, "Inode Modified:\t%s", ctime(&fs_inode->ctime));

	/* A bad hack to force a specified number of blocks */
	if (numblock > 0)
		fs_inode->size = numblock * ffs->ffsbsize_b;

	fprintf (hFile, "\nDirect Blocks:\n");

	indir_idx = 0;
	fs->file_walk(fs, fs_inode, 0, 0, 
	  FS_FLAG_FILE_AONLY | FS_FLAG_FILE_META | FS_FLAG_FILE_NOID, 
	  print_addr_act, (char *)hFile);

    if (printidx != 0)
        fprintf(hFile, "\n");

    /* print indirect blocks */
    if (indir_idx > 0) {
        int i;
        fprintf(hFile, "\nIndirect Blocks:\n");

        printidx = 0;

        for (i = 0; i < indir_idx; i++) {
            fprintf(hFile, "%lu ", (unsigned long) indirl[i]);
            if (++printidx == WIDTH) {
                fprintf(hFile, "\n");
                printidx = 0;
            }
        }
        if (printidx != 0)
            fprintf(hFile, "\n");
    }

	return;
}



/* ffs_close - close a fast file system */
static void 
ffs_close(FS_INFO *fs)
{
    FFS_INFO *ffs = (FFS_INFO *) fs;

    fs->io->close(fs->io);
    ffs_cgroup_free(ffs);
    ffs_dinode_free(ffs);
    free((char *) ffs->fs.sb1);
    free(ffs->dinode);
    free(ffs);
}

/* ffs_open - open a fast file system */

FS_INFO *
ffs_open(IO_INFO *io, unsigned char ftype)
{
	char   *myname = "ffs_open";
	FFS_INFO *ffs = (FFS_INFO *) mymalloc(sizeof(*ffs));
	int     len;
	FS_INFO	*fs = &(ffs->fs_info);
	//Initialise the io subsystem in the fs object
	fs->io=io;

	if ((ftype & FSMASK) != FFS_TYPE) {
		return(NULL);
		error ("Invalid FS Type in ffs_open");
	}

	/* Open the image */
	//if ((fs->fd = open(name, O_RDONLY)) < 0)
	//	error("%s: open %s: %m", myname, name);

	fs->ftype = ftype;
	fs->flags = 0;


	/*
	 * Try UFS 1 first
	 */
	/* ffs_sb2 is bigger, so allocate space for it */
	len = roundup(sizeof(ffs_sb2), FFS_DEV_BSIZE);
	ffs->fs.sb1 = (ffs_sb1 *) mymalloc(len);

	fs->io->read_random(fs->io,(char *) ffs->fs.sb1, sizeof(ffs_sb1), UFS1_SBOFF,myname);

	/* check the magic and figure out the endian ordering */
	if (guessu32(fs, ffs->fs.sb1->magic, UFS1_FS_MAGIC)) {

		fs->io->read_random(fs->io,(char *) ffs->fs.sb2, sizeof(ffs_sb2),UFS2_SBOFF,myname);

		/* If that didn't work, try the 256KB location */
		if (guessu32(fs, ffs->fs.sb2->magic, UFS2_FS_MAGIC)) {

			fs->io->read_random(fs->io,(char *) ffs->fs.sb2, sizeof(ffs_sb2),UFS2_SBOFF2,myname);

			if (guessu32(fs, ffs->fs.sb2->magic, UFS2_FS_MAGIC)) {
				return(NULL);
				//error("Error: %s is not a FFS file system", name);
			}
		
		}
		ffs->ver = FFS_UFS2;
	}
	else {
		ffs->ver = FFS_UFS1;
	}


	/*
	 * Translate some filesystem-specific information to generic form.
	 */
	if (ffs->ver == FFS_UFS1) {
		fs->inum_count = gets32(fs, ffs->fs.sb1->cg_num) * gets32(fs, ffs->fs.sb1->cg_inode_num);
	} 
	else {
		fs->inum_count = gets32(fs, ffs->fs.sb2->cg_num) * gets32(fs, ffs->fs.sb2->cg_inode_num);

	}

	fs->root_inum = FFS_ROOTINO;
	fs->first_inum = FFS_FIRSTINO;
	fs->last_inum = fs->inum_count - 1;


	if (ffs->ver == FFS_UFS1) {
		fs->block_count = gets32(fs, ffs->fs.sb1->frag_num);
		fs->block_size = gets32(fs, ffs->fs.sb1->fsize_b);
		ffs->ffsbsize_b = gets32(fs, ffs->fs.sb1->bsize_b);
		ffs->ffsbsize_f = gets32(fs, ffs->fs.sb1->bsize_frag);
	}
	else {
		fs->block_count = gets64(fs, ffs->fs.sb2->frag_num);
		fs->block_size = gets32(fs, ffs->fs.sb2->fsize_b);
		ffs->ffsbsize_b = gets32(fs, ffs->fs.sb2->bsize_b);
		ffs->ffsbsize_f = gets32(fs, ffs->fs.sb2->bsize_frag);
	}

	fs->first_block = 0;
	fs->last_block = fs->block_count - 1;
	fs->dev_bsize = FFS_DEV_BSIZE;


	/*
	 * Other initialization: caches, callbacks.
	 */
	ffs->cg_buf = 0;
	ffs->cg_num = -1;
	ffs->dino_buf = 0;
	fs->seek_pos = -1;

	fs->inode_walk = ffs_inode_walk;
	fs->read_block = fs_read_block;
	fs->block_walk = ffs_block_walk;
	fs->inode_lookup = ffs_inode_lookup;
	fs->dent_walk = ffs_dent_walk;
	fs->file_walk = ffs_file_walk;
	fs->fsstat = ffs_fsstat;
	fs->fscheck = ffs_fscheck;
	fs->istat = ffs_istat;
	fs->close = ffs_close;

	/* allocate the dinode buffer */
	if (ffs->ver == FFS_UFS1) 
		ffs->dinode = (char *) mymalloc(sizeof(ffs_inode1));
	else
		ffs->dinode = (char *) mymalloc(sizeof(ffs_inode1));

	/*
	 * Print some stats.
	 */
	if (verbose)
		fprintf(logfp,
		"inodes %lu root ino %lu cyl groups %lu blocks %lu\n",
		(ULONG) fs->inum_count,
		(ULONG) fs->root_inum,
		(ULONG) gets32(fs, ffs->fs.sb1->cg_num),
		(ULONG) fs->block_count);

	return (fs);
}

