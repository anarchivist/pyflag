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
 *	ext2fs_open 3
 * SUMMARY
 *	LINUX file system support
 * SYNOPSIS
 *	#include "fstools.h"
 *
 *	FS_INFO *ext2fs_open(const char *name)
 * DESCRIPTION
 *	ext2fs_open() opens the named block device and makes it accessible
 *	for the standard file system operations described in fs_open(3).
 * BUGS
 *	You need a LINUX machine in order to access LINUX disks.
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
#include "ext2fs.h"
#include "fs_io.h"
#include "mymalloc.h"
#include "error.h"

/* ext2fs_group_lookup - look up group descriptor info */

static void 
ext2fs_group_lookup(EXT2FS_INFO *ext2fs, GRPNUM_T grpnum)
{
    ext2fs_gd *gd = ext2fs->group;
    OFF_T   offs;

    /*
     * Sanity check
     */
    if (grpnum < 0 || grpnum >= ext2fs->groups_count)
		error("invalid group descriptor number: %lu", (ULONG) grpnum);

    /*
     * We're not reading group descriptors often, so it is OK to do small
     * reads instead of cacheing group descriptors in a large buffer.
     */
    offs = ext2fs->group_offset + grpnum * sizeof(ext2fs_gd);
    ext2fs->fs_info.io->read_random(ext2fs->fs_info.io,(char *) gd, sizeof(ext2fs_gd),offs, "group descriptor");
    ext2fs->grpnum = grpnum;

    if (verbose) {
		FS_INFO *fs = (FS_INFO *)&ext2fs->fs_info;
		fprintf(logfp,
			"\tgroup %lu: %lu/%lu free blocks/inodes\n",
			(ULONG) grpnum,
			(ULONG) getu16(fs, gd->bg_free_blocks_count),
			(ULONG) getu16(fs, gd->bg_free_inodes_count));
	}
}

/* ext2fs_print_map - print a bitmap */

static void 
ext2fs_print_map(UCHAR * map, int len)
{
    int     i;

    for (i = 0; i < len; i++) {
		if (i > 0 && i % 10 == 0)
	    	putc('|', logfp);
		putc(isset(map, i) ? '1' : '.', logfp);
    }
    putc('\n', logfp);
}

/* ext2fs_bmap_lookup - look up block bitmap */

UCHAR  *
ext2fs_bmap_lookup(EXT2FS_INFO *ext2fs, GRPNUM_T grpnum)
{
	FS_INFO *fs = (FS_INFO *)&ext2fs->fs_info;

    /*
     * Look up the group descriptor info.
     */
    if (ext2fs->grpnum != grpnum)
		ext2fs_group_lookup(ext2fs, grpnum);

    /*
     * Look up the block allocation bitmap.
     */
    fs->io->read_random(fs->io,(char *) ext2fs->block_map,
		   ext2fs->fs_info.block_size,
		   (OFF_T) getu32(fs, ext2fs->group->bg_block_bitmap) * 
		   (OFF_T) ext2fs->fs_info.block_size,
		   "block bitmap");

    ext2fs->bmap_num = grpnum;

    if (verbose > 1)
		ext2fs_print_map(ext2fs->block_map, 
		  getu32(fs, ext2fs->fs->s_blocks_per_group));

    return (ext2fs->block_map);
}

/* ext2fs_imap_lookup - look up inode bitmap */

UCHAR  *
ext2fs_imap_lookup(EXT2FS_INFO *ext2fs, GRPNUM_T grpnum)
{

	FS_INFO *fs = (FS_INFO *)&ext2fs->fs_info;
    /*
     * Look up the group descriptor info.
     */
    if (ext2fs->grpnum != grpnum)
		ext2fs_group_lookup(ext2fs, grpnum);

    /*
     * Look up the inode allocation bitmap.
     */
    fs->io->read_random(fs->io,(char *) ext2fs->inode_map,
		   ext2fs->fs_info.block_size,
		   (OFF_T) getu32(fs, ext2fs->group->bg_inode_bitmap) * 
		   (OFF_T) ext2fs->fs_info.block_size,
		   "inode bitmap");
    ext2fs->imap_num = grpnum;
    if (verbose > 1)
		ext2fs_print_map(ext2fs->inode_map, 
		  getu32(fs, ext2fs->fs->s_inodes_per_group));

    return (ext2fs->inode_map);
}

/* ext2fs_dinode_lookup - look up disk inode */

static void
ext2fs_dinode_lookup(EXT2FS_INFO *ext2fs, INUM_T inum)
{
    ext2fs_inode *dino = ext2fs->dinode;
    GRPNUM_T grpnum;
    OFF_T   addr;
    size_t  offs;
	FS_INFO *fs = (FS_INFO *)&ext2fs->fs_info;

    /*
     * Sanity check.
     */
    if ((inum < fs->first_inum) || (inum > fs->last_inum))
		error("invalid inode number: %lu", (ULONG) inum);

    /*
     * Look up the group descriptor for this inode. 
     */
	grpnum = (inum - fs->first_inum) / 
	  getu32(fs, ext2fs->fs->s_inodes_per_group);

	if (ext2fs->grpnum != grpnum)
		ext2fs_group_lookup(ext2fs, grpnum);

    /*
     * Look up the inode table block for this inode.
     */
    offs = (inum - 1) - getu32(fs, ext2fs->fs->s_inodes_per_group) * grpnum;
    addr = (OFF_T) getu32(fs, ext2fs->group->bg_inode_table) * 
	  (OFF_T)fs->block_size
	  + offs * (OFF_T)ext2fs->inode_size;

    fs->io->read_random(fs->io, (char *) dino, ext2fs->inode_size,
	  addr, "inode block");

    ext2fs->inum = inum;
    if (verbose)
		fprintf(logfp, 
		  "%lu m/l/s=%o/%d/%llu u/g=%d/%d macd=%lu/%lu/%lu/%lu\n",
		  (ULONG) inum, 
		  getu16(fs, dino->i_mode),
		  getu16(fs, dino->i_nlink),
		  (ULLONG) (getu32(fs, dino->i_size) + 
		    (getu16(fs, dino->i_mode) & EXT2_IN_REG) ?
		    (u_int64_t) getu32(fs, dino->i_size_high) << 32 : 0),
		  getu16(fs, dino->i_uid) + (getu16(fs, dino->i_uid_high)<<16),
		  getu16(fs, dino->i_gid) + (getu16(fs, dino->i_gid_high)<<16),
		  (ULONG) getu32(fs, dino->i_mtime),
		  (ULONG) getu32(fs, dino->i_atime),
		  (ULONG) getu32(fs, dino->i_ctime),
		  (ULONG) getu32(fs, dino->i_dtime));
}

/* ext2fs_copy_inode - copy disk inode to generic inode */

static void 
ext2fs_copy_inode(EXT2FS_INFO *ext2fs, FS_INODE *fs_inode)
{
	int     i;
	ext2fs_inode 	*in = ext2fs->dinode;
	FS_INFO *fs = (FS_INFO *)&ext2fs->fs_info;
	ext2fs_sb *sb = ext2fs->fs;
	GRPNUM_T grpnum;
	UCHAR  *imap = 0;
	INUM_T  ibase = 0;

	fs_inode->mode =  getu16(fs, in->i_mode);
	fs_inode->nlink =  getu16(fs, in->i_nlink);

	fs_inode->size =  getu32(fs, in->i_size);

	/* the general size value in the inode is only 32-bits,
	 * but the i_dir_acl value is used for regular files to 
	 * hold the upper 32-bits 
	 *
	 * The RO_COMPAT_LARGE_FILE flag in the super block will identify
	 * if there are any large files in the file system
	 */
	if ((fs_inode->mode & EXT2_IN_REG) && 
	  (getu32(fs, sb->s_feature_ro_compat) & 
		  EXT2FS_FEATURE_RO_COMPAT_LARGE_FILE) ) {
		fs_inode->size +=  ((u_int64_t)getu32(fs, in->i_size_high) << 32);
	}

	fs_inode->uid =  getu16(fs, in->i_uid) + (getu16(fs, in->i_uid_high)<<16);
	fs_inode->gid =  getu16(fs, in->i_gid) + (getu16(fs, in->i_gid_high)<<16);
	fs_inode->mtime =  getu32(fs, in->i_mtime);
	fs_inode->atime =  getu32(fs, in->i_atime);
	fs_inode->ctime =  getu32(fs, in->i_ctime);
	fs_inode->dtime =  getu32(fs, in->i_dtime);

	fs_inode->seq = 0;

	if (fs_inode->link) {
		free(fs_inode->link);
		fs_inode->link = NULL;
	}	

	if (fs_inode->direct_count != EXT2FS_NDADDR
	  || fs_inode->indir_count != EXT2FS_NIADDR)
		fs_inode_realloc(fs_inode, EXT2FS_NDADDR,
			 EXT2FS_NIADDR);

	for (i = 0; i < EXT2FS_NDADDR; i++)
		fs_inode->direct_addr[i] = gets32(fs, in->i_block[i]);

	for (i = 0; i < EXT2FS_NIADDR; i++)
		fs_inode->indir_addr[i] = gets32(fs, in->i_block[i+EXT2FS_NDADDR]);


    /* set the link string 
	 * the size check prevents us from trying to allocate a huge amount of
	 * memory for a bad inode value
	*/
    if (((fs_inode->mode & FS_INODE_FMT) == FS_INODE_LNK)  &&
	  (fs_inode->size < EXT2FS_MAXPATHLEN) && (fs_inode->size >= 0)) {
        int count = 0, j;

        fs_inode->link = mymalloc(fs_inode->size + 1);

        /* it is located directly in the pointers */
        if (fs_inode->size < 4 * (EXT2FS_NDADDR + EXT2FS_NIADDR)) {
            for (i=0; i < (EXT2FS_NDADDR + EXT2FS_NIADDR) && 
			  count < fs_inode->size; i++) {
				char *ptr = (char *)&in->i_block[i];
                for (j = 0; j < 4 && count < fs_inode->size; j++) {
                    fs_inode->link[count++] = ptr[j];
                }
            }
			fs_inode->link[count] = '\0';

			/* clear the values to avoid the prog from reading them */
			for (i = 0; i < EXT2FS_NDADDR; i++)
				fs_inode->direct_addr[i] = 0;
			for (i = 0; i < EXT2FS_NIADDR; i++)
				fs_inode->indir_addr[i] = 0;
        }

        /* it is in blocks */
        else {
			FS_INFO *fs = (FS_INFO *)&ext2fs->fs_info;
            FS_BUF *fs_buf = fs_buf_alloc(fs->block_size);
            char *ptr = fs_inode->link;

			/* we only need to do the direct blocks due to the limit 
			 * on path length */
            for (i = 0; i < EXT2FS_NDADDR && count < fs_inode->size; i++) {
                int read_count = (fs_inode->size - count < fs->block_size)?
                    fs_inode->size - count : fs->block_size;

                fs->read_block(fs,fs_buf, fs->block_size,
                  fs_inode->direct_addr[i], "link block");

                memcpy (ptr, fs_buf->data, read_count);
                count += read_count;
                ptr = (char *)(int)ptr + count;
             }

			 /* terminate the string */
			 *ptr = '\0';
             fs_buf_free(fs_buf);
        }

    }

	/* Fill in the flags value */
    grpnum = (ext2fs->inum - fs->first_inum) / 
	  getu32(fs, ext2fs->fs->s_inodes_per_group);

	imap = ext2fs_imap_lookup(ext2fs, grpnum);
	ibase = grpnum * getu32(fs, ext2fs->fs->s_inodes_per_group) + 
	  fs->first_inum;
 
    /*
     * Apply the allocated/unallocated restriction.
     */
    fs_inode->flags = (isset(imap, ext2fs->inum - ibase) ?
           FS_FLAG_META_ALLOC : FS_FLAG_META_UNALLOC);

    fs_inode->flags |= (fs_inode->nlink ?
      FS_FLAG_META_LINK : FS_FLAG_META_UNLINK);

    /*
     * Apply the used/unused restriction.
     */

    fs_inode->flags |= (fs_inode->ctime ?
      FS_FLAG_META_USED : FS_FLAG_META_UNUSED);

}

/* ext2fs_inode_lookup - lookup inode, external interface */

static FS_INODE *
ext2fs_inode_lookup(FS_INFO *fs, INUM_T inum)
{
    EXT2FS_INFO *ext2fs = (EXT2FS_INFO *) fs;
    FS_INODE *fs_inode = fs_inode_alloc(EXT2FS_NDADDR,EXT2FS_NIADDR);

    ext2fs_dinode_lookup(ext2fs, inum);
    ext2fs_copy_inode(ext2fs, fs_inode);


    return (fs_inode);
}

/* ext2fs_inode_walk - inode iterator 
 *
 * flags used: FS_FLAG_META_USED, FS_FLAG_META_UNUSED,
 *  FS_FLAG_META_LINK, FS_FLAG_META_UNLINK,
 *  FS_FLAG_META_ALLOC, FS_FLAG_META_UNALLOC
*/

void    
ext2fs_inode_walk(FS_INFO *fs, INUM_T start, INUM_T last, int flags,
			          FS_INODE_WALK_FN action, char *ptr)
{
    char   *myname = "extXfs_inode_walk";
    EXT2FS_INFO *ext2fs = (EXT2FS_INFO *) fs;
    GRPNUM_T grpnum;
    UCHAR  *imap = 0;
    INUM_T  inum;
    INUM_T  ibase = 0;
    FS_INODE *fs_inode = fs_inode_alloc(EXT2FS_NDADDR,EXT2FS_NIADDR);
    int     myflags;

    /*
     * Sanity checks.
     */
    if (start < fs->first_inum || start > fs->last_inum)
		error("%s: invalid start inode number: %lu", myname, (ULONG) start);
    if (last < fs->first_inum || last > fs->last_inum || last < start)
		error("%s: invalid last inode number: %lu", myname, (ULONG) last);

    /*
     * Iterate.
     */
    for (inum = start; inum <= last; inum++) {

	/*
	 * Be sure to use the proper group descriptor data. XXX Linux inodes
	 * start at 1, as in Fortran.
	 */
	grpnum = (inum - 1) / getu32(fs, ext2fs->fs->s_inodes_per_group);
	if (imap == 0 || ext2fs->imap_num != grpnum) {
	    imap = ext2fs_imap_lookup(ext2fs, grpnum);
	  	ibase = grpnum * getu32(fs, ext2fs->fs->s_inodes_per_group) + 1;
	}

	/*
	 * Apply the allocated/unallocated restriction.
	 */
	myflags = (isset(imap, inum - ibase) ?
		   FS_FLAG_META_ALLOC : FS_FLAG_META_UNALLOC);
	if ((flags & myflags) != myflags)
	    continue;

	ext2fs_dinode_lookup(ext2fs, inum);

	/*
	 * Apply the linked/unlinked restriction.
	 */
	myflags |= (getu16(fs, ext2fs->dinode->i_nlink) ? 
	  FS_FLAG_META_LINK : FS_FLAG_META_UNLINK);

	if ((flags & myflags) != myflags)
	    continue;

	/*
	 * Apply the used/unused restriction.
	 */

    myflags |= (getu32(fs, ext2fs->dinode->i_ctime) ? 
	  FS_FLAG_META_USED : FS_FLAG_META_UNUSED);

	if ((flags & myflags) != myflags)
	    continue;

	/*
	 * Fill in a file system-independent inode structure and pass control
	 * to the application.
	 */
	ext2fs_copy_inode(ext2fs, fs_inode);
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

/* ext2fs_block_walk - block iterator 
 *
 * flags: FS_FLAG_DATA_ALLOC, FS_FLAG_DATA_UNALLOC, FS_FLAG_DATA_CONT,
 *  FS_FLAG_DATA_META
*/

void    
ext2fs_block_walk(FS_INFO *fs, DADDR_T start, DADDR_T last, int flags,
          FS_BLOCK_WALK_FN action, char *ptr)
{
    char   *myname = "extXfs_block_walk";
    EXT2FS_INFO *ext2fs = (EXT2FS_INFO *) fs;
    FS_BUF *fs_buf = fs_buf_alloc(fs->block_size);
    GRPNUM_T grpnum;
    UCHAR  *bmap = 0;
    DADDR_T addr;
    DADDR_T dbase = 0;          /* first block number in group */
	DADDR_T dmin = 0;           /* first block after inodes */
    int     myflags;

    /*
     * Sanity checks.
     */
    if (start < fs->first_block || start > fs->last_block)
		error("%s: invalid start block number: %lu", myname, (ULONG) start);
    if (last < fs->first_block || last > fs->last_block || last < start)
		error("%s: invalid last block number: %lu", myname, (ULONG) last);

    /*
     * Iterate. This is not as tricky as it could be, because the free list
     * map covers the entire disk partition, including blocks occupied by
     * group descriptor blocks, bit maps, and other non-data blocks.
     */
    for (addr = start; addr <= last; addr++) {

	/*
	 * Be sure to use the right group descriptor information. XXX There
	 * appears to be an off-by-one discrepancy between bitmap offsets and
	 * disk block numbers.
	 *
	 * Addendum: this offset is controlled by the super block's
	 * s_first_data_block field.
	 */
#define INODE_TABLE_SIZE(ext2fs) \
    ((getu32(fs, ext2fs->fs->s_inodes_per_group) * ext2fs->inode_size - 1) \
           / fs->block_size + 1)

	/* This is meta data that is not described in the groups */
	if (addr < getu32(fs, ext2fs->fs->s_first_data_block)) {
		myflags = FS_FLAG_DATA_META | FS_FLAG_DATA_ALLOC;
		ext2fs->grpnum = -1;

		if ((flags & myflags) == myflags) {
			fs->read_block(fs,fs_buf, fs->block_size, addr, "data block");
			if (WALK_STOP == action(fs, addr, fs_buf->data, myflags, ptr)) {
				fs_buf_free(fs_buf);
				return;
			}
		}
		continue;
	}
	grpnum = ext2_dtog_lcl(fs, ext2fs->fs, addr);

	/* Lookup bitmap if not loaded */
	if (bmap == 0 || ext2fs->bmap_num != grpnum) {
	    bmap = ext2fs_bmap_lookup(ext2fs, grpnum);
		dbase = ext2_cgbase_lcl(fs, ext2fs->fs, grpnum);
        dmin = getu32(fs, ext2fs->group->bg_inode_table) + 
		  INODE_TABLE_SIZE(ext2fs);

        if (verbose)
        fprintf(logfp, "group %d dbase %lu bmap %+ld imap %+ld inos %+ld..%ld\n"
,
            (int) grpnum,
            (ULONG) dbase,
            (long) getu32(fs, ext2fs->group->bg_block_bitmap) - (long) dbase,
            (long) getu32(fs, ext2fs->group->bg_inode_bitmap) - (long) dbase,
            (long) getu32(fs, ext2fs->group->bg_inode_table) - (long) dbase,
            (long) dmin - 1 - dbase);
	}

	/*
     * Pass blocks of interest to the application. Identify meta blocks
     * (any blocks that can't be allocated for file/directory data).
     *
     * XXX With sparse superblock placement, most block groups have the
     * block and inode bitmaps where one would otherwise find the backup
     * superblock and the backup group descriptor blocks. The inode
     * blocks are in the normal place, though. This leaves little gaps
     * between the bitmaps and the inode table - and ext2fs will use
     * those blocks for file/directory data blocks. So we must properly
     * account for those gaps between meta blocks.
     *
     * Thus, superblocks and group descriptor blocks are sometimes overlaid
     * by bitmap blocks. This means that one can still assume that the
     * locations of superblocks and group descriptor blocks are reserved.
     * They just happen to be reserved for something else :-)
	 */
	myflags = (isset(bmap, addr - dbase) ?
		   FS_FLAG_DATA_ALLOC : FS_FLAG_DATA_UNALLOC);
    if ((addr >= dbase && addr < getu32(fs, ext2fs->group->bg_block_bitmap))
        || (addr == getu32(fs, ext2fs->group->bg_block_bitmap))
        || (addr == getu32(fs, ext2fs->group->bg_inode_bitmap))
        || (addr >= getu32(fs, ext2fs->group->bg_inode_table) && addr < dmin))
        myflags |= FS_FLAG_DATA_META;
	else 
        myflags |= FS_FLAG_DATA_CONT;

    if ((myflags & FS_FLAG_DATA_META) && (myflags & FS_FLAG_DATA_UNALLOC)) {
        remark("unallocated meta block %lu!! dbase %lu dmin %lu",
           (unsigned long) addr, (unsigned long) dbase,
           (unsigned long) dmin);
    }

	if ((flags & myflags) == myflags) {
	    fs->read_block(fs,fs_buf, fs->block_size, addr, "data block");
	    if (WALK_STOP == action(fs, addr, fs_buf->data, myflags, ptr)) {
			fs_buf_free(fs_buf);
			return;
		}
	}
    }

    /*
     * Cleanup.
     */
    fs_buf_free(fs_buf);
}



/**************************************************************************
 * 
 * FILE WALKING
 *
 **************************************************************************/

static int 
ext2fs_file_walk_direct(FS_INFO *fs, FS_BUF *buf[],
  size_t length, DADDR_T addr, int flags, FS_FILE_WALK_FN action, char *ptr)
{
	int     read_count;
	int 	myflags;

	read_count = (length < buf[0]->size ? length : buf[0]->size);

	if (addr > fs->last_block) {
		if (flags & FS_FLAG_FILE_NOABORT)  {
			if (verbose) {
				fprintf (logfp, 
				  "Invalid direct block address (too large): %lu",
		  		  (ULONG) addr);
			}
			return 0;
		}
		else {
			error ("Invalid direct block address (too large): %lu",
		  	  (ULONG) addr);
		}
	}

	// @@@ We do not check allocation status here
	myflags = FS_FLAG_DATA_CONT;

	if (addr == 0) {
		if (0 == (flags & FS_FLAG_FILE_NOSPARSE)) {

			if ((flags & FS_FLAG_FILE_AONLY) == 0) 
				memset(buf[0]->data, 0, read_count);

			if (WALK_STOP == action(fs, addr, buf[0]->data, read_count, 
			  myflags, ptr)) 
				return 0;
		}
	} else {
		if ((flags & FS_FLAG_FILE_AONLY) == 0) {
			fs->read_block(fs, buf[0], 
			  roundup(read_count, EXT2FS_DEV_BSIZE), addr,
				  "data block");
		}

		if (WALK_STOP == action(fs, addr, buf[0]->data, read_count, 
		  myflags, ptr))
			return 0;
	}

	return (read_count);
} 


/* ext2fs_file_walk_indir - copy indirect block */
static int 
ext2fs_file_walk_indir(FS_INFO *fs, FS_BUF *buf[], size_t length,
  DADDR_T addr, int level, int flags, FS_FILE_WALK_FN action, char *ptr)
{    
    char   *myname = "extXfs_file_walk_indir";
    size_t   todo_count = length;
    DADDR_T *iaddr;
    int     n;
    
    if (verbose)
    	fprintf(logfp, "%s: level %d block %lu\n", myname, level, (ULONG) addr);
    
    if (addr > fs->last_block) {
        if (flags & FS_FLAG_FILE_NOABORT)  {
			if (verbose) {
				fprintf (logfp, 
        		  "Invalid indirect block address (too large): %lu",
				  (ULONG)addr);
			}
            return 0;    
		}
		else {
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
    	fs->read_block(fs,buf[level], buf[level]->size, addr,
              "disk address block");

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
			if (flags & FS_FLAG_FILE_NOABORT)  {
				if (verbose) {
					fprintf (logfp, 
					  "Invalid address in indirect list (too large): %lu",
     	     		  (ULONG)getu32(fs, (u_int8_t *)&iaddr[n]) );
				}
				return 0;    
			}
			else {
				error ("Invalid address in indirect list (too large): %lu",
          		  (ULONG)getu32(fs, (u_int8_t *)&iaddr[n]) );
			}
		}


		if (level == 1)
			todo_count -= ext2fs_file_walk_direct(fs, buf, todo_count, 
			  getu32(fs, (u_int8_t *)&iaddr[n]), flags, action, ptr); 
    	else
        	todo_count -= ext2fs_file_walk_indir(fs, buf, todo_count, 
			  getu32(fs, (u_int8_t *)&iaddr[n]), level - 1, flags, action, ptr);
	
		/* nothing was updated, so we should go now */
		if (prevcnt == todo_count)
			return 0;
	}

    return (length - todo_count);
}


/*      
 * flag values: FS_FLAG_FILE_NOSPARSE, FS_FLAG_FILE_AONLY, FS_FLAG_FILE_SLACK
 * FS_FLAG_FILE_META, FS_FLAG_FILE_NOABORT
 *
 * nothing special is done for FS_FLAG_FILE_RECOVER
 *
 * The action will use the flags: FS_FLAG_DATA_CONT, FS_FLAG_DATA_META
 * -- @@@ Currently do not do _ALLOC and _UNALLOC
 *  
 * The type and id fields are ignored with EXT2FS
 */
void
ext2fs_file_walk(FS_INFO *fs, FS_INODE *inode, u_int32_t type, u_int16_t id,
    int flags, FS_FILE_WALK_FN action, char *ptr)
{
    size_t   length;
    FS_BUF **buf;
    int     level, retval, n;

    /*
     * Initialize a buffer for each level of indirection that is supported by
     * this inode. The level 0 buffer is sized to the logical block size used
     * for files. The level 1.. buffers are sized to the block size used for
     * indirect blocks.
     */
    buf = (FS_BUF **) mymalloc(sizeof(*buf) * (inode->indir_count + 1));
    buf[0] = fs_buf_alloc(fs->block_size);

    length = inode->size;

	/* Roundup if we want the slack space on the final fragment */
	if (flags & FS_FLAG_FILE_SLACK)
		length = roundup(length, fs->block_size);

    /*
     * Read the file blocks. First the direct blocks, then the indirect ones.
     */

	for (n = 0; length > 0 && n < inode->direct_count; n++) {
		retval = ext2fs_file_walk_direct(fs, buf, length, 
		  inode->direct_addr[n],  flags, action, ptr);

		if (retval)
			length -= retval;
		else {
			length = 0;
			break;
		}
	}

	if (length > 0) {
		for (level = 1; level <= inode->indir_count; level++)
			buf[level] = fs_buf_alloc(fs->block_size);

		for (level = 1; length > 0 && level <= inode->indir_count; level++) {
			retval = ext2fs_file_walk_indir(fs, buf, length, 
			  inode->indir_addr[level - 1], level, flags, action, ptr);
			if (retval)
				length -= retval;
			else 
				break;
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
ext2fs_fscheck(FS_INFO *fs, FILE *hFile)
{
	error ("fscheck not implemented yet for EXT3FS");
}

static void
ext2fs_fsstat(FS_INFO *fs, FILE *hFile)
{
	int i;
	EXT2FS_INFO *ext2fs = (EXT2FS_INFO *)fs;
	ext2fs_sb *sb = ext2fs->fs;
	int ibpg;
	time_t tmptime;


	fprintf(hFile, "FILE SYSTEM INFORMATION\n");
	fprintf(hFile, "--------------------------------------------\n");

	fprintf(hFile, "File System Type: %s\n",
		(fs->ftype == EXT3FS)? "EXT3FS" : "EXT2FS");
	fprintf(hFile, "Volume Name: %s\n", sb->s_volume_name);
	fprintf(hFile, "Volume ID: %"PRIx64"%"PRIx64"\n",
	  getu64(fs, &sb->s_uuid[8]), 
	  getu64(fs, &sb->s_uuid[0]));

	tmptime = getu32(fs, sb->s_wtime);
	fprintf(hFile, "\nLast Writen at: %s", asctime(localtime(&tmptime))); 
	tmptime = getu32(fs, sb->s_lastcheck);
	fprintf(hFile, "Last Checked at: %s", asctime(localtime(&tmptime))); 

	tmptime = getu32(fs, sb->s_mtime);
	fprintf(hFile, "\nLast Mounted at: %s", asctime(localtime(&tmptime))); 

	/* State of the file system */
	if (getu16(fs, sb->s_state) & EXT2FS_STATE_VALID)
		fprintf(hFile, "Unmounted properly\n");
	else
		fprintf(hFile, "Unmounted Improperly\n");

	if (sb->s_last_mounted != '\0')
		fprintf(hFile, "Last mounted on: %s\n", sb->s_last_mounted);

	fprintf(hFile, "\nSource OS: ");
	switch (getu32(fs, sb->s_creator_os)) {
	  case EXT2FS_OS_LINUX:
		fprintf(hFile, "Linux\n");
		break;
	  case EXT2FS_OS_HURD:
		fprintf(hFile, "HURD\n");
		break;
	  case EXT2FS_OS_MASIX:
		fprintf(hFile, "MASIX\n");
		break;
	  case EXT2FS_OS_FREEBSD:
		fprintf(hFile, "FreeBSD\n");
		break;
	  case EXT2FS_OS_LITES:
		fprintf(hFile, "LITES\n");
		break;
	  default:
		fprintf(hFile, "%x\n", getu32(fs, sb->s_creator_os));
		break;
	}

	if (getu32(fs, sb->s_rev_level) == EXT2FS_REV_ORIG) 
		fprintf(hFile, "Static Structure\n");
	else
		fprintf(hFile, "Dynamic Structure\n");


	/* add features */
	if (getu32(fs, sb->s_feature_compat)) {
		fprintf(hFile, "Compat Features: ");

		if (getu32(fs, sb->s_feature_compat) & 
		  EXT2FS_FEATURE_COMPAT_DIR_PREALLOC)
			fprintf(hFile, "Dir Prealloc, ");
		if (getu32(fs, sb->s_feature_compat) & 
		  EXT2FS_FEATURE_COMPAT_IMAGIC_INODES)
			fprintf(hFile, "iMagic inodes, ");
		if (getu32(fs, sb->s_feature_compat) & 
		  EXT2FS_FEATURE_COMPAT_HAS_JOURNAL)
			fprintf(hFile, "Journal, ");
		if (getu32(fs, sb->s_feature_compat) & 
		  EXT2FS_FEATURE_COMPAT_EXT_ATTR)
			fprintf(hFile, "Ext Attributes, ");
		if (getu32(fs, sb->s_feature_compat) & 
		  EXT2FS_FEATURE_COMPAT_RESIZE_INO)
			fprintf(hFile, "Resize Inode, ");
		if (getu32(fs, sb->s_feature_compat) & 
		  EXT2FS_FEATURE_COMPAT_DIR_INDEX)
			fprintf(hFile, "Dir Index");

		fprintf(hFile, "\n");
	}

	if (getu32(fs, sb->s_feature_incompat)) {
		fprintf(hFile, "InCompat Features: ");

		if (getu32(fs, sb->s_feature_incompat) & 
		  EXT2FS_FEATURE_INCOMPAT_COMPRESSION)
			fprintf(hFile, "Compression, ");
		if (getu32(fs, sb->s_feature_incompat) & 
		  EXT2FS_FEATURE_INCOMPAT_FILETYPE)
			fprintf(hFile, "Filetype, ");
		if (getu32(fs, sb->s_feature_incompat) & 
		  EXT2FS_FEATURE_INCOMPAT_RECOVER)
			fprintf(hFile, "Recover, ");
		if (getu32(fs, sb->s_feature_incompat) & 
		  EXT2FS_FEATURE_INCOMPAT_JOURNAL_DEV)
			fprintf(hFile, "Journal Dev");

		fprintf(hFile, "\n");
	}

	if (getu32(fs, sb->s_feature_ro_compat)) {
		fprintf(hFile, "Read Only Compat Features: ");

		if (getu32(fs, sb->s_feature_ro_compat) & 
		  EXT2FS_FEATURE_RO_COMPAT_SPARSE_SUPER)
			fprintf(hFile, "Sparse Super, ");
		if (getu32(fs, sb->s_feature_ro_compat) & 
		  EXT2FS_FEATURE_RO_COMPAT_LARGE_FILE)
			fprintf(hFile, "Has Large Files, ");
		if (getu32(fs, sb->s_feature_ro_compat) & 
		  EXT2FS_FEATURE_RO_COMPAT_BTREE_DIR)
			fprintf(hFile, "Btree Dir");

		fprintf(hFile, "\n");

	}

	/* Print journal information */
	if (getu32(fs, sb->s_feature_compat) & 
	  EXT2FS_FEATURE_COMPAT_HAS_JOURNAL) {

		fprintf(hFile, "\nJournal ID: %"PRIx64"%"PRIx64"\n",
		  getu64(fs, &sb->s_journal_uuid[8]), 
		  getu64(fs, &sb->s_journal_uuid[0]));

		if (getu32(fs, sb->s_journal_inum) != 0)
			fprintf(hFile, "Journal Inode: %"PRIu32"\n",
			  getu32(fs, sb->s_journal_inum));

		if (getu32(fs, sb->s_journal_dev) != 0)
			fprintf(hFile, "Journal Device: %"PRIu32"\n",
			  getu32(fs, sb->s_journal_dev));


	}

	fprintf(hFile, "\nMETADATA INFORMATION\n");
	fprintf(hFile, "--------------------------------------------\n");

	fprintf(hFile, "Inode Range: %lu - %lu\n",
	  (ULONG)fs->first_inum, (ULONG)fs->last_inum);
	fprintf(hFile, "Root Directory: %lu\n", (ULONG)fs->root_inum);

	fprintf(hFile, "Free Inodes: %"PRIu32"\n",
	  getu32(fs, sb->s_free_inode_count));


	/* @@@ NEED TO TEST THIS */
#if 0
	if (getu32(fs, sb->s_last_orphan)) {
		u_int32_t	or_in;
		fprintf(hFile, "Orphan Inodes: ");
		or_in = getu32(fs, sb->s_last_orphan);
		while (or_in) {
			FS_INODE *fsi;

			if ((or_in > fs->last_inum) || (or_in < fs->first_inum))
				break;

			fprintf(hFile, "%"PRIu32", ", or_in);

			/* Get the next one */
			fsi = ext2fs_inode_lookup(fs, or_in);
			if (!fsi)
				break;

			or_in = fsi->dtime;
		}
	}
#endif

	fprintf(hFile, "\nCONTENT INFORMATION\n");
	fprintf(hFile, "--------------------------------------------\n");

	fprintf(hFile, "Block Range: %lu - %lu\n",
	  (ULONG)fs->first_block, (ULONG)fs->last_block);

	fprintf(hFile, "Block Size: %lu\n", (ULONG)fs->block_size);

	if (getu32(fs, sb->s_first_data_block)) 
		fprintf(hFile, "Reserved Area Before Block Groups: %"PRIu32"\n",
		  getu32(fs, sb->s_first_data_block));

	fprintf(hFile, "Free Blocks: %"PRIu32"\n",
	  getu32(fs, sb->s_free_blocks_count));

	fprintf(hFile, "\nBLOCK GROUP INFORMATION\n");
	fprintf(hFile, "--------------------------------------------\n");

	fprintf(hFile, "Number of Block Groups: %d\n", ext2fs->groups_count);

	fprintf(hFile, "Inodes per group: %d\n", 
	  getu32(fs, sb->s_inodes_per_group));
	fprintf(hFile, "Blocks per group: %d\n", 
	  getu32(fs, sb->s_blocks_per_group));


	/* number of blocks the inodes consume */
	ibpg = (getu32(fs, sb->s_inodes_per_group) * ext2fs->inode_size +
	  fs->block_size - 1) /  fs->block_size;

	for (i = 0; i < ext2fs->groups_count; i++) {
		GRPNUM_T cg_base;
		INUM_T inum;

		ext2fs_group_lookup(ext2fs, i);
		fprintf(hFile, "\nGroup: %d:\n", i);

		inum = fs->first_inum + gets32(fs, sb->s_inodes_per_group) * i;
		fprintf(hFile, "  Inode Range: %lu - ", (ULONG)inum);

		if ((inum + gets32(fs, sb->s_inodes_per_group) - 1) < fs->last_inum) 
			fprintf(hFile, "%lu\n", 
			  inum + gets32(fs, sb->s_inodes_per_group) - 1);
		else
			fprintf(hFile, "%lu\n", fs->last_inum);

   
		cg_base = ext2_cgbase_lcl(fs, sb, i);

		fprintf(hFile, "  Block Range: %lu - %lu\n",
		  (ULONG)cg_base,
		  (((ULONG)ext2_cgbase_lcl(fs, sb, i + 1) - 1) < fs->last_block) ?
		  ((ULONG)ext2_cgbase_lcl(fs, sb, i + 1) - 1) : fs->last_block);


		fprintf(hFile, "  Layout:\n");

		/* only print the super block data if we are not in a sparse
		 * group 
		 */
		if ((getu32(fs, ext2fs->fs->s_feature_ro_compat) & 
	  	  EXT2FS_FEATURE_RO_COMPAT_SPARSE_SUPER) && 
		  (cg_base != getu32(fs, ext2fs->group->bg_block_bitmap)) ) {
			OFF_T boff;

			/* the super block is the first 1024 bytes */
			fprintf(hFile, "    Super Block: %lu - %lu\n",
			  (ULONG)cg_base,
			  (ULONG)cg_base +
			  ((sizeof (ext2fs_sb) + fs->block_size - 1) / fs->block_size) - 1);

			boff = roundup(sizeof(ext2fs_sb), fs->block_size);

			/* Group Descriptors */
			fprintf(hFile, "    Group Descriptor Table: %lu - ",
			  (ULONG)(cg_base + (boff + fs->block_size - 1) / fs->block_size) );

			boff += (ext2fs->groups_count * sizeof (ext2fs_gd));
			fprintf(hFile, "%lu\n",
			  (ULONG)((cg_base + (boff + fs->block_size - 1) / fs->block_size)
			  - 1));
		}


		/* The block bitmap is a full block */
		fprintf(hFile, "    Data bitmap: %lu - %lu\n", 
		  (ULONG)getu32(fs, ext2fs->group->bg_block_bitmap),
		  (ULONG)getu32(fs, ext2fs->group->bg_block_bitmap));


		/* The inode bitmap is a full block */
		fprintf(hFile, "    Inode bitmap: %lu - %lu\n", 
		  (ULONG)getu32(fs, ext2fs->group->bg_inode_bitmap),
		  (ULONG)getu32(fs, ext2fs->group->bg_inode_bitmap));


		fprintf(hFile, "    Inode Table: %lu - %lu\n", 
		  (ULONG)getu32(fs, ext2fs->group->bg_inode_table),
		  (ULONG)getu32(fs, ext2fs->group->bg_inode_table) + ibpg - 1);


		fprintf(hFile, "    Data Blocks: ");

		/* If we are in a sparse group, display the other addresses */
		if ((getu32(fs, ext2fs->fs->s_feature_ro_compat) & 
	  	  EXT2FS_FEATURE_RO_COMPAT_SPARSE_SUPER) && 
		  (cg_base == getu32(fs, ext2fs->group->bg_block_bitmap)) ) {

			/* it goes from the end of the inode bitmap to before the
			 * table
			 *
			 * This hard coded aspect does not scale ...
			 */
			fprintf(hFile, "%lu - %lu, ",
		  	  (ULONG)getu32(fs, ext2fs->group->bg_inode_bitmap) + 1,
		  	  (ULONG)getu32(fs, ext2fs->group->bg_inode_table) - 1);
		}

		fprintf(hFile, "%lu - %lu\n", 
		  (ULONG)getu32(fs, ext2fs->group->bg_inode_table) + ibpg,
		  (((ULONG)ext2_cgbase_lcl(fs, sb, i + 1) - 1) < fs->last_block) ?
		  ((ULONG)ext2_cgbase_lcl(fs, sb, i + 1) - 1) : fs->last_block);


		/* Print the free info */
		fprintf(hFile, "  Free Inodes: %"PRIu16" (%d%%)\n",
		  getu16(fs, ext2fs->group->bg_free_inodes_count),
		  (100 * getu16(fs, ext2fs->group->bg_free_inodes_count)) / 
		  getu32(fs, sb->s_inodes_per_group));

		fprintf(hFile, "  Free Blocks: %"PRIu16" (%d%%)\n",
		  getu16(fs, ext2fs->group->bg_free_blocks_count),
		  (100 * getu16(fs, ext2fs->group->bg_free_blocks_count)) / 
		  getu32(fs, sb->s_blocks_per_group));

		fprintf(hFile, "  Total Directories: %"PRIu16"\n",
		  getu16(fs, ext2fs->group->bg_used_dirs_count));
	}

	return;
}


/************************* istat *******************************/
 
static void
ext2fs_make_acl_str (char *str, int len, u_int16_t perm)
{
	int i = 0;

	if (perm & EXT2_PACL_PERM_READ) {
		snprintf(&str[i], len - 1, "Read");
		i += 4;
	}
	if (perm & EXT2_PACL_PERM_WRITE) {
		if (i) {
			snprintf(&str[i], len - 1, ", ");
			i += 2;
		}
		snprintf(&str[i], len - 1, "Write");
		i += 5;
	}
	if (perm & EXT2_PACL_PERM_EXEC) {
		if (i) {
			snprintf(&str[i], len - 1, ", ");
			i += 2;
		}
		snprintf(&str[i], len - 1, "Execute");
		i += 7;
	}

}



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
        /* cycle through the blocks if they exist */
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
ext2fs_istat (FS_INFO *fs, FILE *hFile, INUM_T inum, int numblock,
  int32_t sec_skew)
{
	EXT2FS_INFO *ext2fs = (EXT2FS_INFO *) fs;
	FS_INODE *fs_inode;
	char ls[12];

	fs_inode = ext2fs_inode_lookup (fs, inum);
	fprintf(hFile, "inode: %lu\n", (ULONG) inum);
	fprintf(hFile, "%sAllocated\n",
	  (fs_inode->flags & FS_FLAG_META_ALLOC)?"":"Not ");

	fprintf(hFile, "Group: %lu\n", (ULONG)ext2fs->grpnum);

	if (fs_inode->link)
		fprintf(hFile, "symbolic link to: %s\n", fs_inode->link);

	fprintf(hFile, "uid / gid: %d / %d\n",
	  (int)fs_inode->uid, (int)fs_inode->gid);

	make_ls(fs_inode->mode, ls, 12);
	fprintf(hFile, "mode: %s\n", ls);

	if (getu32(fs, ext2fs->dinode->i_flags)) {
		fprintf(hFile, "Flags: ");
		if (getu32(fs, ext2fs->dinode->i_flags) & EXT2_IN_SECDEL)
			fprintf(hFile, "Secure Delete, ");

		if (getu32(fs, ext2fs->dinode->i_flags) & EXT2_IN_UNRM)
			fprintf(hFile, "Undelete, ");

		if (getu32(fs, ext2fs->dinode->i_flags) & EXT2_IN_COMP)
			fprintf(hFile, "Compressed, ");

		if (getu32(fs, ext2fs->dinode->i_flags) & EXT2_IN_SYNC)
			fprintf(hFile, "Sync Updates, ");

		if (getu32(fs, ext2fs->dinode->i_flags) & EXT2_IN_IMM)
			fprintf(hFile, "Immutable, ");

		if (getu32(fs, ext2fs->dinode->i_flags) & EXT2_IN_APPEND)
			fprintf(hFile, "Append Only, ");

		if (getu32(fs, ext2fs->dinode->i_flags) & EXT2_IN_NODUMP)
			fprintf(hFile, "Do Not Dump, ");

		if (getu32(fs, ext2fs->dinode->i_flags) & EXT2_IN_NOA)
			fprintf(hFile, "No A-Time, ");
		
		fprintf(hFile, "\n");
	}

	fprintf(hFile, "size: %llu\n", (ULLONG) fs_inode->size);
	fprintf(hFile, "num of links: %lu\n", (ULONG) fs_inode->nlink);

	/* Ext attribute are stored in a block with a header and a list
	 * of entries that are aligned to 4-byte boundaries.  The attr
	 * value is stored at the end of the block.  There are 4 null bytes
	 * in between the headers and values 
	 */
	if (getu32(fs, ext2fs->dinode->i_file_acl) != 0) {
		FS_BUF *fs_buf = fs_buf_alloc(fs->block_size);
		ext2fs_ea_header *ea_head;
		ext2fs_ea_entry *ea_entry;

		fprintf(hFile, "\nExtended Attributes  (Block: %"PRIu32")\n",
		  getu32(fs, ext2fs->dinode->i_file_acl));

		/* Is the value too big? */
		if (getu32(fs, ext2fs->dinode->i_file_acl) > fs->last_block) {
			fprintf(hFile, "Extended Attributes block is larger than file system\n");
			goto egress_ea;
		}

		fs_read_block(fs, fs_buf, fs->block_size, 
		  getu32(fs, ext2fs->dinode->i_file_acl),
		  "extended attribute block");



		/* Check the header */
		ea_head = (ext2fs_ea_header *)fs_buf->data;
		if (getu32(fs, ea_head->magic) != EXT2_EA_MAGIC) {
			fprintf(hFile, "Incorrect extended attribute header: %x\n", 
			  getu32(fs, ea_head->magic));
		}


		/* Cycle through each entry - at the top of the block */
		for (ea_entry = (ext2fs_ea_entry *)&ea_head->entry;

		  ((int)ea_entry < ((int)fs_buf->data + fs->block_size - sizeof(ext2fs_ea_entry))) ;

		  ea_entry = (ext2fs_ea_entry *) ((int)ea_entry + 
		    EXT2_EA_LEN(ea_entry->nlen))) {

			char name[256];

			/* Stop if the first four bytes are NULL */
			if ((ea_entry->nlen == 0) && (ea_entry->nidx == 0) &&
		  	  (getu16(fs, ea_entry->val_off) == 0))
				break;

			/* The Linux src does not allow this */
			if (getu32(fs, ea_entry->val_blk) != 0) {
				fprintf(hFile, "Attribute has non-zero value block - skipping\n");
				continue;
			}


			/* Is the value location and size valid? */
			if ((getu32(fs, ea_entry->val_off) > fs->block_size) || 
			  ((getu16(fs, ea_entry->val_off)  + getu32(fs, ea_entry->val_size)) > fs->block_size) ) {
				continue;
			}	


			/* Copy the name into a buffer - not NULL term */
			strncpy(name, &ea_entry->name, 
			  ea_entry->nlen);
			name[ea_entry->nlen] = '\0';


			/* User assigned attributes - setfattr / getfattr */
			if ((ea_entry->nidx == EXT2_EA_IDX_USER) ||
			  (ea_entry->nidx == EXT2_EA_IDX_TRUSTED) ||
			  (ea_entry->nidx == EXT2_EA_IDX_SECURITY) ) {
				char val[256];

				strncpy(val, &fs_buf->data[getu16(fs, ea_entry->val_off)], 
				  getu32(fs, ea_entry->val_size) > 256 ? 
				  256 : getu32(fs, ea_entry->val_size));

				val[getu32(fs, ea_entry->val_size) > 256 ? 
				  256 : getu32(fs, ea_entry->val_size)] = '\0';

				if (ea_entry->nidx == EXT2_EA_IDX_USER) 
					fprintf(hFile, "user.%s=%s\n",
						name, val);
				else if (ea_entry->nidx == EXT2_EA_IDX_TRUSTED) 
					fprintf(hFile, "trust.%s=%s\n",
						name, val);
				else if (ea_entry->nidx == EXT2_EA_IDX_SECURITY) 
					fprintf(hFile, "security.%s=%s\n",
						name, val);

			}


			/* POSIX ACL - setfacl / getfacl stuff */
			else if ((ea_entry->nidx == EXT2_EA_IDX_POSIX_ACL_ACCESS)  ||
			  (ea_entry->nidx == EXT2_EA_IDX_POSIX_ACL_DEFAULT)) {

				ext2fs_pos_acl_entry_lo  *acl_lo;
				ext2fs_pos_acl_head  *acl_head;

				if (ea_entry->nidx == EXT2_EA_IDX_POSIX_ACL_ACCESS) 
					fprintf(hFile, "POSIX Access Control List Entries:\n");
				else if (ea_entry->nidx == EXT2_EA_IDX_POSIX_ACL_DEFAULT)
					fprintf(hFile, "POSIX Default Access Control List Entries:\n");

				/* examine the header */
				acl_head = (ext2fs_pos_acl_head *)&fs_buf->data[getu16(fs, ea_entry->val_off)];

				if (getu32(fs, acl_head->ver) != 1) {
					fprintf(hFile, "Invalid ACL Header Version: %d\n", getu32(fs, acl_head->ver));
					continue;
				}

				/* The first entry starts after the header */
				acl_lo = (ext2fs_pos_acl_entry_lo *)((int)acl_head + sizeof(ext2fs_pos_acl_head));


				/* Cycle through the values */
				while ((int)acl_lo < ((int)fs_buf->data + getu16(fs, ea_entry->val_off) + getu32(fs, ea_entry->val_size))) {

					char perm[64];
					int len;

					/* Make a string from the permissions */
					ext2fs_make_acl_str (perm, 64, getu16(fs, acl_lo->perm));

					switch (getu16(fs, acl_lo->tag)) {
						case EXT2_PACL_TAG_USERO:

							fprintf(hFile, "  uid: %d: %s\n", fs_inode->uid, perm);
							len = sizeof(ext2fs_pos_acl_entry_sh);
							break;

						case EXT2_PACL_TAG_GRPO:
							fprintf(hFile, "  gid: %d: %s\n", fs_inode->gid, perm);
							len = sizeof(ext2fs_pos_acl_entry_sh);
							break;
						case EXT2_PACL_TAG_OTHER:
							fprintf(hFile, "  other: %s\n", perm);
							len = sizeof(ext2fs_pos_acl_entry_sh);
							break;
						case EXT2_PACL_TAG_MASK:
							fprintf(hFile, "  mask: %s\n", perm);
							len = sizeof(ext2fs_pos_acl_entry_sh);
							break;


						case EXT2_PACL_TAG_GRP:
							fprintf(hFile, "  gid: %d: %s\n", getu32(fs, acl_lo->id), perm);
							len = sizeof(ext2fs_pos_acl_entry_lo);
							break;

						case EXT2_PACL_TAG_USER:
							fprintf(hFile, "  uid: %d: %s\n", getu32(fs, acl_lo->id), perm);

							len = sizeof(ext2fs_pos_acl_entry_lo);
							break;

						default:
							fprintf(hFile, "Unknown ACL tag: %d\n", getu16(fs, acl_lo->tag));
							len = sizeof(ext2fs_pos_acl_entry_sh);
							break;
					}
					acl_lo = (ext2fs_pos_acl_entry_lo *)((int)acl_lo + len);
				}
			}
			else {
				fprintf(hFile, "Unsupported Extended Attr Type: %d\n", ea_entry->nidx);
			}
		}
egress_ea:

		fs_buf_free(fs_buf);
	}

	if (sec_skew != 0) {
		fprintf(hFile, "\nAdjusted Inode Times:\n");                  
		fs_inode->mtime -= sec_skew;
		fs_inode->atime -= sec_skew;
		fs_inode->ctime -= sec_skew;
   
		fprintf(hFile, "Accessed:\t%s", ctime(&fs_inode->atime));
		fprintf(hFile, "File Modified:\t%s", ctime(&fs_inode->mtime));
		fprintf(hFile, "Inode Modified:\t%s", ctime(&fs_inode->ctime));

		if (fs_inode->dtime) {
			fs_inode->dtime -= sec_skew;
			fprintf(hFile, "Deleted:\t%s", ctime(&fs_inode->dtime));
			fs_inode->dtime += sec_skew;
		}

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

	if (fs_inode->dtime) 
		fprintf(hFile, "Deleted:\t%s", ctime(&fs_inode->dtime));
		
	if (numblock > 0)
		fs_inode->size = numblock * fs->block_size;

	fprintf (hFile, "\nDirect Blocks:\n");

	indir_idx = 0;
	fs->file_walk(fs, fs_inode, 0, 0, 
	  (FS_FLAG_FILE_AONLY | FS_FLAG_FILE_META | FS_FLAG_FILE_NOID),
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


/* ext2fs_close - close an ext2fs file system */

static void 
ext2fs_close(FS_INFO *fs)
{
	EXT2FS_INFO *ext2fs = (EXT2FS_INFO *) fs;

	fs->io->close(fs->io);
	free((char *)ext2fs->fs);
	free((char *)ext2fs->dinode);
	free((char *)ext2fs->group);
	free((char *)ext2fs->block_map);
	free((char *)ext2fs->inode_map);
	free(ext2fs);
}

/* ext2fs_open - open an ext2fs file system */

FS_INFO *
ext2fs_open(IO_INFO *io, unsigned char ftype)
{
	//char   *myname = "extXfs_open";
	EXT2FS_INFO *ext2fs = (EXT2FS_INFO *) mymalloc(sizeof(*ext2fs));
	int     len;
	FS_INFO *fs = &(ext2fs->fs_info);

    /* Initialize the FS_INFO object */
    fs->io=io;
	
	if ((ftype & FSMASK) != EXTxFS_TYPE) 
		error ("Invalid FS Type in ext2fs_open");

	/*
	* Open the block device; linux has no raw character disk device.
	*/
//	if ((fs->fd = open(name, O_RDONLY)) < 0)
//		error("%s: open %s: %m", myname, name);

	fs->ftype = ftype;
	fs->flags = 0;
	fs->flags |= FS_HAVE_DTIME;

	/*
	 * Read the superblock.
	 */
	len = sizeof(ext2fs_sb);
	ext2fs->fs = (ext2fs_sb *)mymalloc (len);

    /*  Commented out in favour of generic io_subsystem calls
	if (LSEEK(fs->fd, EXT2FS_SBOFF, SEEK_SET) != EXT2FS_SBOFF)
		error("%s: lseek: %m", myname);
	if (read(fs->fd, ext2fs->fs, len) != len)
		error("%s: read superblock: %m", name);
    */
    fs->io->read_random(fs->io,(char *)ext2fs->fs,len,EXT2FS_SBOFF,"Checking for EXT2FS");

	/* 
	 * Verify we are looking at an EXTxFS image
	 */
	if (guessu16(fs, ext2fs->fs->s_magic, EXT2FS_FS_MAGIC)) {
		return(NULL);
		//error("Error: %s is not an EXTxFS file system", name);
	}

	if (verbose) {
    		if (getu32(fs, ext2fs->fs->s_feature_ro_compat) & 
	  	  EXT2FS_FEATURE_RO_COMPAT_SPARSE_SUPER)
			fprintf(logfp, "File system has sparse super blocks\n");

		fprintf(logfp, "First data block is %d\n", 
	  	  (int) getu32(fs, ext2fs->fs->s_first_data_block));
	}

	/* If autodetect was given, look for the journal */
	if (ftype == EXTAUTO) {
		if (getu32(fs, ext2fs->fs->s_feature_compat) & 
		  EXT2FS_FEATURE_COMPAT_HAS_JOURNAL)
			fs->ftype = EXT3FS;
		else 
			fs->ftype = EXT2FS;
	}	


	/* we need to figure out if dentries are v1 or v2 */
	if (getu32(fs, ext2fs->fs->s_feature_incompat) & 
	  EXT2FS_FEATURE_INCOMPAT_FILETYPE) 
		ext2fs->deentry_type = EXT2_DE_V2;
	else
		ext2fs->deentry_type = EXT2_DE_V1;


	/*
	* Translate some filesystem-specific information to generic form.
	*/
	fs->inum_count = getu32(fs, ext2fs->fs->s_inodes_count);
	fs->last_inum = fs->inum_count;
	fs->first_inum = EXT2FS_FIRSTINO;
	fs->root_inum = EXT2FS_ROOTINO;


	/* Set the size of the inode, but default to our data structure
	 * size if it is larger */
	ext2fs->inode_size = getu16(fs, ext2fs->fs->s_inode_size);
	if (ext2fs->inode_size < sizeof (ext2fs_inode))  {
		ext2fs->inode_size = sizeof (ext2fs_inode); 
		if (verbose)
			fprintf(logfp, "SB inode size is too small, using default");
	}


	fs->block_count = getu32(fs, ext2fs->fs->s_blocks_count);
	fs->first_block = 0;
	fs->last_block = fs->block_count - 1;


	if (getu32(fs, ext2fs->fs->s_log_block_size) != 
	  getu32(fs, ext2fs->fs->s_log_frag_size)) {
		error("This file system has fragments that are a different size than blocks, which is not currently supported\nContact brian with details of the system that created this image");
	}

	fs->block_size = 
		EXT2FS_MIN_BLOCK_SIZE << getu32(fs, ext2fs->fs->s_log_block_size);

	fs->dev_bsize = EXT2FS_DEV_BSIZE;

	/* The group descriptors are located in the block following the 
	 * super block
	 */

	ext2fs->group_offset = roundup ((EXT2FS_SBOFF + sizeof(ext2fs_sb)), fs->block_size);

	ext2fs->groups_count = ( getu32(fs, ext2fs->fs->s_blocks_count) - 
	  getu32(fs, ext2fs->fs->s_first_data_block) + 
	  getu32(fs, ext2fs->fs->s_blocks_per_group) - 1) /
	  getu32(fs, ext2fs->fs->s_blocks_per_group);

	fs->seek_pos = -1;

	/* callbacks */
	fs->inode_walk = ext2fs_inode_walk;
    fs->read_block = fs_read_block;
	fs->block_walk = ext2fs_block_walk;
	fs->inode_lookup = ext2fs_inode_lookup;
	fs->dent_walk = ext2fs_dent_walk;
	fs->file_walk = ext2fs_file_walk;
	fs->fsstat = ext2fs_fsstat;
	fs->fscheck = ext2fs_fscheck;
	fs->istat = ext2fs_istat;
	fs->close = ext2fs_close;

	/* allocate buffers */

	/* inode map */
	ext2fs->inode_map = (unsigned char *) mymalloc(fs->block_size);
	ext2fs->imap_num = -1;

	/* block map */
	ext2fs->block_map = (unsigned char *) mymalloc(fs->block_size);
	ext2fs->bmap_num = -1;

	/* dinode */
	ext2fs->dinode = (ext2fs_inode *) mymalloc(ext2fs->inode_size);
	ext2fs->inum = -1;

	/* group descriptor */
	ext2fs->group = (ext2fs_gd *) mymalloc(sizeof(ext2fs_gd));
	ext2fs->grpnum = -1;


	/*
	* Print some stats.
	*/
	if (verbose)
		fprintf(logfp,
		"inodes %lu root ino %lu blocks %lu blocks/group %lu\n",
		(ULONG) getu32(fs, ext2fs->fs->s_inodes_count),
		(ULONG) fs->root_inum,
		(ULONG) getu32(fs, ext2fs->fs->s_blocks_count),
		(ULONG) getu32(fs, ext2fs->fs->s_blocks_per_group));

	return (fs);
}

