/*
** The Sleuth Kit 
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
** 
** Copyright (c) 1997,1998,1999, International Business Machines          
** Corporation and others. All Rights Reserved.
*/

/* TCT */
/*++
 * NAME
 *	fs_open 3
 * SUMMARY
 *	open a file system
 * SYNOPSIS
 *	#include "fstools.h"
 *
 *	FS_INFO *fs_open(const char *path, const char *type)
 *
 *	void	inode_walk(fs, start, last, flags, action, ptr)
 *	FS_INFO	*fs;
 *	INUM_T	start;
 *	INUM_T	last;
 *	int	flags;
 *	void	(*action)(INUM_T inum, FS_INODE *inode, int flags, char *ptr);
 *
 *	void	block_walk(fs, start, last, flags, action, ptr)
 *	FS_INFO	*fs;
 *	DADDR_T	start;
 *	DADDR_T	last;
 *	int	flags;
 *	void	(*action)(DADDR_T addr, char *data, int flags, char *ptr);
 *
 *	struct dinode *inode_lookup(fs, inum)
 *	FS_INFO	*fs;
 *	INUM_T	inum;
 *
 *	void	close(fs)
 *	FS_INFO	*fs;
 * DESCRIPTION
 *	fs_open() opens the named file and expects a file system of
 *	the specified type. The result is an object with the following
 *	methods:
 *
 *	fs->inode_walk() iterates over the inode list and executes the
 *	specified action for all inodes that match the restriction
 *	expressed via \fBflags\fR.
 *
 *	fs->block_walk() iterates over the block list and executes the
 *	specified action for all blocks that match the restriction
 *	expressed via \fBflags\fR.
 *
 *	fs->inode_lookup() looks up the information stored in the specified
 *	inode. The caller must destroy the result by calling fs_inode_free().
 *
 *	fs->close() closes the specified file system and destroys the handle.
 *
 *	Arguments:
 * .IP path
 *	Special device. With FFS, specify a raw disk device. With ext2fs,
 *	specify a block device instead. However, nothing prevents the
 *	user from specifying a file with a disk image.
 * .IP type
 *	File system type. The following file systems are known, but 
 *	not all file systems are available on all systems:
 * .RS
 * .IP ffs
 *	BSD Fast File System and derivatives.
 * .IP ext2fs
 *	LINUX second extended file system.
 * .RE
 * .IP fs
 *	File system handle obtained with fs_open().
 * .IP start
 *	first inode (block) number for inode_walk() (block_walk()).
 * .IP last
 *	last inode (block) number for inode_walk() (block_walk()).
 * .IP flags
 *	Properties of inodes (blocks) of interest; properties of
 *	the inode that was found; miscellaneous flags for internal
 *	communication. Implemented as a bit-wise OR of:
 * .RS
 * .IP FS_FLAG_LINK
 *	Inode with link count > 0.
 * .IP FS_FLAG_UNLINK
 *	Inode with link count equal to 0.
 * .IP FS_FLAG_ALLOC
 *	Allocated inode or block.
 * .IP FS_FLAG_UNALLOC
 *	Unallocated inode or block.
 * .IP FS_FLAG_USED
 *	Inode that has been used at least once.
 * .IP FS_FLAG_UNUSED
 *	Virgin inode.
 * .IP FS_FLAG_ALIGN
 *	When unremoving blocks, maintain block alignment (FFS only).
 * .RE
 * .IP action
 *	Function that is executed for each inode (block) that
 *	satisfies the restriction. The arguments specify the
 *	inode (block) number, the inode (block) contents, the
 *	properties of the inode (block) found, and the application
 *	context pointer.
 * .IP inum
 *	inode number.
 * .IP ptr
 *	Application context that is passed on to the action routine.
 * SEE ALSO
 *	fs_copy_file(3), copy file by inode number
 *	fs_inode(3), inode memory management
 *	ffs(3), fast file system support
 *	ext2fs(3), LINUX second extended file system support
 * LICENSE
 *	This software is distributed under the IBM Public License.
 * AUTHOR(S)
 *	Wietse Venema
 *	IBM T.J. Watson Research
 *	P.O. Box 704
 *	Yorktown Heights, NY 10598, USA
 --*/

#include "fs_tools.h"
#include "error.h"

typedef struct {
    char	*name;
	char code;
	char	*comment;
} FS_TYPES;

extern FS_TYPES fs_open_table[];

/* fs_open - open a file system */

FS_INFO *fs_open(IO_INFO *io, const char *type)
{
	unsigned char ftype;
	/*
	  FS_INFO *temp=NULL;
	  int i;
	*/

	//Open the IO
	io->open(io);

	ftype = fs_parse_type (type);

	switch (ftype & FSMASK) {
		case FFS_TYPE:
			return ffs_open( io,ftype);
		case EXTxFS_TYPE:
			return ext2fs_open(io,ftype);
		case FATFS_TYPE:
			return fatfs_open(io,ftype);
		case NTFS_TYPE:
			return ntfs_open(io,ftype);
//		case RAWFS_TYPE:
//			return rawfs_open(io, ftype);
//		case SWAPFS_TYPE:
//			return swapfs_open(io, ftype);
		case UNSUPP_FS:
		default:
			printf("unknown filesystem type: %s\n", type);
			printf("known types:\n");
			fs_print_types();
			exit(1);
	}
}

void 
print_version() 
{
	char *str = "The Sleuth Kit";
#ifdef VER
	printf("%s ver %s\n", str, VER);
#else
	printf("%s\n", str);
#endif
	return;
}

