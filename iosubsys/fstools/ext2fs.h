/*
** The Sleuth Kit 
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
** 
*/
#ifndef _EXT2FS_H
#define _EXT2FS_H

/*
** Constants
*/
#define EXT2FS_FIRSTINO    1	/* inode 1 contains the bad blocks */
#define EXT2FS_ROOTINO     2	/* location of root directory inode */
#define EXT2FS_NDADDR      12
#define EXT2FS_NIADDR      3
#define EXT2FS_SBOFF       1024
#define EXT2FS_FS_MAGIC    0xef53
#define EXT2FS_MAXNAMLEN   255
#define EXT2FS_MAXPATHLEN	4096
#define EXT2FS_MIN_BLOCK_SIZE	1024
#define EXT2FS_MAX_BLOCK_SIZE	4096



#define EXT2FS_DEV_BSIZE   512


/*
** Super Block
*/
typedef struct {
	u_int8_t	s_inodes_count[4];	/* u32 */
	u_int8_t	s_blocks_count[4];	/* u32 */
	u_int8_t	f1[12];
	u_int8_t	s_first_data_block[4];	/* u32 */
	u_int8_t	s_log_block_size[4];	/* u32 */
	u_int8_t	s_log_frag_size[4];		/* s32 */
	u_int8_t	s_blocks_per_group[4];	/* u32 */
	u_int8_t	s_frags_per_group[4];	/* u32 */
	u_int8_t	s_inodes_per_group[4];	/* u32 */
	u_int8_t	s_mtime[4];		/* u32 */	/* mount time */
	u_int8_t	s_wtime[4];		/* u32 */	/* write time */
	u_int8_t	s_mnt_count[2];	/* u16 */	/* mount count */
	u_int8_t	f4[2];
	u_int8_t	s_magic[2];	/* u16 */
	u_int8_t	s_state[2];	/* u16 */	/* fs state */
	u_int8_t	s_errors[2]; /* u16 */
	u_int8_t	s_minor_rev_level[2];	/* u16 */
	u_int8_t	s_lastcheck[4];	/* u32 */
	u_int8_t	s_checkinterval[4];	/* u32 */
	u_int8_t	s_creator_os[4];	/* u32 */
	u_int8_t	s_rev_level[4];	/* u32 */
	u_int8_t	f5[12];
	u_int8_t	s_feature_compat[4];	/* u32 */
	u_int8_t	s_feature_incompat[4];	/* u32 */
	u_int8_t	s_feature_ro_compat[4];	/* u32 */
	u_int8_t	s_uuid[16];		/* u8[16] */
	char		s_volume_name[16];
	char		s_last_mounted[64];
	u_int8_t	f6[824];
} ext2fs_sb;

/* File system State Values */
#define EXT2FS_STATE_VALID	0x0001		/* unmounted correctly */
#define EXT2FS_STATE_ERROR	0x0002		/* errors detected */

/* Operating System Codes */
#define EXT2FS_OS_LINUX		0
#define EXT2FS_OS_HURD		1
#define	EXT2FS_OS_MASIX		2
#define EXT2FS_OS_FREEBSD	3
#define EXT2FS_OS_LITES		4

/* Revision Levels */
#define EXT2FS_REV_ORIG		0
#define EXT2FS_REV_DYN		1

/* feature flags */
#define EXT2FS_FEATURE_COMPAT_DIR_PREALLOC	0x0001
#define EXT2FS_FEATURE_COMPAT_IMAGIC_INODES	0x0002
#define EXT2FS_FEATURE_COMPAT_HAS_JOURNAL	0x0004
#define EXT2FS_FEATURE_COMPAT_EXT_ATTR		0x0008
#define EXT2FS_FEATURE_COMPAT_RESIZE_INO	0x0010
#define EXT2FS_FEATURE_COMPAT_DIR_INDEX		0x0020

#define EXT2FS_FEATURE_INCOMPAT_COMPRESSION	0x0001
#define EXT2FS_FEATURE_INCOMPAT_FILETYPE	0x0002
#define EXT2FS_FEATURE_INCOMPAT_RECOVER		0x0004
#define EXT2FS_FEATURE_INCOMPAT_JOURNAL_DEV	0x0008

#define EXT2FS_FEATURE_RO_COMPAT_SPARSE_SUPER	0x0001
#define EXT2FS_FEATURE_RO_COMPAT_LARGE_FILE		0x0002
#define EXT2FS_FEATURE_RO_COMPAT_BTREE_DIR		0x0004



/*
 * Group Descriptor
 */
typedef struct {
	u_int8_t	bg_block_bitmap[4];	/* u32: block of blocks bitmap */ 
	u_int8_t	bg_inode_bitmap[4];	/* u32: block of inodes bitmap */
	u_int8_t	bg_inode_table[4];		/* u32: block of inodes table */
	u_int8_t	bg_free_blocks_count[2];	/* u16: num of free blocks */
	u_int8_t	bg_free_inodes_count[2];	/* u16: num of free inodes */
	u_int8_t	f1[16];
} ext2fs_gd;


/* data address to group number */
#define ext2_dtog_lcl(fsi, fs, d)	\
	(((d) - getu32(fsi, fs->s_first_data_block)) / \
	getu32(fsi, fs->s_blocks_per_group))


/* first fragment of group */
#define ext2_cgbase_lcl(fsi, fs, c)	\
	((DADDR_T)((getu32(fsi, fs->s_blocks_per_group) * (c)) + \
	getu32(fsi, fs->s_first_data_block)))


/*
 * Inode
 */
typedef struct {
    u_int8_t i_mode[2];		/* u16 */
    u_int8_t i_uid[2];	/* u16 */
    u_int8_t i_size[4];	/* u32 */
    u_int8_t i_atime[4];	/* u32 */
    u_int8_t i_ctime[4];	/* u32 */
    u_int8_t i_mtime[4];	/* u32 */
    u_int8_t i_dtime[4];	/* u32 */
    u_int8_t i_gid[2];	/* u16 */
    u_int8_t i_nlink[2];	/* u16 */
    u_int8_t i_nblk[4];
    u_int8_t i_flags[4];
    u_int8_t i_f5[4];
    u_int8_t i_block[15][4];	/*s32 */
    u_int8_t f6[8];
    u_int8_t i_size_high[4];  /* u32 - also i_dir_acl for non-regular  */
    u_int8_t f7[16];
} ext2fs_inode;

/* MODE */
#define EXT2_IN_FMT  0017000
#define EXT2_IN_SOCK 0140000
#define EXT2_IN_LNK  0120000
#define EXT2_IN_REG  0100000
#define EXT2_IN_BLK  0060000
#define EXT2_IN_DIR  0040000
#define EXT2_IN_CHR  0020000
#define EXT2_IN_FIFO  0010000

#define EXT2_IN_SECDEL 		0x00000001 /* Secure deletion */
#define EXT2_IN_UNRM 		0x00000002 /* Undelete */
#define EXT2_IN_COMP 		0x00000004 /* Compress file */
#define EXT2_IN_SYNC		0x00000008 /* Synchronous updates */
#define EXT2_IN_IMM		 	0x00000010 /* Immutable file */
#define EXT2_IN_APPEND 		0x00000020 /* writes to file may only append */
#define EXT2_IN_NODUMP 		0x00000040 /* do not dump file */
#define EXT2_IN_NOA		 	0x00000080 /* do not update atime */



/*
 * directory entries
 */
typedef struct {
    u_int8_t inode[4];		/* u32 */
    u_int8_t rec_len[2];	/* u16 */
    u_int8_t name_len[2];	/* u16 */
    char name[255];
} ext2fs_dentry1;

/* new structure starting at 2.2 */
typedef struct {
    u_int8_t inode[4];		/* u32 */
    u_int8_t rec_len[2];	/* u16 */
    u_int8_t name_len;
    u_int8_t type;
    char name[255];
} ext2fs_dentry2;

#define EXT2FS_DIRSIZ_lcl(len) \
    ((len + 8 + 3) & ~(3))


/* Ext2 directory file types (not the same as FFS. Sigh. */
#define EXT2_DE_UNKNOWN         0
#define EXT2_DE_REG_FILE        1
#define EXT2_DE_DIR             2
#define EXT2_DE_CHRDEV          3
#define EXT2_DE_BLKDEV          4
#define EXT2_DE_FIFO            5
#define EXT2_DE_SOCK            6
#define EXT2_DE_SYMLINK         7
#define EXT2_DE_MAX             8



 /*
  * Structure of an ext2fs file system handle.
  */
typedef struct {
    FS_INFO fs_info;            /* super class */
    ext2fs_sb	*fs;			/* super block */
    ext2fs_gd	*group;   		/* cached group descriptor */
    GRPNUM_T grpnum;            /* cached group number */
    UCHAR  *block_map;          /* cached block allocation bitmap */
    GRPNUM_T bmap_num;          /* cached block bitmap nr */
    UCHAR  *inode_map;          /* cached inode allocation bitmap */
    GRPNUM_T imap_num;          /* cached inode bitmap nr */
    ext2fs_inode *dinode;           /* cached disk inode */
    INUM_T  inum;           /* cached inode number */
    OFF_T   group_offset;       /* offset to first group desc */
    int     groups_count;       /* nr of descriptor group blocks */
} EXT2FS_INFO;

extern void ext2fs_dent_walk(FS_INFO *, INUM_T, int, FS_DENT_WALK_FN, char *);

#endif
