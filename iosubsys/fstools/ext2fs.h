/*
** The Sleuth Kit 
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003-2004 Brian Carrier.  All rights reserved
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
	u_int8_t	s_r_blocks_count[4];
	u_int8_t	s_free_blocks_count[4];	/* u32 */
	u_int8_t	s_free_inode_count[4];	/* u32 */
	u_int8_t	s_first_data_block[4];	/* u32 */
	u_int8_t	s_log_block_size[4];	/* u32 */
	u_int8_t	s_log_frag_size[4];		/* s32 */
	u_int8_t	s_blocks_per_group[4];	/* u32 */
	u_int8_t	s_frags_per_group[4];	/* u32 */
	u_int8_t	s_inodes_per_group[4];	/* u32 */
	u_int8_t	s_mtime[4];		/* u32 */	/* mount time */
	u_int8_t	s_wtime[4];		/* u32 */	/* write time */
	u_int8_t	s_mnt_count[2];	/* u16 */	/* mount count */
	u_int8_t	s_max_mnt_count[2];	/* s16 */
	u_int8_t	s_magic[2];	/* u16 */
	u_int8_t	s_state[2];	/* u16 */	/* fs state */
	u_int8_t	s_errors[2]; /* u16 */
	u_int8_t	s_minor_rev_level[2];	/* u16 */
	u_int8_t	s_lastcheck[4];	/* u32 */
	u_int8_t	s_checkinterval[4];	/* u32 */
	u_int8_t	s_creator_os[4];	/* u32 */
	u_int8_t	s_rev_level[4];	/* u32 */
	u_int8_t	s_def_resuid[2];	/* u16 */
	u_int8_t	s_def_resgid[2];	/* u16 */
	u_int8_t	s_first_ino[4];		/* u32 */
	u_int8_t	s_inode_size[2];		/* u16 */
	u_int8_t	s_block_group_nr[2];		/* u16 */
	u_int8_t	s_feature_compat[4];	/* u32 */
	u_int8_t	s_feature_incompat[4];	/* u32 */
	u_int8_t	s_feature_ro_compat[4];	/* u32 */
	u_int8_t	s_uuid[16];		/* u8[16] */
	char		s_volume_name[16];
	char		s_last_mounted[64];
	u_int8_t	s_algorithm_usage_bitmap[4];	/* u32 */
	u_int8_t	s_prealloc_blocks;	/* u8 */
	u_int8_t	s_prealloc_dir_blocks;	/* u8 */
	u_int8_t	s_padding1[2];		/* u16 */
	u_int8_t	s_journal_uuid[16];	/* u8[16] */
	u_int8_t	s_journal_inum[4];	/* u32 */
	u_int8_t	s_journal_dev[4];	/* u32 */
	u_int8_t	s_last_orphan[4];	/* u32 */
	u_int8_t	s_padding[788];
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
	u_int8_t	bg_used_dirs_count[2];		/* u16: num of use directories  */
	u_int8_t	f1[14];
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
    u_int8_t i_generation[4];
    u_int8_t i_file_acl[4];
    u_int8_t i_size_high[4];  /* u32 - also i_dir_acl for non-regular  */
    u_int8_t i_faddr[4];
    u_int8_t i_frag;
    u_int8_t i_fsize;
    u_int8_t f1[2];
    u_int8_t i_uid_high[2];
    u_int8_t i_gid_high[2];
    u_int8_t f7[4];
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


#define EXT2_DE_V1	1
#define EXT2_DE_V2	2




/* Extended Attributes
 */

#define EXT2_EA_MAGIC	0xEA020000

typedef struct {
	u_int8_t	magic[4];
	u_int8_t	refcount[4];
	u_int8_t	blocks[4];
	u_int8_t	hash[4];
	u_int8_t	f1[16];
	u_int8_t	entry;
} ext2fs_ea_header;


#define EXT2_EA_IDX_USER                   1
#define EXT2_EA_IDX_POSIX_ACL_ACCESS       2
#define EXT2_EA_IDX_POSIX_ACL_DEFAULT      3
#define EXT2_EA_IDX_TRUSTED                4
#define EXT2_EA_IDX_LUSTRE                 5
#define EXT2_EA_IDX_SECURITY               6

/* Entries follow the header and are aligned to 4-byte boundaries 
 * the value of the attribute is stored at the bottom of the block 
 */
typedef struct {
	u_int8_t        nlen;
	u_int8_t        nidx;
	u_int8_t        val_off[2];
	u_int8_t        val_blk[4];
	u_int8_t        val_size[4];
	u_int8_t        hash[4];
	u_int8_t        name;
} ext2fs_ea_entry;

#define EXT2_EA_LEN(nlen) \
	((((nlen) + 19 ) / 4) * 4)


typedef struct {
	u_int8_t	ver[4];
} ext2fs_pos_acl_head;


#define EXT2_PACL_TAG_USERO	0x01
#define EXT2_PACL_TAG_USER	0x02
#define EXT2_PACL_TAG_GRPO	0x04
#define EXT2_PACL_TAG_GRP	0x08
#define EXT2_PACL_TAG_MASK	0x10
#define EXT2_PACL_TAG_OTHER	0x20


#define EXT2_PACL_PERM_EXEC	0x01
#define EXT2_PACL_PERM_WRITE	0x02
#define EXT2_PACL_PERM_READ	0x04


typedef struct {
	u_int8_t	tag[2];
	u_int8_t	perm[2];
} ext2fs_pos_acl_entry_sh;

typedef struct {
	u_int8_t	tag[2];
	u_int8_t	perm[2];
	u_int8_t	id[4];
} ext2fs_pos_acl_entry_lo;


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
	u_int8_t	deentry_type;	/* v1 or v2 of dentry */
	u_int16_t	inode_size;	/* size of each inode */
} EXT2FS_INFO;

extern void ext2fs_dent_walk(FS_INFO *, INUM_T, int, FS_DENT_WALK_FN, char *);

#endif
