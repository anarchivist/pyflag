/*
** The Sleuth Kit 
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003-2004 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002 @stake Inc.  All rights reserved
*/
#ifndef _FFS_H
#define _FFS_H

extern void
ffs_dent_walk(FS_INFO *, INUM_T, int, FS_DENT_WALK_FN, char *);

/*
** CONSTANTS
**/
#define FFS_FIRSTINO	0	/* 0 & 1 are reserved (1 was bad blocks) */
#define FFS_ROOTINO		2	/* location of root directory inode */
#define FFS_NDADDR		12
#define FFS_NIADDR		3

#define UFS1_SBOFF	8192
#define UFS2_SBOFF	65536
#define UFS2_SBOFF2	262144

#define UFS1_FS_MAGIC	0x011954
#define UFS2_FS_MAGIC	0x19540119

#define FFS_MAXNAMLEN 	255
#define FFS_MAXPATHLEN	1024
#define FFS_DIRBLKSIZ	512



#define FFS_DEV_BSIZE	512


typedef struct {
	u_int8_t	dir_num[4];
	u_int8_t	blk_free[4];
	u_int8_t	ino_free[4];
	u_int8_t	frag_free[4];
} ffs_csum;


/*
 * Super Block Structure
 */
typedef struct {
	u_int8_t f1[8];			
	/* Offsets in each cylinder group */
	u_int8_t sb_off[4];	/* s32 */
	u_int8_t gd_off[4];	/* s32 */
	u_int8_t ino_off[4];	/* s32 */
	u_int8_t dat_off[4];	/* s32 */

	/* How much the base of the admin data in each cyl group changes */
	u_int8_t cg_delta[4];	/* s32 */
	u_int8_t cg_cyc_mask[4];	/* s32 */

	u_int8_t wtime[4];	/* u32 : last written time */
	u_int8_t frag_num[4];	/* s32 - number of fragments in FS */
	u_int8_t blk_num[4];	/* s32 - number of blocks in FS */
	u_int8_t cg_num[4];	/* s32 - number of cyl grps in FS */
	u_int8_t bsize_b[4];	/* s32 - size of block */
	u_int8_t fsize_b[4];	/* s32 - size of fragment */
	u_int8_t bsize_frag[4];	/* s32 - num of frag in block */
	u_int8_t f5[36];
	u_int8_t fs_fragshift[4];	/* s32 */
	u_int8_t f6[20];
	u_int8_t fs_inopb[4];	/* s32 */
	u_int8_t f7[20];
	u_int8_t fs_id[8];
	u_int8_t cg_saddr[4];		/* s32 */
	u_int8_t cg_ssize_b[4];		/* s32 */
	u_int8_t fs_cgsize[4];		/* s32 */
	u_int8_t f7c[12];
	u_int8_t fs_ncyl[4];		/* s32 */
	u_int8_t fs_cpg[4];		/* s32 */
	u_int8_t cg_inode_num[4];		/* s32 */
	u_int8_t cg_frag_num[4];     /* s32 */	

	ffs_csum cstotal;

	u_int8_t fs_fmod;
	u_int8_t fs_clean;
	u_int8_t fs_ronly;
	u_int8_t fs_flags;
	u_int8_t last_mnt[512];
	u_int8_t f8[648];
	u_int8_t magic[4];     /* s32 */
	u_int8_t f9[1];
} ffs_sb1;

typedef struct {
	u_int8_t f1[8];			
	/* Offsets in each cylinder group */
	u_int8_t sb_off[4];	/* s32 */
	u_int8_t gd_off[4];	/* s32 */
	u_int8_t ino_off[4];	/* s32 */
	u_int8_t dat_off[4];	/* s32 */

	/* How much the base of the admin data in each cyl group changes */
	u_int8_t cg_old_delta[4];	/* s32 */
	u_int8_t cg_old_cyc_mask[4];	/* s32 */

	u_int8_t old_wtime[4];	/* u32 : last written time */
	u_int8_t old_frag_num[4];	/* s32 - number of fragments in FS */
	u_int8_t old_blk_num[4];	/* s32 - number of blocks in FS */
	u_int8_t cg_num[4];	/* s32 - number of cyl grps in FS */
	u_int8_t bsize_b[4];	/* s32 - size of block */
	u_int8_t fsize_b[4];	/* s32 - size of fragment */
	u_int8_t bsize_frag[4];	/* s32 - num of frag in block */
	u_int8_t f5[36];
	u_int8_t fs_fragshift[4];	/* s32 */
	u_int8_t f6[20];
	u_int8_t fs_inopb[4];	/* s32 */
	u_int8_t f7[28];
	u_int8_t fs_old_csaddr[4];		/* s32 */
	u_int8_t fs_cssize[4];		/* s32 */
	u_int8_t fs_cgsize[4];		/* s32 */
	u_int8_t f7c[12];
	u_int8_t fs_old_ncyl[4];		/* s32 */
	u_int8_t fs_old_cpg[4];		/* s32 */
	u_int8_t cg_inode_num[4];		/* s32 */
	u_int8_t cg_frag_num[4];     /* s32 - fs_fpg */	

	u_int8_t fs_old_cstotal[16];
	u_int8_t fs_fmod;
	u_int8_t fs_clean;
	u_int8_t fs_ronly;
	u_int8_t fs_old_flags;
	u_int8_t last_mnt[468];
	u_int8_t volname[32];
	u_int8_t swuid[8];
	u_int8_t f7d[352];

	u_int8_t wtime[8];	/* u32 : last written time */
	u_int8_t frag_num[8];	/* s32 - number of fragments in FS */
	u_int8_t blk_num[8];	/* s32 - number of blocks in FS */
	u_int8_t csaddr[8];

	u_int8_t f8a[208];
	u_int8_t fs_flags[4];
	u_int8_t f8b[56];

	u_int8_t magic[4];     /* s32 */
	u_int8_t f9[1];
} ffs_sb2;






/*
 * Cylinder Group Descriptor
 */
typedef struct {
	u_int8_t f1[4];
	u_int8_t magic[4];	/* 0x090255 */
	u_int8_t wtime[4];	/* last written time */
	u_int8_t cg_cgx[4];     /* s32 - my group number*/
	u_int8_t cyl_num[2];	/* number of cyl in this group */
	u_int8_t ino_num[2];	/* number of inodes in this group */
	u_int8_t frag_num[4];	/* number of fragments in this group */
	ffs_csum cs;
	u_int8_t last_alloc_blk[4]; /* last allocated blk relative to start */
	u_int8_t last_alloc_frag[4]; /* last alloc frag relative to start */
	u_int8_t last_alloc_ino[4];
	u_int8_t avail_frag[8][4]; 
	u_int8_t f2b[8];
	u_int8_t cg_iusedoff[4];     /* s32 */
	u_int8_t cg_freeoff[4];     /* s32 */
	u_int8_t f3[72];
} ffs_cgd;


/*
 * inode
 */

/* ffs_inode1: OpenBSD & FreeBSD etc. */
typedef struct {
	u_int8_t	di_mode[2]; 	/* u16 */
	u_int8_t	di_nlink[2];	/* s16 */
	u_int8_t	f1[4];
	u_int8_t	di_size[8];		/* u64 */
	u_int8_t	di_atime[4];	/* s32 */
	u_int8_t	f2[4];
	u_int8_t	di_mtime[4];	/* s32 */
	u_int8_t	f3[4];
	u_int8_t	di_ctime[4];	/* s32 */
	u_int8_t	f4[4];
	u_int8_t	di_db[12][4];	/* s32 */
	u_int8_t	di_ib[3][4];	/* s32 */
	u_int8_t	f5[12];
	u_int8_t	di_uid[4];		/* u32 */
	u_int8_t	di_gid[4];		/* u32 */
	u_int8_t	f6[8];
} ffs_inode1;

/* ffs_inode2: Solaris */
typedef struct {
	u_int8_t	di_mode[2];	/* u16 */
	u_int8_t	di_nlink[2];	/* s16 */
	u_int8_t	f1[4];
	u_int8_t	di_size[8];		/* u64 */
	u_int8_t	di_atime[4];	/* s32 */
	u_int8_t	f2[4];
	u_int8_t	di_mtime[4];	/* s32 */
	u_int8_t	f3[4];
	u_int8_t	di_ctime[4];	/* s32 */
	u_int8_t	f4[4];
	u_int8_t	di_db[12][4];	/* s32 */
	u_int8_t	di_ib[3][4];	/* s32 */
	u_int8_t	f5[16];
	u_int8_t	di_uid[4];	/* u32 */
	u_int8_t	di_gid[4];	/* u32 */
	u_int8_t	f6[4];
} ffs_inode2;

#define FFS_IN_FMT       0170000     /* Mask of file type. */
#define FFS_IN_FIFO      0010000     /* Named pipe (fifo). */
#define FFS_IN_CHR       0020000     /* Character device. */
#define FFS_IN_DIR       0040000     /* Directory file. */
#define FFS_IN_BLK       0060000     /* Block device. */
#define FFS_IN_REG       0100000     /* Regular file. */
#define FFS_IN_LNK       0120000     /* Symbolic link. */
#define FFS_IN_SHAD		 0130000	 /* SOLARIS ONLY */ 
#define FFS_IN_SOCK      0140000     /* UNIX domain socket. */
#define FFS_IN_WHT       0160000     /* Whiteout. */

/*
 * Directory Entries
 */
/* ffs_dentry1: new OpenBSD & FreeBSD etc. */
typedef struct {
	u_int8_t	d_ino[4];	/* u32 */
	u_int8_t	d_reclen[2];	/* u16 */
	u_int8_t	d_type;		/* u8 */
	u_int8_t	d_namlen;	/* u8 */
	char		d_name[256];
} ffs_dentry1;

/* type field values */
#define FFS_DT_UNKNOWN   0
#define FFS_DT_FIFO      1
#define FFS_DT_CHR       2
#define FFS_DT_DIR       4
#define FFS_DT_BLK       6
#define FFS_DT_REG       8
#define FFS_DT_LNK      10
#define FFS_DT_SOCK     12
#define FFS_DT_WHT      14

/* ffs_dentry2: Solaris and old xBSDs (no type field) */
typedef struct {
	u_int8_t	d_ino[4];	/* u32 */
	u_int8_t	d_reclen[2];	/* u16 */
	u_int8_t	d_namlen[2];	/* u16 */
	char		d_name[256];
} ffs_dentry2;


#define FFS_DIRSIZ_lcl(len) \
    ((len + 8 + 3) & ~(3))




 /*
  * Structure of a fast file system handle.
  */

#define FFS_UFS1	0x1
#define FFS_UFS2	0x2

typedef struct {
	FS_INFO fs_info;            /* super class */
	union {
		ffs_sb1 *sb1;         /* super block buffer */
		ffs_sb2 *sb2;         /* super block buffer */
	} fs;
	u_int8_t	ver;		/* UFS1 or UFS2 */
	char *dinode;               /* disk inode cache */
	INUM_T inum;				/* address of cached disk inode */
	FS_BUF *cg_buf;             /* cylinder block buffer */
	CGNUM_T cg_num;				/* number of cached cyl */
	FS_BUF *dino_buf;           /* inode block buffer */
	int	ffsbsize_f;		/* num of frags in an FFS block */
	int 	ffsbsize_b;		/* size of an FFS block in bytes */
} FFS_INFO;


/* modified macros */

/* original:
** cgbase(fs, c)   ((daddr_t)((fs)->fs_cg_frag_num * (c)))
*/
#define cgbase_lcl(fsi, fs, c)	\
	((DADDR_T)(gets32(fsi, (fs)->cg_frag_num) * (c)))


/* Macros to calc the locations of structures in cyl groups */

#define cgstart_lcl(fsi, fs, c)                          \
	( (getu32((fsi), (fs)->magic) == UFS2_FS_MAGIC) ? \
	(cgbase_lcl(fsi, fs, c)) :  \
	(cgbase_lcl(fsi, fs, c) + gets32((fsi), (fs)->cg_delta) * \
	 ((c) & ~(gets32((fsi), (fs)->cg_cyc_mask)))) )

/* cyl grp block */
#define cgtod_lcl(fsi, fs, c)	\
	(cgstart_lcl(fsi, fs, c) + gets32(fsi, (fs)->gd_off))		

/* inode block in cyl grp */
#define cgimin_lcl(fsi, fs, c)	\
	(cgstart_lcl(fsi, fs, c) + gets32(fsi, (fs)->ino_off))	

/* 1st data  block in cyl grp*/
#define cgdmin_lcl(fsi, fs, c)   \
	(cgstart_lcl(fsi, fs, c) + gets32(fsi, (fs)->dat_off))  

/* super blk in cyl grp*/
#define cgsblock_lcl(fsi, fs, c) 	\
	(cgstart_lcl(fsi, fs, c) + gets32(fsi, (fs)->sb_off))  

/* original:
** blkstofrags(fs, blks)  
**    ((blks) << (fs)->fs_fragshift)
*/
#define blkstofrags_lcl(fsi, fs, blks)  \
    ((blks) << gets32(fsi, (fs)->fs_fragshift))

/* original:
** itod(fs, x) \
**      ((DADDR_T)(cgimin(fs, itog(fs, x)) + \
**      (blkstofrags((fs), (((x)%(ulong_t)(fs)->cg_inode_num)/(ulong_t)INOPB(fs))))))
*/
#define itod_lcl(fsi, fs, x) \
      ((DADDR_T)(cgimin_lcl(fsi, fs, itog_lcl(fsi, fs, x)) + \
      (blkstofrags_lcl(fsi, (fs), (((x)%(ULONG)gets32(fsi, (fs)->cg_inode_num))/ \
	  (ULONG)gets32(fsi, (fs)->fs_inopb))))))

/* original:
** itoo(fs, x) ((x) % (uint32_t)INOPB(fs))
*/
#define itoo_lcl(fsi, fs, x) 	\
	((x) % (u_int32_t)getu32(fsi, (fs)->fs_inopb))

/* original:
** #define itog(fs, x)    ((x) / (fs)->fs_cg_inode_num)
*/
#define itog_lcl(fsi, fs, x)	\
	((x) / gets32(fsi, (fs)->cg_inode_num))

/* original:
** dtog(fs, d) ((d) / (fs)->fs_cg_frag_num)
*/
#define dtog_lcl(fsi, fs, d)	\
	((d) / gets32(fsi, (fs)->cg_frag_num))

#define cg_inosused_lcl(fsi, cgp)	\
	((u_int8_t *)((u_int8_t *)(cgp) + gets32(fsi, (cgp)->cg_iusedoff)))

#define cg_blksfree_lcl(fsi, cgp) \
	((u_int8_t *)((u_int8_t *)(cgp) + gets32(fsi, (cgp)->cg_freeoff)))


#endif /* _FFS_H */
