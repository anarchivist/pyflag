/*
** The Sleuth Kit 
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003 Brian Carrier.  All rights reserved
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
#define FFS_SBOFF		8192
#define FFS_FS_MAGIC	0x011954
#define FFS_MAXNAMLEN 	255
#define FFS_MAXPATHLEN	1024
#define FFS_DIRBLKSIZ	512



#define FFS_DEV_BSIZE	512






/*
 * Super Block Structure
 */
typedef struct {
	u_int8_t f1[8];			
	u_int8_t fs_sblkno[4];	/* s32 */
	u_int8_t fs_cblkno[4];	/* s32 */
	u_int8_t fs_iblkno[4];	/* s32 */
	u_int8_t fs_dblkno[4];	/* s32 */
	u_int8_t fs_cgoffset[4];	/* s32 */
	u_int8_t fs_cgmask[4];	/* s32 */
	u_int8_t fs_time[4];	/* u32 : last written time */
	u_int8_t fs_size[4];	/* s32 */
	u_int8_t f4[4];
	u_int8_t fs_ncg[4];		/* s32 */
	u_int8_t fs_bsize[4];	/* s32 */
	u_int8_t fs_fsize[4];	/* s32 */
	u_int8_t fs_frag[4];	/* s32 */
	u_int8_t f5[36];
	u_int8_t fs_fragshift[4];	/* s32 */
	u_int8_t f6[20];
	u_int8_t fs_inopb[4];	/* s32 */
	u_int8_t f7[28];
	u_int8_t fs_csaddr[4];		/* s32 */
	u_int8_t fs_cssize[4];		/* s32 */
	u_int8_t fs_cgsize[4];		/* s32 */
	u_int8_t f7c[12];
	u_int8_t fs_ncyl[4];		/* s32 */
	u_int8_t fs_cpg[4];		/* s32 */
	u_int8_t fs_ipg[4];		/* s32 */
	u_int8_t fs_fpg[4];     /* s32 */	
	u_int8_t f8[1180];
	u_int8_t fs_magic[4];     /* s32 */
	u_int8_t f9[1];
} ffs_sb;

/*
 * Cylinder Group
 */
typedef struct {
	u_int8_t f1[12];
	u_int8_t cg_cgx[4];     /* s32 */
	u_int8_t f2[76];
	u_int8_t cg_iusedoff[4];     /* s32 */
	u_int8_t cg_freeoff[4];     /* s32 */
	u_int8_t f3[72];
} ffs_cg;


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
typedef struct {
    FS_INFO fs_info;            /* super class */
    ffs_sb *fs;                   /* super block buffer */
    char *dinode;               /* disk inode cache */
	INUM_T inum;				/* address of cached disk inode */
    FS_BUF *cg_buf;             /* cylinder block buffer */
	CGNUM_T cg_num;				/* number of cached cyl */
    FS_BUF *dino_buf;           /* inode block buffer */
	int	block_frags;			/* num of frags in block */
} FFS_INFO;


/* modified macros */

/* original:
** cgbase(fs, c)   ((daddr_t)((fs)->fs_fpg * (c)))
*/
#define cgbase_lcl(fsi, fs, c)	\
	((DADDR_T)(gets32(fsi, (fs)->fs_fpg) * (c)))


/* Macros to calc the locations of structures in cyl groups */

#define cgstart_lcl(fsi, fs, c)                          \
     (cgbase_lcl(fsi, fs, c) + gets32((fsi), (fs)->fs_cgoffset) * \
	 ((c) & ~(gets32((fsi), (fs)->fs_cgmask))))

/* cyl grp block */
#define cgtod_lcl(fsi, fs, c)	\
	(cgstart_lcl(fsi, fs, c) + gets32(fsi, (fs)->fs_cblkno))		

/* inode block in cyl grp */
#define cgimin_lcl(fsi, fs, c)	\
	(cgstart_lcl(fsi, fs, c) + gets32(fsi, (fs)->fs_iblkno))	

/* 1st data  block in cyl grp*/
#define cgdmin_lcl(fsi, fs, c)   \
	(cgstart_lcl(fsi, fs, c) + gets32(fsi, (fs)->fs_dblkno))  

/* super blk in cyl grp*/
#define cgsblock_lcl(fsi, fs, c) 	\
	(cgstart_lcl(fsi, fs, c) + gets32(fsi, (fs)->fs_sblkno))  

/* original:
** blkstofrags(fs, blks)  
**    ((blks) << (fs)->fs_fragshift)
*/
#define blkstofrags_lcl(fsi, fs, blks)  \
    ((blks) << gets32(fsi, (fs)->fs_fragshift))

/* original:
** itod(fs, x) \
**      ((DADDR_T)(cgimin(fs, itog(fs, x)) + \
**      (blkstofrags((fs), (((x)%(ulong_t)(fs)->fs_ipg)/(ulong_t)INOPB(fs))))))
*/
#define itod_lcl(fsi, fs, x) \
      ((DADDR_T)(cgimin_lcl(fsi, fs, itog_lcl(fsi, fs, x)) + \
      (blkstofrags_lcl(fsi, (fs), (((x)%(ULONG)gets32(fsi, (fs)->fs_ipg))/ \
	  (ULONG)gets32(fsi, (fs)->fs_inopb))))))

/* original:
** itoo(fs, x) ((x) % (uint32_t)INOPB(fs))
*/
#define itoo_lcl(fsi, fs, x) 	\
	((x) % (u_int32_t)getu32(fsi, (fs)->fs_inopb))

/* original:
** #define itog(fs, x)    ((x) / (fs)->fs_ipg)
*/
#define itog_lcl(fsi, fs, x)	\
	((x) / gets32(fsi, (fs)->fs_ipg))

/* original:
** dtog(fs, d) ((d) / (fs)->fs_fpg)
*/
#define dtog_lcl(fsi, fs, d)	\
	((d) / gets32(fsi, (fs)->fs_fpg))

#define cg_inosused_lcl(fsi, cgp)	\
	((u_int8_t *)((u_int8_t *)(cgp) + gets32(fsi, (cgp)->cg_iusedoff)))

#define cg_blksfree_lcl(fsi, cgp) \
	((u_int8_t *)((u_int8_t *)(cgp) + gets32(fsi, (cgp)->cg_freeoff)))


#endif /* _FFS_H */
