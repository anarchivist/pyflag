/*
** The Sleuth Kit 
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002 @stake Inc.  All rights reserved
*/

#ifndef _FATFS_H
#define _FATFS_H

/*
** Constants
*/
#define FATFS_ROOTINO	2	/* location of root directory inode */
#define FATFS_FIRSTINO	2

/* The following two values do not have the same meaning as they do in
 * EXT2FS and FFS because there is no notion of indirect pointers.  
 * we will assign the first cluster to direct_addr[0] and that is it
 */
#define FATFS_NDADDR    2 
#define FATFS_NIADDR    0

#define FATFS_SBOFF		0
#define FATFS_FS_MAGIC	0xaa55
#define FATFS_MAXNAMLEN	271 /* 256 + 8.3 name appended stuff */
#define FATFS_DEV_BSIZE   512

/* size of FAT to read into FATFS_INFO each time */
/* This must be at least 1024 bytes or else fat12 will get messed up */
#define FAT_CACHE_B		2048
#define FAT_CACHE_S		4

/* MASK values for FAT entries */
#define FATFS_12_MASK	0x00000fff
#define FATFS_16_MASK	0x0000ffff
#define FATFS_32_MASK	0x0fffffff

/* Constants for the FAT entry */
#define FATFS_UNALLOC	0
#define FATFS_BAD		0x0ffffff7
#define FATFS_EOFS		0x0ffffff8
#define FATFS_EOFE		0x0fffffff



/* macro to identify if the FAT value is End of File
 * returns 1 if it is and 0 if it is not 
 */
#define FATFS_ISEOF(val, mask)	\
	((val >= (FATFS_EOFS & mask)) && (val <= (FATFS_EOFE)))


#define FATFS_ISBAD(val, mask) \
	((val) == (FATFS_BAD & mask))


#define FATFS_CLUST_2_SECT(fatfs, c)	\
	(fatfs->firstclustsect + ((((c) & fatfs->mask) - 2) * fatfs->csize))

#define FATFS_SECT_2_CLUST(fatfs, s)	\
	(2 + ((s)  - fatfs->firstclustsect) / fatfs->csize)



/* given an inode, determine which sector it is in
 * i must be larger than 3 (2 is the root and it doesn't have a sector)
 */
#define FATFS_INODE_2_SECT(fatfs, i)    \
    ((i - 3)/(fatfs->dentry_cnt_se) + fatfs->firstdatasect)
  
#define FATFS_INODE_2_OFF(fatfs, i)     \
    (((i - 3) % fatfs->dentry_cnt_se) * sizeof(fatfs_dentry))
        
/* given a sector IN THE DATA AREA, return the base inode for it */
#define FATFS_SECT_2_INODE(fatfs, s)    \
    ((s - fatfs->firstdatasect) * fatfs->dentry_cnt_se + 3)



/*
 * Boot Sector Structure for FAT12, FAT16, and FAT32
 */
typedef struct {
	u_int8_t	f1[3];
	char		oemname[8];
	u_int8_t	ssize[2];	/* sector size in bytes */
	u_int8_t	csize;		/* cluster size in sectors */
	u_int8_t	reserved[2];/* number of reserved sectors for boot sectors */
	u_int8_t	numfat;		/* Number of FATs */
	u_int8_t	numroot[2];	/* Number of Root dentries */
	u_int8_t	sectors16[2];/* number of sectors in FS */
	u_int8_t	f2[1];
	u_int8_t	sectperfat16[2]; /* size of FAT */
	u_int8_t	f3[4];
	u_int8_t	prevsect[4];	/* number of sectors before FS partition */
	u_int8_t	sectors32[4];	/* 32-bit value of number of FS sectors */

	/* The following are different for fat12/fat16 and fat32 */
	union {
		struct {
			u_int8_t	f5[3];
			u_int8_t	vol_id[4];
			u_int8_t	vol_lab[11];
			u_int8_t	fs_type[8];
			u_int8_t	f6[448];
		} f16;
		struct {
			u_int8_t	sectperfat32[4];
			u_int8_t	ext_flag[2];
			u_int8_t	fs_ver[2];
			u_int8_t	rootclust[4];	/* cluster where root directory is stored */
			u_int8_t	fsinfo[2];	/* FS_INFO Location */
			u_int8_t	bs_backup[2];  /* sector of backup of boot sector */
			u_int8_t	f5[12];
			u_int8_t	drvnum;
			u_int8_t	f6[2];
			u_int8_t	vol_id[4];
			u_int8_t	vol_lab[11];
			u_int8_t	fs_type[8];
			u_int8_t	f7[420];
		} f32;	
	} a;

	u_int8_t	magic[2];		/* MAGIC for all versions */

} fatfs_sb;

typedef struct {
	u_int8_t	magic1[4];	/* 41615252 */
	u_int8_t	f1[480];
	u_int8_t	magic2[4];	/* 61417272 */
	u_int8_t	freecnt[4];		/* free clusters 0xfffffffff if unknown */
	u_int8_t	nextfree[4];	/* next free cluster */
	u_int8_t	f2[12];
	u_int8_t	magic3[4];  /* AA550000 */
} fatfs_fsinfo;



/* directory entry short name structure */
typedef struct {
	u_int8_t	name[8];
	u_int8_t	ext[3];
	u_int8_t	attrib;
	u_int8_t	lowercase;
	u_int8_t	ctimeten;	/* create times */
	u_int8_t	ctime[2];
	u_int8_t	cdate[2];
	u_int8_t	adate[2];	/* access time */
	u_int8_t	highclust[2];
	u_int8_t	wtime[2];	/* last write time */
	u_int8_t	wdate[2];
	u_int8_t	startclust[2];
	u_int8_t	size[4];
} fatfs_dentry;


/* Macro to combine the upper and lower 2-byte parts of the starting
 * cluster 
 */
#define FATFS_DENTRY_CLUST(fsi, de)	\
	((getu16(fsi, de->startclust)) | (getu16(fsi, de->highclust)<<16))

/* constants for first byte of name[] */
#define FATFS_SLOT_EMPTY	0x00
#define FATFS_SLOT_E5		0x05	/* actual value is 0xe5 */
#define FATFS_SLOT_DELETED	0xe5

/* 
 *Return 1 if c is an valid charactor for a short file name 
 *
 * NOTE: 0x05 is allowed in name[0], and 0x2e (".") is allowed for name[0]
 * and name[1] and 0xe5 is allowed for name[0]
 */
#define FATFS_IS_83_NAME(c)		\
	(((FATFS_IS_LFN_NAME(c) == 0)	|| \
	  ((c) == 0x00) || \
	  ((c) == 0x2b) || \
	  ((c) == 0x2c) || \
	  ((c) == 0x2e) || \
	  ((c) == 0x3a) || \
	  ((c) == 0x3b) || \
	  ((c) == 0x3d) || \
	  ((c) == 0x5b) || \
	  ((c) == 0x5d) || \
	  ((c) == 0xff)) == 0)


#define FATFS_IS_LFN_NAME(c)	\
	(((((c) > 0x00) && ((c) < 0x20)) || \
	  ((c) == 0x22) || \
	  ((c) == 0x2a) || \
	  ((c) == 0x2f) || \
	  ((c) == 0x3c) || \
	  ((c) == 0x3e) || \
	  ((c) == 0x3f) || \
	  ((c) == 0x5c) || \
	  ((c) == 0x7c) || \
	  (((c) >= 0x80) && ((c) < 0xff)))  == 0)


/* flags for attributes field */
#define FATFS_ATTR_NORMAL	0x00        /* normal file */
#define FATFS_ATTR_READONLY	0x01        /* file is readonly */
#define FATFS_ATTR_HIDDEN	0x02        /* file is hidden */
#define FATFS_ATTR_SYSTEM	0x04        /* file is a system file */
#define FATFS_ATTR_VOLUME	0x08        /* entry is a volume label */
#define FATFS_ATTR_DIRECTORY	0x10        /* entry is a directory name */
#define FATFS_ATTR_ARCHIVE	0x20        /* file is new or modified */
#define FATFS_ATTR_LFN		0x0f		/* A long file name entry */
#define FATFS_ATTR_ALL		0x3f		/* all flags set */

/* flags for lowercase field */
#define FATFS_CASE_LOWER_BASE	0x08	/* base is lower case */
#define FATFS_CASE_LOWER_EXT	0x10	/* extension is lower case */
#define FATFS_CASE_LOWER_ALL	0x18	/* both are lower */

#define FATFS_SEC_MASK		0x1f		/* number of seconds div by 2 */
#define FATFS_SEC_SHIFT		0		
#define FATFS_SEC_MIN		0
#define FATFS_SEC_MAX		29
#define FATFS_MIN_MASK		0x7e0		/* number of minutes 0-59 */
#define FATFS_MIN_SHIFT		5
#define FATFS_MIN_MIN		0	
#define FATFS_MIN_MAX		59
#define FATFS_HOUR_MASK		0xf800		/* number of hours 0-23 */
#define FATFS_HOUR_SHIFT	11
#define FATFS_HOUR_MIN		0	
#define FATFS_HOUR_MAX		23

/* return 1 if x is a valid FAT time */
#define FATFS_ISTIME(x)	\
	(((((x & FATFS_SEC_MASK) >> FATFS_SEC_SHIFT) > FATFS_SEC_MAX) || \
	  (((x & FATFS_MIN_MASK) >> FATFS_MIN_SHIFT) > FATFS_MIN_MAX) || \
	  (((x & FATFS_HOUR_MASK) >> FATFS_HOUR_SHIFT) > FATFS_HOUR_MAX) ) == 0)

#define FATFS_DAY_MASK		0x1f		/* day of month 1-31 */
#define FATFS_DAY_SHIFT		0		
#define FATFS_DAY_MIN		1
#define FATFS_DAY_MAX		31
#define FATFS_MON_MASK		0x1e0		/* month 1-12 */
#define FATFS_MON_SHIFT		5
#define FATFS_MON_MIN		1
#define FATFS_MON_MAX		12	
#define FATFS_YEAR_MASK		0xfe00		/* year, from 1980 0-127 */
#define FATFS_YEAR_SHIFT	9
#define FATFS_YEAR_MIN		0
#define FATFS_YEAR_MAX		127	

/* return 1 if x is a valid FAT date */
#define FATFS_ISDATE(x)	\
	 (((((x & FATFS_DAY_MASK) >> FATFS_DAY_SHIFT) > FATFS_DAY_MAX) || \
	   (((x & FATFS_DAY_MASK) >> FATFS_DAY_SHIFT) < FATFS_DAY_MIN) || \
	   (((x & FATFS_MON_MASK) >> FATFS_MON_SHIFT) > FATFS_MON_MAX) || \
	   (((x & FATFS_MON_MASK) >> FATFS_MON_SHIFT) < FATFS_MON_MIN) || \
	   (((x & FATFS_YEAR_MASK) >> FATFS_YEAR_SHIFT) > FATFS_YEAR_MAX) ) == 0)

/* 
 * Long file name support for windows 
 *
 * Contents of this are in UNICODE, not ASCII 
 */
typedef struct {
	u_int8_t	seq;
	u_int8_t	part1[10];
	u_int8_t	attributes;
	u_int8_t	reserved1;
	u_int8_t	chksum;
	u_int8_t	part2[12];
	u_int8_t	reserved2[2];
	u_int8_t	part3[4];
} fatfs_dentry_lfn;

/* flags for seq field */
#define FATFS_LFN_LAST	0x40	/* This bit is set for the first lfn entry */
#define FATFS_LFN_CNT	0x3f	/* These bits are a mask for the decreasing
  * sequence number for the entries */

/* internal FATFS_INFO structure */
typedef struct {
	FS_INFO fs_info;	/* super class */
	FS_BUF *table;			/* file allocation table (part of it) */

	FS_BUF *dinodes;		/* sector size buffer of inode list */
	fatfs_sb	*sb;

	fatfs_dentry	*dep;

	char *lfn;				/* buffer to allocate space for lfn support */
	u_int16_t		lfn_len; /* current length name in lfn */
	u_int8_t		lfn_chk;	/* checksum of entries in lfn */
	u_int8_t		lfn_seq;	/* seq of first entry in lfn */

	/* FIrst sector of FAT */
	u_int32_t firstfatsect;

	/* First sector after FAT  - For FAT12 and FAT16, this is where the
	 * root directory entries are.  For FAT32, this is the the first 
	 * cluster */
	u_int32_t firstdatasect;	

	/* The sector number were cluster 2 (the first one) is
	 * for FAT32, it will be the same as firstdatasect, but for FAT12 & 16
	 * it will be the first sector after the Root directory  */
	u_int32_t 	firstclustsect;

	/* size of data area in clusters, starting at firstdatasect */
	u_int32_t 	clustcnt;	

	u_int32_t	lastclust;

	/* sector where the root directory is located */
	u_int32_t	rootsect;

	u_int32_t	dentry_cnt_se; /* max number of dentries per sector */
	u_int32_t	dentry_cnt_cl; /* max number of dentries per cluster */

	u_int16_t	ssize;		/* size of sectors in bytes */
	u_int8_t	csize;		/* size of clusters in sectors */
	//u_int16_t	reserved;	/* number of reserved sectors */
	u_int8_t	numfat;		/* number of fat tables */
	u_int32_t	sectperfat;	/* sectors per fat table */
	u_int16_t	numroot;	/* number of 32-byte dentries in root dir */
	u_int32_t	mask;		/* the mask to use for the sectors */

} FATFS_INFO;


/*
 * Macro to identify if a cluster is allocated
 * returns 1 if it is allocated and 0 if not
 */
#define is_clustalloc(fs, c) \
    (getFAT((fs), (c)) != FATFS_UNALLOC)

extern u_int8_t is_sectalloc(FATFS_INFO *, int);



extern void fatfs_dent_walk(FS_INFO *, INUM_T, int, FS_DENT_WALK_FN, char *);
extern u_int8_t fatfs_isdentry(FATFS_INFO *, fatfs_dentry *);
extern void fatfs_make_root (FATFS_INFO *, FS_INODE *);
#endif
