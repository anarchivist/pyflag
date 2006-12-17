/*
** fs_tools
** The Sleuth Kit 
**
** This header file is to be included if file system routines
** are used from the library.  
**
** $Date: 2006/12/05 21:39:52 $
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002 @stake Inc.  All rights reserved
** 
** Copyright (c) 1997,1998,1999, International Business Machines          
** Corporation and others. All Rights Reserved.
*/

#ifndef _FS_TOOLS_H
#define _FS_TOOLS_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "img_tools.h"

#ifdef __cplusplus
extern "C" {
#endif

/****************  FILE SYSTEM TYPES SECTION ********************/
    extern uint8_t fs_parse_type(const TSK_TCHAR *);
    extern void fs_print_types(FILE *);
    extern char *fs_get_type(uint8_t);

    /*
     * the most-sig-nibble is the file system type, which indictates which
     * _open function to call.  The least-sig-nibble is the specific type
     * of implementation.
     * */
#define FSMASK                  0xf0
#define OSMASK                  0x0f

#define UNSUPP_FS               0x00

#define FFS_TYPE                0x10
#define FFS_1                   0x11	/* UFS1 - FreeBSD, OpenBSD, BSDI ... */
#define FFS_1B                  0x12	/* Solaris (no type) */
#define FFS_2                   0x13	/* UFS2 - FreeBSD, NetBSD */
#define FFSAUTO                 0x14

#define EXTxFS_TYPE             0x20
#define EXT2FS                  0x21
#define EXT3FS                  0x22
#define EXTAUTO                 0x23

#define FATFS_TYPE              0x30
#define FAT12           	0x31
#define FAT16           	0x32
#define FAT32           	0x33
#define FATAUTO         	0x34

#define NTFS_TYPE               0x40
#define NTFS                    0x40

#define SWAPFS_TYPE             0x50
#define SWAP                    0x50

#define RAWFS_TYPE              0x60
#define RAW                     0x60

#define ISO9660_TYPE            0x70
#define ISO9660                 0x70

#define HFS_TYPE                0x80
#define HFS                     0x80


    typedef struct FS_INFO FS_INFO;
    typedef struct FS_INODE FS_INODE;
    typedef struct FS_DENT FS_DENT;
    typedef struct FS_DATA FS_DATA;
    typedef struct FS_DATA_RUN FS_DATA_RUN;
    typedef struct FS_NAME FS_NAME;
    typedef struct FS_JENTRY FS_JENTRY;


/* Flags for the return value of inode_walk, block_walk, and dent_walk
 * actions
 */
#define WALK_CONT	0x0
#define WALK_STOP	0x1
#define WALK_ERROR	0x2

/* walk action functions */
    typedef uint8_t(*FS_INODE_WALK_FN) (FS_INFO *, FS_INODE *, int,
	void *);
    typedef uint8_t(*FS_BLOCK_WALK_FN) (FS_INFO *, DADDR_T, char *, int,
	void *);
    typedef uint8_t(*FS_DENT_WALK_FN) (FS_INFO *, FS_DENT *, int, void *);
    typedef uint8_t(*FS_FILE_WALK_FN) (FS_INFO *, DADDR_T, char *,
	size_t, int, void *);

    typedef uint8_t(*FS_JBLK_WALK_FN) (FS_INFO *, char *, int, void *);
    typedef uint8_t(*FS_JENTRY_WALK_FN) (FS_INFO *, FS_JENTRY *, int,
	void *);



/***************************************************************
 * FS_INFO: Allocated when an image is opened
 */
    struct FS_INFO {
	IMG_INFO *img_info;
	SSIZE_T offset;		/* byte offset into img_info that fs starts */

	/* meta data */
	INUM_T inum_count;	/* number of inodes */
	INUM_T root_inum;	/* root inode */
	INUM_T first_inum;	/* first valid inode */
	INUM_T last_inum;	/* LINUX starts at 1 */

	/* content */
	DADDR_T block_count;	/* number of blocks */
	DADDR_T first_block;	/* in case start at 1 */
	DADDR_T last_block;	/* in case start at 1 */
	unsigned int block_size;	/* block size in bytes */
	unsigned int dev_bsize;	/* size of device blocks */

	/* Journal */
	INUM_T journ_inum;	/* Inode of journal */

	uint8_t ftype;		/* type of file system */
	uint8_t flags;		/* flags for image, see below */

	/* endian order flag - values defined in misc/tsk_endian.h */
	uint8_t endian;

	TSK_LIST *list_inum_named;	/* list of unallocated inodes that
					 * are pointed to by a file name -- 
					 * Used to find orphans
					 */
	/* file system specific function pointers */
	 uint8_t(*block_walk) (FS_INFO *, DADDR_T, DADDR_T, int,
	    FS_BLOCK_WALK_FN, void *);

	 uint8_t(*inode_walk) (FS_INFO *, INUM_T, INUM_T, int,
	    FS_INODE_WALK_FN, void *);
	FS_INODE *(*inode_lookup) (FS_INFO *, INUM_T);
	 uint8_t(*istat) (FS_INFO *, FILE *, INUM_T, DADDR_T, int32_t);

	 uint8_t(*file_walk) (FS_INFO *, FS_INODE *, uint32_t, uint16_t,
	    int, FS_FILE_WALK_FN, void *);

	 uint8_t(*dent_walk) (FS_INFO *, INUM_T, int, FS_DENT_WALK_FN,
	    void *);

	 uint8_t(*jopen) (FS_INFO *, INUM_T);
	 uint8_t(*jblk_walk) (FS_INFO *, DADDR_T, DADDR_T, int,
	    FS_JBLK_WALK_FN, void *);
	 uint8_t(*jentry_walk) (FS_INFO *, int, FS_JENTRY_WALK_FN, void *);


	 uint8_t(*fsstat) (FS_INFO *, FILE *);
	 uint8_t(*fscheck) (FS_INFO *, FILE *);

	void (*close) (FS_INFO *);
    };

/* flag for FS_INFO flags */
#define FS_HAVE_SEQ		0x08

//#define FS_FLAG_TMHDR (1<<9)          /* show tm header */

/* flags that are used for dent_walk and FS_NAME */
#define FS_FLAG_NAME_ALLOC   (1<<0)	/* allocated */
#define FS_FLAG_NAME_UNALLOC (1<<1)	/* unallocated */
#define FS_FLAG_NAME_RECURSE (1<<2)	/* recurse on directories */

/* flags that are used for inode_walk and FS_INODE */
#define FS_FLAG_META_ALLOC	(1<<0)	/* allocated */
#define FS_FLAG_META_UNALLOC    (1<<1)	/* unallocated */
#define FS_FLAG_META_USED	(1<<2)	/* used */
#define FS_FLAG_META_UNUSED	(1<<3)	/* never used */
#define FS_FLAG_META_ORPHAN	(1<<4)	/* Orphan Files */
#define FS_FLAG_META_COMP	(1<<5)	/* The file contains compressed data */

/* flags that are used for block_walk and any data units 
 * Including the data units in the action of file_walk */
#define FS_FLAG_DATA_ALLOC	(1<<0)	/* allocated */
#define FS_FLAG_DATA_UNALLOC    (1<<1)	/* unallocated */
#define FS_FLAG_DATA_CONT	(1<<2)	/* allocated for file content */
#define FS_FLAG_DATA_META	(1<<3)	/* allocated for meta data */
#define FS_FLAG_DATA_BAD	(1<<4)	/* marked as bad by the FS */
#define FS_FLAG_DATA_ALIGN	(1<<5)	/* block align (i.e. send a whole block) */
#define FS_FLAG_DATA_RES	(1<<6)	/* This data is resident (NTFS ONLY) -- used by ntfs_data_walk */
#define FS_FLAG_DATA_SPARSE	(1<<7)	/* Used to note that the block addr
					 * is not be accurate since the block
					 * is sparse (all zeros) */
#define FS_FLAG_DATA_COMP	(1<<8)	/* This "block" was stored in compressed form */




/* Flags used when calling file_walk, action of file_walk uses
 * the FS_FLAG_DATA_ flags */
#define FS_FLAG_FILE_AONLY	(1<<0)	/* only copy address to callback */
#define FS_FLAG_FILE_SLACK	(1<<1)	/* return slack space too */
#define FS_FLAG_FILE_RECOVER    (1<<2)	/* Recover a deleted file */
#define FS_FLAG_FILE_META	(1<<3)	/* return meta data units too */
#define FS_FLAG_FILE_NOSPARSE   (1<<4)	/* don't return sparse data units */
#define FS_FLAG_FILE_NOID	(1<<5)	/* Ignore the id field in the argument - use only type */



/***************************************************************
 * Generic inode structure for filesystem-independent operations.
 */


/* 
 * All non-resident addresses will be stored here so that the search
 * programs (find_inode) can account for the addresses. 
 *
 * All resident non-standard attributes will be stored here so they
 * can be displayed.  By default, the $Data attribute will be saved
 * in the FS_INODE structure. If the $Data attribute is resident,
 * then the dir/indir stuff will be 0 and the $Data will be the
 * first element in this linked list 
 */

/* len = 0 when not being used */
    struct FS_DATA_RUN {
	FS_DATA_RUN *next;
	DADDR_T addr;		/* Starting data unit address */
	DADDR_T len;		/* Length in data units */
	uint8_t flags;
    };
#define FS_DATA_FILLER	0x1
#define FS_DATA_SPARSE	0x2

    struct FS_DATA {
	FS_DATA *next;
	uint8_t flags;
	char *name;		/* name of data (if available) */
	size_t nsize;		/* number of allocated bytes for name */
	uint32_t type;		/* type of attribute */
	uint16_t id;		/* id of attr, used when duplicate types */

	OFF_T size;		/* size of data (in bytes) of stream or run */

	/* Run-List data (non-resident) */
	FS_DATA_RUN *run;	/* a linked list of data runs */
	OFF_T runlen;		/* number of bytes that are allocated in
				 * original run (larger than size) */
	uint32_t compsize;	/* size of the compression unit */

	/* stream data (resident) */
	size_t buflen;		/* allocated bytes in buf */
	uint8_t *buf;		/* buffer for resident data */
    };

#define FS_DATA_INUSE	0x1	// structre in use
#define FS_DATA_NONRES	0x2	// non-resident
#define FS_DATA_RES		0x4	// resident
#define	FS_DATA_ENC		0x10	// encrypted
#define FS_DATA_COMP	0x20	// compressed
#define FS_DATA_SPAR	0x40	// sparse



    extern FS_DATA *fs_data_alloc(uint8_t);
    extern FS_DATA_RUN *fs_data_run_alloc();
    extern FS_DATA *fs_data_getnew_attr(FS_DATA *, uint8_t);
    extern void fs_data_clear_list(FS_DATA *);

    extern FS_DATA *fs_data_put_str(FS_DATA *, char *, uint32_t, uint16_t,
	void *, unsigned int);

    extern FS_DATA *fs_data_put_run(FS_DATA *, DADDR_T, OFF_T,
	FS_DATA_RUN *, char *, uint32_t, uint16_t, OFF_T, uint8_t,
	uint32_t);

    extern FS_DATA *fs_data_lookup(FS_DATA *, uint32_t, uint16_t);
    extern FS_DATA *fs_data_lookup_noid(FS_DATA *, uint32_t);

    extern void fs_data_run_free(FS_DATA_RUN *);
    extern void fs_data_free(FS_DATA *);









/* Currently this is only used with NTFS & FAT systems */
    struct FS_NAME {
	FS_NAME *next;
	char name[512];		// Could be in UTF-8 encoding
	INUM_T par_inode;
	uint32_t par_seq;
    };

    struct FS_INODE {
	INUM_T addr;		/* Address of meta data structure */
	mode_t mode;		/* type and permission */
	int nlink;		/* link count */
	OFF_T size;		/* file size */
	uid_t uid;		/* owner */
	gid_t gid;		/* group */

	/* @@@ Need to make these 64-bits ... ? */
	time_t mtime;		/* last modified */
	time_t atime;		/* last access */
	time_t ctime;		/* last status change */

	/* filesystem specific times */
	union {
	    struct {		/* NTFS Times */
		time_t crtime;	/* create time */
	    };
	    struct {		/* Linux Times */
		time_t dtime;	/* delete time */
	    };
	    struct {		/* HFS Times */
		time_t bkup_time;
		time_t attr_mtime;
	    };
	};

	DADDR_T *direct_addr;	/* direct blocks */
	int direct_count;	/* number of blocks */
	DADDR_T *indir_addr;	/* indirect blocks */
	int indir_count;	/* number of blocks */

	uint32_t seq;		/* sequence number (NTFS Only) */
	FS_DATA *attr;		/* additional attributes for NTFS */
	FS_NAME *name;
	char *link;		/* used if this is a symbolic link */

	int flags;		/* flags FS_FLAG_META_* */
    };

    extern FS_INODE *fs_inode_alloc(int, int);
    extern FS_INODE *fs_inode_realloc(FS_INODE *, int, int);
    extern void fs_inode_free(FS_INODE *);




/************************************************************************* 
 * Directory entries 
 */
    struct FS_DENT {
	char *name;		/* long / normal name -- could be UTF-8 */
	ULONG name_max;		/* number of bytes allocated to name */

	char *shrt_name;	/* short version of name (FAT / NTFS only) */
	ULONG shrt_name_max;	/* number of bytes allocated to short name */

	INUM_T inode;		/* inode number */
	struct FS_INODE *fsi;	/* Inode structure */

	uint8_t ent_type;	/* dir, file etc FS_DENT_??? */

	//int flags;            /* FS_FLAG_NAME_* */

	char *path;		/* prefix to name when recursing */
	unsigned int pathdepth;	/* current depth of directories */
    };


/* Type of file that entry is for (ent_type for FS_DENT) */
#define FS_DENT_UNDEF   0	/* Unknown Type */
#define FS_DENT_FIFO    1	/* named pipe */
#define FS_DENT_CHR     2	/* character */
#define FS_DENT_DIR 	4	/* directory */
#define FS_DENT_BLK     6	/* block */
#define FS_DENT_REG     8	/* regular file */
#define FS_DENT_LNK 	10	/* symbolic link */
#define FS_DENT_SOCK    12	/* socket */
#define FS_DENT_SHAD    13	/* shadow inode (solaris) */
#define FS_DENT_WHT 	14	/* whiteout (openbsd) */

#define FS_DENT_MASK    15	/* mask value */
#define FS_DENT_MAX_STR 15	/* max index for string version of types */

/* ascii representation of above types */
    extern char fs_dent_str[FS_DENT_MAX_STR][2];

/* string that is prepended to orphan FAT & NTFS files when the file
 * name is known, but the parent is not */
#define ORPHAN_STR "-ORPHAN_FILE-"

/* Type of file in the mode field of Inodes.  FAT and NTFS are converted
 * to this mode value */
#define FS_INODE_FMT       0170000	/* Mask of file type. */
#define FS_INODE_FIFO      0010000	/* Named pipe (fifo). */
#define FS_INODE_CHR       0020000	/* Character device. */
#define FS_INODE_DIR       0040000	/* Directory file. */
#define FS_INODE_BLK       0060000	/* Block device. */
#define FS_INODE_REG       0100000	/* Regular file. */
#define FS_INODE_LNK       0120000	/* Symbolic link. */
#define FS_INODE_SHAD      0130000	/* SOLARIS ONLY */
#define FS_INODE_SOCK      0140000	/* UNIX domain socket. */
#define FS_INODE_WHT       0160000	/* Whiteout. */

#define FS_INODE_SHIFT		12
#define FS_INODE_MASK    15	/* mask value */
#define FS_INODE_MAX_STR 15	/* max index for string version of types */

    extern char fs_inode_str[FS_INODE_MAX_STR][2];

#define MODE_ISUID 0004000	/* set user id on execution */
#define MODE_ISGID 0002000	/* set group id on execution */
#define MODE_ISVTX 0001000	/* sticky bit */

#define MODE_IRUSR 0000400	/* R for owner */
#define MODE_IWUSR 0000200	/* W for owner */
#define MODE_IXUSR 0000100	/* X for owner */

#define MODE_IRGRP 0000040	/* R for group */
#define MODE_IWGRP 0000020	/* W for group */
#define MODE_IXGRP 0000010	/* X for group */

#define MODE_IROTH 0000004	/* R for other */
#define MODE_IWOTH 0000002	/* W for other */
#define MODE_IXOTH 0000001	/* X for other */



/**************** Journal Stuff **********************/
    struct FS_JENTRY {
	DADDR_T jblk;		/* journal block address */
	DADDR_T fsblk;		/* fs block that journal entry is about */
    };




/* function decs */
    extern FS_DENT *fs_dent_alloc(ULONG, ULONG);
    extern FS_DENT *fs_dent_realloc(FS_DENT *, ULONG);
    extern void fs_dent_free(FS_DENT *);
    extern void fs_dent_print(FILE *, FS_DENT *, int, FS_INFO *,
	FS_DATA *);
    extern void fs_dent_print_long(FILE *, FS_DENT *, int, FS_INFO *,
	FS_DATA *);
    extern void fs_dent_print_mac(FILE *, FS_DENT *, int, FS_INFO *,
	FS_DATA * fs_data, char *);

    extern void make_ls(mode_t, char *);
    extern void fs_print_day(FILE *, time_t);
    extern void fs_print_time(FILE *, time_t);

/*
** Is this string a "." or ".."
*/
#define ISDOT(str) ( ((str[0] == '.') && \
 ( ((str[1] == '.') && (str[2] == '\0')) || (str[1] == '\0') ) ) ? 1 : 0 )



/**************************************************************8
 * Generic routines.
 */
    extern FS_INFO *fs_open(IMG_INFO *, SSIZE_T, const TSK_TCHAR *);

/* fs_io routines */
    extern SSIZE_T fs_read_block(FS_INFO *, DATA_BUF *, OFF_T, DADDR_T);
    extern SSIZE_T fs_read_block_nobuf(FS_INFO *, char *, OFF_T, DADDR_T);
#define fs_read_random(fsi, buf, len, offs)	\
	(fsi)->img_info->read_random((fsi)->img_info, (fsi)->offset, (buf), (len), (offs))

    extern char *fs_load_file(FS_INFO *, FS_INODE *, uint32_t, uint16_t,
	int);

    extern SSIZE_T
	fs_read_file(FS_INFO *, FS_INODE *, uint32_t, uint16_t,
	SSIZE_T, SSIZE_T, char *);

    extern SSIZE_T
	fs_read_file_noid(FS_INFO *, FS_INODE *, SSIZE_T, SSIZE_T, char *);







/***** LIBRARY ROUTINES FOR COMMAND LINE FUNCTIONS */
#define DCALC_DD        0x1
#define DCALC_DLS       0x2
#define DCALC_SLACK     0x4
    extern int8_t fs_dcalc(FS_INFO * fs, uint8_t lclflags, DADDR_T cnt);


#define DCAT_HEX                0x1
#define DCAT_ASCII   0x2
#define DCAT_HTML       0x4
#define DCAT_STAT       0x8
    extern uint8_t fs_dcat(FS_INFO * fs, uint8_t lclflags, DADDR_T addr,
	DADDR_T read_num_units);


#define DLS_CAT     0x01
#define DLS_LIST    0x02
#define DLS_SLACK   0x04
    extern uint8_t fs_dls(FS_INFO * fs, uint8_t lclflags, DADDR_T bstart,
	DADDR_T bend, int flags);

    extern uint8_t fs_dstat(FS_INFO * fs, uint8_t lclflags, DADDR_T addr,
	int flags);

#define FFIND_ALL 0x1
    extern uint8_t fs_ffind(FS_INFO * fs, uint8_t lclflags, INUM_T inode,
	uint32_t type, uint16_t id, int flags);



#define FLS_DOT         0x001
#define FLS_LONG        0x002
#define FLS_FILE        0x004
#define FLS_DIR         0x008
#define FLS_FULL        0x010
#define FLS_MAC         0x020
    extern uint8_t fs_fls(FS_INFO * fs, uint8_t lclflags, INUM_T inode,
	int flags, TSK_TCHAR * pre, int32_t skew);


    extern uint8_t fs_icat(FS_INFO * fs, uint8_t lclflags, INUM_T inum,
	uint32_t type, uint16_t id, int flags);


#define IFIND_ALL       0x01
#define IFIND_PATH      0x04
#define IFIND_DATA      0x08
#define IFIND_PAR       0x10
#define IFIND_PAR_LONG  0x20
    extern int8_t fs_ifind_path(FS_INFO * fs, uint8_t lclflags,
	TSK_TCHAR * path, INUM_T * result);
    extern uint8_t fs_ifind_data(FS_INFO * fs, uint8_t lclflags,
	DADDR_T blk);
    extern uint8_t fs_ifind_par(FS_INFO * fs, uint8_t lclflags,
	INUM_T par);


#define ILS_OPEN        (1<<0)
#define ILS_MAC		(1<<1)
#define ILS_LINK	(1<<2)
#define ILS_UNLINK	(1<<3)

    extern uint8_t fs_ils(FS_INFO * fs, uint8_t lclflags, INUM_T istart,
	INUM_T ilast, int flags, int32_t skew, TSK_TCHAR * img);



#ifdef __cplusplus
}
#endif
#endif
/* LICENSE
 * .ad
 * .fi
 *	This software is distributed under the IBM Public License.
 * AUTHOR(S)
 *	Wietse Venema
 *	IBM T.J. Watson Research
 *	P.O. Box 704
 *	Yorktown Heights, NY 10598, USA
 --*/
