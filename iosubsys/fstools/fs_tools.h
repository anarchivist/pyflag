/*
** The Sleuth Kit 
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003-2004 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002 @stake Inc.  All rights reserved
** 
** Copyright (c) 1997,1998,1999, International Business Machines          
** Corporation and others. All Rights Reserved.
*/

 /*
  * External interface.
  */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/fcntl.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>

#include "fs_os.h"
#include "fs_types.h"
#include "except.h"
 /*
  * Verbose logging.
  */
//extern FILE *logfp;
FILE *logfp;




#ifndef NBBY				/* NIH */
#define NBBY 8
#endif
#ifndef isset				/* NIH */
#define isset(a,i)	((a)[(i)/NBBY] & (1<<((i)%NBBY)))
#endif

typedef unsigned long INUM_T;
typedef unsigned long ULONG;
typedef unsigned long long ULLONG;
typedef unsigned long CGNUM_T;
typedef unsigned long GRPNUM_T;
typedef unsigned char UCHAR;

typedef struct FS_INFO FS_INFO;
typedef struct IO_INFO IO_INFO;
typedef struct FS_BUF FS_BUF;
typedef struct FS_INODE FS_INODE;
typedef struct FS_DENT FS_DENT;
typedef struct FS_DATA FS_DATA;
typedef struct FS_DATA_RUN FS_DATA_RUN;
typedef struct FS_NAME FS_NAME;

/* Flags for the return value of inode_walk, block_walk, and dent_walk
 * actions
 */
#define WALK_CONT	0x0
#define WALK_STOP	0x1

/* walk action functions */
typedef u_int8_t (*FS_INODE_WALK_FN) (FS_INFO *, INUM_T, FS_INODE *, int, char *);
typedef u_int8_t (*FS_BLOCK_WALK_FN) (FS_INFO *, DADDR_T, char *, int, char *);
typedef u_int8_t (*FS_DENT_WALK_FN) (FS_INFO *, FS_DENT *, int, char *);
typedef u_int8_t (*FS_FILE_WALK_FN) (FS_INFO *, DADDR_T, char *, int, int, char *);

/***********************************************************
 * Linked list for IO subsystem options
 **************************************************/
struct IO_OPT {
  char *option;
  char *value;
  struct IO_OPT *next;
};

typedef struct IO_OPT IO_OPT;

/****************************************************************
 * Generic IO Subsystem objects
 */
struct IO_INFO {
  /* The name of the subsystem */
  char *name;
  /* Its description */
  char *description;
  /* Total size of the derived class. The one with the above name and description. Note that if the class is extended its size may be longer than sizeof(IO_INFO) */
  int size;
  /* A constructor, this creates a new instance of the object based on the class */
  struct IO_INFO * (*constructor)(IO_INFO *class);
  /* Destructor: Responsible for cleaning up and returning memory */
  void (*destructor)(void *self);
  /* A help function describing all parameters to this subsystem */
  void (*help)(void);
  /* The function used to parse out options and initialise the subsystem */
  int (*initialise)(IO_INFO *self,IO_OPT *arg);
  /* The random read function */
  int (*read_random)(IO_INFO *self, char *buf, int len, OFF_T offs,
		               const char *comment);
  /* A function used to open the file (may not be needed?) */
  int (*open)(IO_INFO *self);
  /* close file function: (may go in the destructor?) */
  int (*close)(IO_INFO *self);
  /* indicates if the open method needs to be called. Generally the read_* methods will check this and if its not set, they will call the open functions */
  int ready;
};

/***************************************************************
 * FS_INFO: Allocated when an image is opened
 */
struct FS_INFO {
  IO_INFO  *io;				/* IO Subsystem to use */
    OFF_T   seek_pos;			/* current seek position */

	/* meta data */
    INUM_T  inum_count;			/* number of inodes */
    INUM_T  root_inum;			/* root inode */
	INUM_T	first_inum;			/* first valid inode */
    INUM_T  last_inum;			/* LINUX starts at 1 */

	/* content */
	DADDR_T block_count;		/* number of blocks */
	DADDR_T first_block;		/* in case start at 1 */
	DADDR_T last_block;			/* in case start at 1 */
	int     block_size;			/* block size in bytes */
	int		dev_bsize;			/* value of DEV_BSIZE constant */


	unsigned char ftype;		/* type of file system */
	unsigned char	flags;		/* flags for image, see below */


	/* file system specific function pointers */
    void    (*block_walk) (FS_INFO *, DADDR_T, DADDR_T, int, 
	  FS_BLOCK_WALK_FN, char *);

    void    (*inode_walk) (FS_INFO *, INUM_T, INUM_T, int, 
	  FS_INODE_WALK_FN, char *);
    FS_INODE *(*inode_lookup) (FS_INFO *, INUM_T);
	void	(*istat) (FS_INFO *, FILE *, INUM_T, int, int32_t);
    void    (*file_walk) (FS_INFO *, FS_INODE *, u_int32_t, u_int16_t, 
	  int, FS_FILE_WALK_FN, char *);

    void    (*dent_walk) (FS_INFO *, INUM_T, int, FS_DENT_WALK_FN, char *);

	void	(*fsstat) (FS_INFO *, FILE *);
	void	(*fscheck) (FS_INFO *, FILE *);

	/* The function used to read a block */
	void (*read_block)(FS_INFO *fs,FS_BUF *buf, int len, DADDR_T addr,
		    const char *comment);

    void    (*close) (FS_INFO *);
};

/* flag for FS_INFO flags */
#define FS_LIT_ENDIAN	0x01
#define FS_BIG_ENDIAN	0x02
#define FS_HAVE_DTIME	0x04
#define FS_HAVE_SEQ		0x08

//#define FS_FLAG_TMHDR	(1<<9)		/* show tm header */

/* flags that are used for dent_walk and FS_NAME */
#define FS_FLAG_NAME_ALLOC	 (1<<0)		/* allocated */
#define FS_FLAG_NAME_UNALLOC (1<<1)		/* unallocated */
#define FS_FLAG_NAME_RECURSE (1<<2)		/* recurse on directories */

/* flags that are used for inode_walk and FS_INODE */
#define FS_FLAG_META_LINK	(1<<0)		/* link count > 0 */
#define FS_FLAG_META_UNLINK	(1<<1)		/* link count == 0 */
#define FS_FLAG_META_ALLOC	(1<<2)		/* allocated */
#define FS_FLAG_META_UNALLOC (1<<3)		/* unallocated */
#define FS_FLAG_META_USED	(1<<4)		/* used */
#define FS_FLAG_META_UNUSED	(1<<5)		/* never used */

/* flags that are used for block_walk and any data units 
 * Including the data units in the action of file_walk */
#define FS_FLAG_DATA_ALLOC	(1<<0)	/* allocated */
#define FS_FLAG_DATA_UNALLOC (1<<1)	/* unallocated */
#define FS_FLAG_DATA_CONT	(1<<2)	/* allocated for file content */
#define FS_FLAG_DATA_META	(1<<3)	/* allocated for meta data */
#define FS_FLAG_DATA_BAD	(1<<4)	/* marked as bad by the FS */
#define FS_FLAG_DATA_ALIGN	(1<<5)	/* block align (i.e. send a whole block) */



/* Flags used when calling file_walk, action of file_walk uses
 * the FS_FLAG_DATA_ flags */
#define FS_FLAG_FILE_AONLY	(1<<0)		/* only copy address to callback */
#define FS_FLAG_FILE_SLACK	(1<<1)		/* return slack space too */
#define FS_FLAG_FILE_RECOVER (1<<2)		/* Recover a deleted file */
#define FS_FLAG_FILE_META	(1<<3)		/* return meta data units too */
#define FS_FLAG_FILE_NOSPARSE (1<<4)	/* don't return sparse data units */
#define FS_FLAG_FILE_NOABORT (1<<5)		/* do not abort when errors are found*/
#define FS_FLAG_FILE_NOID	(1<<6)		/* Ignore the id field in the argument - use only type */


/***************************************************************
 * I/O buffer, used for all forms of I/O.
 */
struct FS_BUF {
    char   *data;			/* buffer memory */
    int     size;			/* buffer size */
    int     used;			/* amount of space used */
    DADDR_T addr;			/* start block */
};

extern FS_BUF *fs_buf_alloc(int);
extern void fs_buf_free(FS_BUF *);


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
	int64_t addr;
	DADDR_T	len;
	u_int8_t flags;
};
#define FS_DATA_FILLER	0x1
#define FS_DATA_SPARSE	0x2

struct FS_DATA {
	FS_DATA		*next;
	u_int8_t	flags;			
	char		*name;			/* name of data (if available) */
	int			nsize;			/* number of allocated bytes for name */
	u_int32_t	type;			/* type of attribute */
	u_int16_t	id;				/* id of attr, used when duplicate types */

	u_int64_t	size;			/* size of data in stream or run */

	/* Run-List data (non-resident) */
	FS_DATA_RUN	*run;			/* a linked list of data runs */
	u_int64_t	runlen;			/* number of bytes that are allocated in
								 * original run (larger than size) */

	/* stream data (resident) */
	int			buflen;			/* allocated bytes in buf */
	u_int8_t	*buf;			/* buffer for resident data */
};

#define FS_DATA_INUSE	0x1		// structre in use
#define FS_DATA_NONRES	0x2		// non-resident 
#define FS_DATA_RES		0x4		// resident 
#define	FS_DATA_ENC		0x10	// encrypted 
#define FS_DATA_COMP	0x20	// compressed
#define FS_DATA_SPAR	0x40	// sparse


/* Currently this is only used with NTFS & FAT systems */
struct FS_NAME {
	FS_NAME *next;
	char name[256];
	u_int64_t par_inode;
	u_int32_t par_seq;
};

struct FS_INODE {
	mode_t  mode;			/* type and permission */
	int     nlink;			/* link count */
	OFF_T   size;			/* file size */
	uid_t   uid;			/* owner */
	gid_t   gid;			/* group */
	time_t  mtime;			/* last modified */
	time_t  atime;			/* last access */
	time_t  ctime;			/* last status change */
	time_t	crtime;		/* create time (NTFS only: not used by ils) */
	time_t  dtime;			/* delete time (Linux only) */
	DADDR_T *direct_addr;		/* direct blocks */
	int     direct_count;		/* number of blocks */
	DADDR_T *indir_addr;		/* indirect blocks */
	int     indir_count;		/* number of blocks */

	u_int32_t	seq;			/* sequence number (NTFS Only) */
	FS_DATA	*attr;				/* additional attributes for NTFS */
	FS_NAME *name;
	char	*link;				/* used if this is a symbolic link */

	int 	flags;			/* flags FS_FLAG_META_* */
};

extern FS_INODE *fs_inode_alloc(int, int);
extern FS_INODE *fs_inode_realloc(FS_INODE *, int, int);
extern void fs_inode_free(FS_INODE *);




/************************************************************************* 
 * Directory entries 
 */
struct FS_DENT {
	unsigned int inode;     /* inode number */
	u_int16_t nextLink;  	/* distance until next entry
				** according to the actual entry ptr */
	u_int16_t reclen;    	/* actual length of record based on name len */
	u_int8_t ent_type; 		/* dir, file etc FS_DENT_???*/
	u_int16_t namlen;   	/* length of actual name */
	ULONG maxnamlen;		/* size allocated to name*/
	char *name;     		/* name of file, directory etc
                			** this MUST be NULL terminated */
	struct FS_INODE *fsi;   /* Inode structure */
	char *path;				/* prefix to name when recursing*/
	unsigned int pathdepth;	/* current depth of directories*/
};

/* Type of file that entry is for (ent_type for FS_DENT) */
#define FS_DENT_UNDEF   0   /* Unknown Type */
#define FS_DENT_FIFO    1   /* named pipe */
#define FS_DENT_CHR     2   /* character */
#define FS_DENT_DIR 	4   /* directory */
#define FS_DENT_BLK     6   /* block */
#define FS_DENT_REG     8   /* regular file */
#define FS_DENT_LNK 	10  /* symbolic link */
#define FS_DENT_SOCK    12  /* socket */
#define FS_DENT_SHAD    13  /* shadow inode (solaris) */
#define FS_DENT_WHT 	14	/* whiteout (openbsd) */

#define FS_DENT_MASK    15  /* mask value */
#define FS_DENT_MAX_STR 15  /* max index for string version of types */

/* ascii representation of above types */
extern char fs_dent_str[FS_DENT_MAX_STR][2];

/* string that is prepended to orphan FAT & NTFS files when the file
 * name is known, but the parent is not */
#define ORPHAN_STR "-ORPHAN_FILE-"

/* Type of file in the mode field of Inodes.  FAT and NTFS are converted
 * to this mode value */
#define FS_INODE_FMT       0170000     /* Mask of file type. */
#define FS_INODE_FIFO      0010000     /* Named pipe (fifo). */
#define FS_INODE_CHR       0020000     /* Character device. */
#define FS_INODE_DIR       0040000     /* Directory file. */
#define FS_INODE_BLK       0060000     /* Block device. */
#define FS_INODE_REG       0100000     /* Regular file. */
#define FS_INODE_LNK       0120000     /* Symbolic link. */
#define FS_INODE_SHAD      0130000     /* SOLARIS ONLY */
#define FS_INODE_SOCK      0140000     /* UNIX domain socket. */
#define FS_INODE_WHT       0160000     /* Whiteout. */

#define FS_INODE_SHIFT		12
#define FS_INODE_MASK    15  /* mask value */
#define FS_INODE_MAX_STR 15  /* max index for string version of types */

extern char fs_inode_str[FS_INODE_MAX_STR][2];

#define MODE_ISUID 0004000         /* set user id on execution */
#define MODE_ISGID 0002000         /* set group id on execution */
#define MODE_ISVTX 0001000         /* sticky bit */
 
#define MODE_IRUSR 0000400         /* R for owner */  
#define MODE_IWUSR 0000200         /* W for owner */
#define MODE_IXUSR 0000100         /* X for owner */
  
#define MODE_IRGRP 0000040         /* R for group */
#define MODE_IWGRP 0000020         /* W for group */
#define MODE_IXGRP 0000010         /* X for group */

#define MODE_IROTH 0000004         /* R for other */
#define MODE_IWOTH 0000002         /* W for other */
#define MODE_IXOTH 0000001         /* X for other */



/* function decs */
extern FS_DENT *fs_dent_alloc(ULONG);
extern FS_DENT *fs_dent_realloc(FS_DENT *, ULONG);
extern void fs_dent_free(FS_DENT *);
extern void fs_dent_print(FILE *, FS_DENT *, int, FS_INFO *, FS_DATA *);
extern void fs_dent_print_long(FILE *, FS_DENT *, int, FS_INFO *, FS_DATA *);
extern void fs_dent_print_mac(FILE *, FS_DENT *, int, FS_INFO *, 
  FS_DATA *fs_data, char *);

extern void make_ls(mode_t, char *, int);
extern void fs_print_day (FILE *, time_t);
extern void fs_print_time (FILE *, time_t);

/*
** Is this string a "." or ".."
*/
#define ISDOT(str) ( ((str[0] == '.') && \
 ( ((str[1] == '.') && (str[2] == '\0')) || (str[1] == '\0') ) ) ? 1 : 0 )



/**************************************************************8
 * Generic routines.
 */
extern FS_INFO *fs_open(IO_INFO *io, const char *);
extern void fs_read_block(FS_INFO *, FS_BUF *, int, DADDR_T, const char *);
extern void fs_read_random(FS_INFO *, char *, int, OFF_T, const char *);
extern void fs_copy_file(FS_INFO *, INUM_T, int);
extern void print_nersion();
extern void fs_print_types();
extern void print_version();

 /*
  * Support for BSD FFS and lookalikes.
  */
extern FS_INFO *ffs_open(IO_INFO *, unsigned char ftype);
  
 /* 
  * Support for LINUX ext2fs.
  */
extern FS_INFO *ext2fs_open(IO_INFO *, unsigned char ftype);

/*
 * Support for FAT
 */
extern FS_INFO *fatfs_open(IO_INFO *, unsigned char ftype);

/*
 * Support for NTFS
 */
extern FS_INFO *ntfs_open(IO_INFO *, unsigned char ftype);

/*
 * Support for RAW
 */
extern FS_INFO *rawfs_open(const char *, unsigned char ftype);

/*
 * Support for SWAP
 */
extern FS_INFO *swapfs_open(const char *, unsigned char ftype);


 /*
  * Support for long seeks.
  */
extern OFF_T mylseek(int, OFF_T, int);


/* 
** Dealing with endian differences
*/

/* macros to read in multi-byte fields
 * file system is an array of 8-bit values, not 32-bit values
 */
extern u_int8_t	guessu16(FS_INFO *, u_int8_t *, u_int16_t);
extern u_int8_t	guessu32(FS_INFO *, u_int8_t *, u_int32_t);

/* 16-bit values */
#define getu16(fs, x)   \
    (u_int16_t)((fs->flags & FS_LIT_ENDIAN) ? \
	  (((u_int8_t *)x)[0] + (((u_int8_t *)x)[1] << 8)) :    \
	  (((u_int8_t *)x)[1] + (((u_int8_t *)x)[0] << 8)) ) 

#define gets16(fs, x)	\
	((int16_t)getu16(fs, x))

/* 32-bit values */
#define getu32(fs, x)	\
	(u_int32_t)( (fs->flags & FS_LIT_ENDIAN)  ?	\
     ((((u_int8_t *)x)[0] <<  0) + \
	  (((u_int8_t *)x)[1] <<  8) + \
	  (((u_int8_t *)x)[2] << 16) + \
	  (((u_int8_t *)x)[3] << 24) ) \
	:	\
	 ((((u_int8_t *)x)[3] <<  0) + \
	  (((u_int8_t *)x)[2] <<  8) + \
	  (((u_int8_t *)x)[1] << 16) + \
	  (((u_int8_t *)x)[0] << 24) ) )

#define gets32(fs, x)	\
	((int32_t)getu32(fs, x))

#define getu48(fs, x)   \
	(u_int64_t)( (fs->flags & FS_LIT_ENDIAN)  ?	\
      ((u_int64_t) \
	  ((u_int64_t)((u_int8_t *)(x))[0] <<  0)+ \
	  ((u_int64_t)((u_int8_t *)(x))[1] <<  8) + \
      ((u_int64_t)((u_int8_t *)(x))[2] << 16) + \
	  ((u_int64_t)((u_int8_t *)(x))[3] << 24) + \
      ((u_int64_t)((u_int8_t *)(x))[4] << 32) + \
      ((u_int64_t)((u_int8_t *)(x))[5] << 40)) \
	: \
      ((u_int64_t) \
	  ((u_int64_t)((u_int8_t *)(x))[5] <<  0)+ \
	  ((u_int64_t)((u_int8_t *)(x))[4] <<  8) + \
      ((u_int64_t)((u_int8_t *)(x))[3] << 16) + \
	  ((u_int64_t)((u_int8_t *)(x))[2] << 24) + \
      ((u_int64_t)((u_int8_t *)(x))[1] << 32) + \
      ((u_int64_t)((u_int8_t *)(x))[0] << 40)) )


#define getu64(fs, x)   \
	(u_int64_t)( (fs->flags & FS_LIT_ENDIAN)  ?	\
      ((u_int64_t) \
	  ((u_int64_t)((u_int8_t *)(x))[0] << 0)  + \
	  ((u_int64_t)((u_int8_t *)(x))[1] << 8) + \
      ((u_int64_t)((u_int8_t *)(x))[2] << 16) + \
	  ((u_int64_t)((u_int8_t *)(x))[3] << 24) + \
      ((u_int64_t)((u_int8_t *)(x))[4] << 32) + \
      ((u_int64_t)((u_int8_t *)(x))[5] << 40) + \
      ((u_int64_t)((u_int8_t *)(x))[6] << 48) + \
      ((u_int64_t)((u_int8_t *)(x))[7] << 56)) \
	: \
      ((u_int64_t) \
	  ((u_int64_t)((u_int8_t *)(x))[7] <<  0) + \
	  ((u_int64_t)((u_int8_t *)(x))[6] <<  8) + \
      ((u_int64_t)((u_int8_t *)(x))[5] << 16) + \
	  ((u_int64_t)((u_int8_t *)(x))[4] << 24) + \
      ((u_int64_t)((u_int8_t *)(x))[3] << 32) + \
      ((u_int64_t)((u_int8_t *)(x))[2] << 40) + \
      ((u_int64_t)((u_int8_t *)(x))[1] << 48) + \
      ((u_int64_t)((u_int8_t *)(x))[0] << 56)) )

#define gets64(fs, x)	\
	((int64_t)getu64(fs, x))

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
