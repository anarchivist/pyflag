/*
** The Sleuth Kit 
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003-2004 Brian Carrier.  All rights reserved 
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
 *	ils 1
 * SUMMARY
 *	list inode information
 * SYNOPSIS
 * .ad
 * .fi
 *	\fBils\fR [\fB-eorvV\fR] [\fB-f \fIfstype\fR]
 *		\fIdevice\fR [\fIstart-stop\fR ...]
 *
 *	\fBils\fR [\fB-aAlLvVzZ\fR] [\fB-f \fIfstype\fR]
 *		\fIdevice\fR [\fIstart-stop\fR ...]
 * DESCRIPTION
 *	\fBils\fR opens the named \fIdevice\fR and lists inode information.
 *	By default, \fBils\fR lists only the inodes of removed files.
 *
 * 	Arguments:
 * .IP \fB-e\fR
 *	List every inode in the file system.
 * .IP "\fB-f\fI fstype\fR"
 *	Specifies the file system type. The default file system type
 *	is system dependent. With most UNIX systems the default type
 *	is \fBffs\fR (Berkeley fast file system). With Linux the default
 *	type is \fBext2fs\fR (second extended file system).
 * .IP \fB-o\fR
 *	List only inodes of removed files that are still open or executing.
 *	This option is short-hand notation for \fB-aL\fR
 *	(see the \fBfine controls\fR section below).
 * .IP \fB-r\fR
 *	List only inodes of removed files. This option is short-hand notation
 *	for \fB-LZ\fR
 *	(see the \fBfine controls\fR section below).
 * .IP \fB-v\fR
 *	Turn on verbose mode, output to stderr.
 * .IP \fB-V\fR
 *	Turn on verbose mode, output to stdout.
 * .IP \fIdevice\fR
 *	Disk special file, or regular file containing a disk image.
 *	On UNIX systems, raw mode disk access may give better performance
 *	than block mode disk access.  LINUX disk device drivers support
 *	only block mode disk access.
 * .IP "\fIstart-stop\fR ..."
 *	Examine the specified inode number or number range. Either the
 *	\fIstart\fR, the \fIstop\fR, or the \fI-stop\fR may be omitted.
 * .PP
 *	Fine controls:
 * .IP \fB-a\fR
 *	List only allocated inodes: these belong to files with at least one
 *	directory entry in the file system, and to removed files that
 *	are still open or executing.
 * .IP \fB-A\fR
 *	List only unallocated inodes: these belong to files that no longer
 *	exist.
 * .IP \fB-l\fR
 *	List only inodes with at least one hard link. These belong to files
 *	with at least one directory entry in the file system.
 * .IP \fB-L\fR
 *	List only inodes without any hard links. These belong to files that no
 *	longer exist, and to removed files that are still open or executing.
 * .IP \fB-z\fR
 *	List only inodes with zero status change time. Presumably, these
 *	inodes were never used.
 * .IP \fB-Z\fR
 *	List only inodes with non-zero status change time. Presumably, these
 *	belong to files that still exist, or that existed in the past.
 * .PP
 *	The output format is in time machine format, as described in
 *	tm-format(5). The output begins with a two-line header that
 *	describes the data origin, and is followed by a one-line header
 *	that lists the names of the data attributes that make up the
 *	remainder of the output:
 * .IP \fBst_ino\fR
 *	The inode number.
 * .IP \fBst_alloc\fR
 *	Allocation status: `a' for allocated inode, `f' for free inode.
 * .IP \fBst_uid\fR
 *	Owner user ID.
 * .IP \fBst_gid\fR
 *	Owner group ID.
 * .IP \fBst_mtime\fR
 *	UNIX time (seconds) of last file modification.
 * .IP \fBst_atime\fR
 *	UNIX time (seconds) of last file access.
 * .IP \fBst_ctime\fR
 *	UNIX time (seconds) of last inode status change.
 * .IP \fBst_dtime\fR
 *	UNIX time (seconds) of file deletion (LINUX only).
 * .IP \fBst_mode\fR
 *	File type and permissions (octal).
 * .IP \fBst_nlink\fR
 *	Number of hard links.
 * .IP \fBst_size\fR
 *	File size in bytes.
 * .IP \fBst_block0,st_block1\fR
 *	The first two entries in the direct block address list.
 * SEE ALSO
 *	mactime(1), mtime, atime, ctime reporter
 *	tm-format(5), time machine data format
 * BUGS
 *	\fBils\fR should support more file system types. Right now, support
 *	is limited to \fBext2fs\fR when built on Linux, and \fBffs\fR when
 *	built on Solaris and BSD systems.
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
#include "split_at.h"

FILE   *logfp;

extern char *progname;

static char *image;

/* number of seconds time skew of system 
 * if the system was 100 seconds fast, the value should be +100 
 */
static int32_t sec_skew = 0;

/* atoinum - convert string to inode number */

INUM_T  atoinum(const char *str)
{
    char   *cp;
    INUM_T  inum;

    if (*str == 0)
	return (0);
    inum = STRTOUL(str, &cp, 0);
    if (*cp || cp == str)
	error("bad inode number: %s", str);
    return (inum);
}

/* usage - explain and terminate */

static void usage()
{
    printf("usage: %s [-eomrvV] [-aAlLzZ] [-f fstype] [-s seconds] device [inum... ]\n",
	  progname);

	printf("\t-e: Display all inodes\n");
	printf("\t-o: Display inodes that are removed, but sill open\n");
	printf("\t-m: Display output in the mactime format (replaces ils2mac from TCT)\n");
	printf("\t-r: Display removed inodes (default)\n");
	printf("\t-i: IO subsystem to use\n");
	printf("\t-s seconds: Time skew of original machine (in seconds)\n");
	printf("\t-a: Allocated files\n"); 
	printf("\t-A: Un-Allocated files\n"); 
	printf("\t-l: Linked files\n"); 
	printf("\t-L: Un-Linked files\n"); 
	printf("\t-z: Un-Used files (ctime is 0)\n"); 
	printf("\t-Z: Used files (ctime is not 0)\n"); 
	printf("\t-v: verbose output to stderr\n");
	printf("\t-V: Display version number\n");
    printf("\t-f fstype: Image file system type\n");
	printf("Supported file system types:\n");
	fs_print_types();
	exit(1);
}

/* print_header - print time machine header */

static void 
print_header(FS_INFO *fs, const char *device)
{
    char    hostnamebuf[BUFSIZ];
    unsigned long now;

    if (gethostname(hostnamebuf, sizeof(hostnamebuf) - 1) < 0)
		error("gethostname: %m");
    hostnamebuf[sizeof(hostnamebuf) - 1] = 0;
    now = time((time_t *) 0);

    /*
     * Identify table type and table origin.
     */
    printf("class|host|device|start_time\n");
    printf("ils|%s|%s|%lu\n", hostnamebuf, device, now);

    /*
     * Identify the fields in the data that follow.
     */
    printf("st_ino|st_alloc|st_uid|st_gid|st_mtime|st_atime|st_ctime");

	if (fs->flags & FS_HAVE_DTIME)
    	printf("|st_dtime");

    printf("|st_mode|st_nlink|st_size|st_block0|st_block1\n");
}

static void 
print_header_mac()
{
    char    hostnamebuf[BUFSIZ];
    unsigned long now;

    if (gethostname(hostnamebuf, sizeof(hostnamebuf) - 1) < 0)
		error("gethostname: %m");
    hostnamebuf[sizeof(hostnamebuf) - 1] = 0;
    now = time((time_t *) 0);

    /*
     * Identify table type and table origin.
     */
    printf("class|host|start_time\n");
    printf("body|%s|%lu\n", hostnamebuf, now);

    /*
     * Identify the fields in the data that follow.
     */
	printf("md5|file|st_dev|st_ino|st_mode|st_ls|st_nlink|st_uid|st_gid|");
	printf("st_rdev|st_size|st_atime|st_mtime|st_ctime|st_blksize|st_blocks\n");

	return;
}


/* print_inode - list generic inode */

static u_int8_t
print_inode(FS_INFO *fs, INUM_T inum, FS_INODE *fs_inode, int flags,
			        char *unused_context)
{

	if (sec_skew != 0) {
		fs_inode->mtime -= sec_skew;
		fs_inode->atime -= sec_skew;
		fs_inode->ctime -= sec_skew;
	}
    printf("%lu|%c|%d|%d|%lu|%lu|%lu",
	   (ULONG) inum, (flags & FS_FLAG_META_ALLOC) ? 'a' : 'f',
	   (int) fs_inode->uid, (int) fs_inode->gid,
	   (ULONG) fs_inode->mtime, (ULONG) fs_inode->atime,
	   (ULONG) fs_inode->ctime);

	if (sec_skew != 0) {
		fs_inode->mtime += sec_skew;
		fs_inode->atime += sec_skew;
		fs_inode->ctime += sec_skew;
	}

	if (fs->flags & FS_HAVE_DTIME) {
		if (sec_skew != 0) 
			fs_inode->dtime -= sec_skew;

    	printf("|%lu", (ULONG) fs_inode->dtime);

		if (sec_skew != 0) 
			fs_inode->dtime += sec_skew;
	}

    printf("|%lo|%d|%llu|%lu|%lu\n",
	   (ULONG) fs_inode->mode, (int) fs_inode->nlink,
	   (ULLONG) fs_inode->size, 
	   (fs_inode->direct_count > 0)?(ULONG) fs_inode->direct_addr[0] : 0,
	   (fs_inode->direct_count > 1)?(ULONG) fs_inode->direct_addr[1] : 0);

	return WALK_CONT;
}


/*
 * Print the inode information in the format that the mactimes program expects
 */

static u_int8_t
print_inode_mac(FS_INFO *fs, INUM_T inum, FS_INODE *fs_inode, int flags,
			        char *unused_context)
{
	char ls[12];

	/* ADD NAME IF WE GOT IT */
	printf("0|<%s-%s%s%s-%lu>|0|%lu|%d|", image, 
	  (fs_inode->name)?fs_inode->name->name:"",
	  (fs_inode->name)?"-":"",
	  (flags & FS_FLAG_META_ALLOC)?"alive":"dead", (ULONG)inum, 
	  (ULONG)inum, (int)fs_inode->mode);

	/* Print the "ls" mode in ascii format */
	make_ls(fs_inode->mode, ls, 12);

	if (sec_skew != 0) {
		fs_inode->mtime -= sec_skew;
		fs_inode->atime -= sec_skew;
		fs_inode->ctime -= sec_skew;
	}

	printf("%s|%d|%d|%d|0|%llu|%lu|%lu|%lu|%lu|0\n", 
	  ls,(int)fs_inode->nlink, (int)fs_inode->uid,
	  (int)fs_inode->gid, (ULLONG)fs_inode->size, 
	  (ULONG)fs_inode->atime, (ULONG)fs_inode->mtime,
	  (ULONG)fs_inode->ctime, (ULONG)fs->block_size);

	if (sec_skew != 0) {
		fs_inode->mtime -= sec_skew;
		fs_inode->atime -= sec_skew;
		fs_inode->ctime -= sec_skew;
	}

	return WALK_CONT;
}

/* main - open file system, list inode info */

int     main(int argc, char **argv)
{
    char   *start;
    char   *last;
    INUM_T  istart;
    INUM_T  ilast;
    int     ch;
    int     flags = 0;
#define ARG_O	0x1
#define ARG_R	0x2
#define ARG_M	0x4
	int		argflags = 0;
    char   *fstype = DEF_FSTYPE;
	FS_INFO *fs;
	char *io_subsys=NULL;
	char *io_subsys_opts=NULL;
	IO_INFO *io=NULL;

    progname = argv[0];

    /*
     * Provide convenience options for the most commonly selected feature
     * combinations.
     */
    while ((ch = getopt(argc, argv, "aAef:i:lLomrs:vVzZ")) > 0) {
	switch (ch) {
	default:
	    usage();
	case 'e':
	    flags |= ~0;
	    break;
	case 'f':
	    fstype = optarg;
	    break;
	case 'i':
	  io_subsys=optarg;
	  break;
    case 'm':
		argflags |= ARG_M;
		break;
	case 'o':
		flags |= (FS_FLAG_META_ALLOC | FS_FLAG_META_UNLINK);
		argflags |= ARG_O;
	    break;
	case 'r':
		argflags |= ARG_R;
	    break;
	case 's':
		sec_skew = atoi(optarg);
		break;
	case 'v':
	    verbose++;
	    logfp = stderr;
	    break;
	case 'V':
		print_version();
		exit(0);

	    /*
	     * Provide fine controls to tweak one feature at a time.
	     */
	case 'a':
	    flags |= FS_FLAG_META_ALLOC;
	    flags &= ~FS_FLAG_META_UNALLOC;
	    break;
	case 'A':
	    flags |= FS_FLAG_META_UNALLOC;
	    flags &= ~FS_FLAG_META_ALLOC;
	    break;
	case 'l':
	    flags |= FS_FLAG_META_LINK;
	    flags &= ~FS_FLAG_META_UNLINK;
	    break;
	case 'L':
	    flags |= FS_FLAG_META_UNLINK;
	    flags &= ~FS_FLAG_META_LINK;
	    break;
	case 'z':
	    flags |= FS_FLAG_META_UNUSED;
	    flags &= ~FS_FLAG_META_USED;
	    break;
	case 'Z':
	    flags |= FS_FLAG_META_USED;
	    flags &= ~FS_FLAG_META_UNUSED;
	    break;
	}
    }

    if (optind >= argc)
		usage();

    	/* User chose to set the io_subsystem */
	if(io_subsys) {
	  io=io_open(io_subsys);
	} else {
	  /* If the user did not specify a subsystem, we choose the standard one */
	  io=io_open("standard");
	};
	
	if(!io) {
	  error("Could not set io subsystem %s",io_subsys);
	};
	
    /*
     * Open the file system - Using the IO subsystem
	 *
	 * Open first so that the fstype parsing will be done before we rely
	 * on it in the next step
	 *
     */
	image = argv[optind];
	fs = fs_open(image, fstype);

	/* NTFS uses alloc and link different than UNIX so change
	 * the default behavior
	 *
	 * The link value can be > 0 on deleted files (even when closed)
	 */

	/* NTFS and FAT have no notion of deleted but still open */
	if ((argflags & ARG_O) &&
	  (((fs->ftype & FSMASK) == NTFS_TYPE) || 
	   ((fs->ftype & FSMASK) == FATFS_TYPE)) ) {
		printf ("Error: '-o' argument does not work with NTFS and FAT images\n");
		return 1;
	}

	/* removed inodes (default behavior) */
	if ((argflags & ARG_R) || (flags == 0)) {
		if (((fs->ftype & FSMASK) == NTFS_TYPE) ||
		  ((fs->ftype & FSMASK) == FATFS_TYPE)) 
			flags |= (FS_FLAG_META_USED | FS_FLAG_META_UNALLOC);
		else 
			flags |= (FS_FLAG_META_USED | FS_FLAG_META_UNLINK);
	}

	/* If neither of the flags in a family are set, then set both 
	 *
     * Apply rules for default settings. Assume a "don't care" condition when
     * nothing is explicitly selected from a specific feature category.
	 */
    if ((flags & (FS_FLAG_META_ALLOC | FS_FLAG_META_UNALLOC)) == 0)
		flags |= FS_FLAG_META_ALLOC | FS_FLAG_META_UNALLOC;

    if ((flags & (FS_FLAG_META_LINK | FS_FLAG_META_UNLINK)) == 0) 
		flags |= FS_FLAG_META_LINK | FS_FLAG_META_UNLINK;

    if ((flags & (FS_FLAG_META_USED | FS_FLAG_META_UNUSED)) == 0)
		flags |= FS_FLAG_META_USED | FS_FLAG_META_UNUSED;


    /*
     * Print the time machine header.
     */
	if (argflags & ARG_M) {
		char *tmpptr;
		/* If this is ported to Windows this will have to be changed to \ */
		tmpptr = strrchr (image, '/');	
		if (tmpptr)
			image = ++tmpptr;

		print_header_mac();
	}
	else {
		print_header(fs, image);
	}

    /*
     * List the named inodes.
     */
    optind++;
    if (optind < argc) {
		while ((start = argv[optind]) != 0) {
			last = split_at(start, '-');
			istart = (*start ? atoinum(start) : fs->first_inum);
			if (istart < fs->first_inum)
				istart = fs->first_inum;

			ilast = (!last ? istart : *last ? atoinum(last) : fs->last_inum);
			if (ilast > fs->last_inum)
				ilast = fs->last_inum;

			if (argflags & ARG_M) 
				fs->inode_walk(fs, istart, ilast, flags, print_inode_mac, 
				  (char *) 0);
			else
				fs->inode_walk(fs, istart, ilast, flags, print_inode, 
				  (char *) 0);
			optind++;
		}
    }

    /*
     * List all inodes, subject to the specified restrictions.
     */
    else {
		if (argflags & ARG_M) 
			fs->inode_walk(fs, fs->first_inum, fs->last_inum, flags, 
			  print_inode_mac, (char *)0);
		else
			fs->inode_walk(fs, fs->first_inum, fs->last_inum, flags, 
			  print_inode, (char *)0);
    }

    fs->close(fs);
    exit(0);
}
