/*
** The Sleuth Kit
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003-2004 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
** renamed to have consistant name (was unrm)
**
** 
** Copyright (c) 1997,1998,1999, International Business Machines
** Corporation and others. All Rights Reserved.
**
*/

/* TCT:
 *
 * LICENSE
 *	This software is distributed under the IBM Public License.
 * AUTHOR(S)
 *	Wietse Venema
 *	IBM T.J. Watson Research
 *	P.O. Box 704
 *	Yorktown Heights, NY 10598, USA
 */

#include "fs_tools.h"
#include "error.h"
#include "split_at.h"

FILE   *logfp;

/* atoblock - convert string to block number */

DADDR_T atoblock(const char *str)
{
    char   *cp;
    DADDR_T addr;

    if (*str == 0)
	return (0);
    addr = STRTOUL(str, &cp, 0);
    if (*cp || cp == str)
	error("bad block number: %s", str);
    return (addr);
}

/* usage - explain and terminate */

static void usage()
{
    printf("usage: %s [-belvV] [-f fstype] device [block... ]\n", progname);
	printf("\t-b: no block padding\n");
	printf("\t-e: every block\n");
	printf("\t-l: print details in time machine list format\n");
	printf("\t-s: print slack space only (other flags are ignored\n");
	printf("\t-v: verbose to stderr\n");
	printf("\t-V: print version\n");
    printf("\t-f fstype: Image file system type\n");
	printf("Supported file system types:\n");
	fs_print_types();
	exit(1);
}



/* call backs for listing details */
static void
print_list_head(FS_INFO *fs, char *image)
{
    char    hostnamebuf[BUFSIZ];
    unsigned long now;
	char unit[32];
  
    if (gethostname(hostnamebuf, sizeof(hostnamebuf) - 1) < 0)
        error("gethostname: %m");
    hostnamebuf[sizeof(hostnamebuf) - 1] = 0;
    now = time((time_t *) 0);

    switch (fs->ftype & FSMASK) {
      case EXT2FS_TYPE:
      case FFS_TYPE:
		strncpy(unit, "fragment", 32);
        break;
      case FATFS_TYPE:
		strncpy(unit, "sector", 32);
        break;
      case NTFS_TYPE:
		strncpy(unit, "cluster", 32);
        break;
      default:
        printf("Unsupported File System\n");
        exit(1);
    }
	
    /*
     * Identify table type and table origin.
     */  
    printf("class|host|image|first_time|unit\n");
    printf("dls|%s|%s|%lu|%s\n", hostnamebuf, image, now, unit);

	printf("addr|alloc\n");
	return;
}

static u_int8_t
print_list(FS_INFO *fs, DADDR_T addr, char *buf, int flags, char *ptr)
{
	printf("%lu|%s\n", (ULONG)addr, (flags & FS_FLAG_DATA_ALLOC)?"a":"f");
	return WALK_CONT;
}





/* print_block - write data block to stdout */

static u_int8_t
print_block(FS_INFO *fs, DADDR_T addr, char *buf, int flags, char *ptr)
{
    if (verbose)
		fprintf(logfp, "write block %lu\n", (ULONG) addr);
    if (fwrite(buf, fs->block_size, 1, stdout) != 1)
		error("write stdout: %m");
	
	return WALK_CONT;
}





/* SLACK SPACE  call backs */
static OFF_T flen;

static u_int8_t
slack_file_act (FS_INFO *fs, DADDR_T addr, char *buf, int size,
  int flags, char *ptr)
{

	if (verbose)
		fprintf (logfp,
		  "slack_file_act: Remaining File:  %lu  Buffer: %lu\n",
		  (ULONG)flen, (ULONG)size);
	
	/* This is not the last data unit */
	if (flen >= size) {
		flen -= size;
	} 
	/* We have passed the end of the allocated space */
	else if (flen == 0) {
		fwrite(buf, size, 1, stdout);	
	}
	/* This is the last data unit and there is unused space */
	else if (flen < size) {
		/* Clear the used space and print it */
		memset(buf, 0, flen);
		fwrite(buf, size, 1, stdout);	
		flen = 0;
	}

	return WALK_CONT;
}

/* Call back for inode_walk */
static u_int8_t
slack_inode_act(FS_INFO *fs, INUM_T inum, FS_INODE *fs_inode, int flags,
  char *ptr)
{

	if (verbose)
		fprintf (logfp,
		  "slack_inode_act: Processing meta data: %lu\n",
		  (ULONG)inum);

	/* We will now do a file walk on the content and print the
	 * data after the specified size of the file */
	if ((fs->ftype & FSMASK) != NTFS_TYPE) {
		flen = fs_inode->size;
		fs->file_walk(fs, fs_inode, 0, 0, 
		  FS_FLAG_FILE_SLACK | FS_FLAG_FILE_NOABORT,
		  slack_file_act, ptr);
	}

	/* For NTFS we go through each non-resident attribute */
	else {
		FS_DATA *fs_data = fs_inode->attr;

		while ((fs_data) && (fs_data->flags & FS_DATA_INUSE)) {

			if (fs_data->flags & FS_DATA_NONRES) {
				flen = fs_data->size;
				fs->file_walk(fs, fs_inode, fs_data->type, fs_data->id, 
				  FS_FLAG_FILE_SLACK | FS_FLAG_FILE_NOABORT, 
				  slack_file_act, ptr);
			}

			fs_data = fs_data->next;
		}
	}

	return WALK_CONT;
}






/* main - open file system, list block info */

int     main(int argc, char **argv)
{
    FS_INFO *fs;
    char   *start;
    char   *last;
    DADDR_T bstart;
    DADDR_T blast;
    int     ch;
    int     flags = FS_FLAG_DATA_UNALLOC | FS_FLAG_DATA_ALIGN | FS_FLAG_DATA_META | FS_FLAG_DATA_CONT; 
    char   *fstype = DEF_FSTYPE;
	char	list = 0, slack = 0;

    progname = argv[0];

    while ((ch = getopt(argc, argv, "bef:lsvV")) > 0) {
	switch (ch) {
	default:
	    usage();
	case 'b':
	    flags &= ~FS_FLAG_DATA_ALIGN;
	    break;
	case 'e':
	    flags |= FS_FLAG_DATA_ALLOC;
	    break;
	case 'f':
	    fstype = optarg;
	    break;
	case 'l':
		list = 1;
	    break;
	case 's':
		slack = 1;
		break;
	case 'v':
	    verbose++;
	    logfp = stderr;
	    break;
	case 'V':
		print_version();
		exit(0);
	}
    }

    if (optind >= argc)
	usage();

    /*
     * Open the file system.
     */
    fs = fs_open(argv[optind++], fstype);


	if (slack) {


		if ((list) || (optind < argc)) {
			fprintf(stderr, "Other options igroned with the slack space flag, try again\n");
			exit (1);
		}

		/* get the info on each allocated inode */
		fs->inode_walk(fs, fs->first_inum, fs->last_inum, 
		  (FS_FLAG_META_ALLOC | FS_FLAG_META_USED | FS_FLAG_META_LINK),
		  slack_inode_act, (char *)0);
	
    	fs->close(fs);
		exit(0);
	}

	if (list)
		print_list_head(fs, argv[optind-1]);

    /*
     * Output the named data blocks, subject to the specified restrictions.
     */
    if (optind < argc) {
	while ((start = argv[optind]) != 0) {
	    last = split_at(start, '-');
	    bstart = (*start ? atoblock(start) : fs->first_block);
		if (bstart < fs->first_block)
			bstart = fs->first_block;

	    blast = (!last ? bstart : *last ? atoblock(last) : fs->last_block);
		if (blast > fs->last_block)
			blast = fs->last_block;

		if (list)
	    fs->block_walk(fs, bstart, blast, flags, print_list, (char *) fs);
		else
	    fs->block_walk(fs, bstart, blast, flags, print_block, (char *) fs);
	    optind++;
	}
    }

    /*
     * Output all blocks, subject to the specified restrictions.
     */
    else {
		if (list)
	    	fs->block_walk(fs, fs->first_block, fs->last_block, 
			   flags, print_list, (char *)fs);
		else
			fs->block_walk(fs, fs->first_block, fs->last_block,
		       flags, print_block, (char *) fs);
    }
    fs->close(fs);
    exit(0);
}
