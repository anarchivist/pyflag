/*
** dcalc
** The Sleuth Kit 
**
** Calculates the corresponding block number between 'dls' and 'dd' images
** when given an 'dls' block number, it determines the block number it
** had in a 'dd' image.  When given a 'dd' image, it determines the
** value it would have in a 'dls' image (if the block is unallocated)
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003 Brian Carrier. All Rights reserved
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc. All Rights reserved
**
**
** TCTUTILs
** Brian Carrier [carrier@cerias.purdue.edu]
** Copyright (c) 2001 Brian Carrier.  All rights reserved
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions are
** met:
**
** 1. Redistributions of source code must retain the above copyright notice,
**    this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright
**    notice, this list of conditions and the following disclaimer in the
**    documentation and/or other materials provided with the distribution.
** 3. The name of the author may not be used to endorse or promote
**    products derived from this software without specific prior written
**    permission.
**
**
** THIS SOFTWARE IS NOT AFFILIATED WITH PURDUE UNIVERSITY OR THE CENTER FOR
** EDUCATION IN INFORMATION ASSURANCE AND SECURITY (CERIAS) AND THEY BEAR
** NO RESPONSIBILITY FOR ITS USE OR MISUSE.
**
**
** THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
** WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
** MERCHANTABILITY AND FITNESS FOR ANY PARTICULAR PURPOSE.
**
** IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
** INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
** (INCLUDING, BUT NOT LIMITED TO, LOSS OF USE, DATA, OR PROFITS OR
** BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
** WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
** OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
** ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**
*/
#include "fs_tools.h"
#include "error.h"
#include "split_at.h"

FILE   *logfp;

static int count;
static int uncnt = 0;

char *progname;

#define CALC_DD		0x1
#define CALC_DLS	0x2
#define CALC_SLACK	0x4

static void 
usage(char *prog)
{
	printf("usage: %s [-du unit_addr] [-vV] [-f fstype] dd_image\n", prog);
	printf("Slowly calculates the opposite block number\n");
	printf("\tOne of the following must be given:\n");
	printf("\t-d: The given address is from a 'dd' image \n");
	printf("\t-s: The given address is from a 'dls -s' (slack) image\n");
	printf("\t-u: The given address is from a 'dls' (unallocated) image\n");
	printf("\t-v: verbose output to stderr\n");
	printf("\t-V: Print version\n");
	printf("\t-f fstype: Image file system type\n");
	printf("Supported file system types:\n");
	fs_print_types();

	exit(1);
}


/* function used when -d is given
**
** keeps a count of unallocated blocks seen thus far
**
** If the specified block is allocated, an error is given, else the
** count of unalloc blocks is given 
**
** This is called for all blocks (alloc and unalloc)
*/
static u_int8_t
count_dd(FS_INFO *fs, DADDR_T addr, char *buf, int flags, char *ptr)
{
	if (flags & FS_FLAG_DATA_UNALLOC) 
		uncnt++;

	if (count-- == 0) {
		if (flags & FS_FLAG_DATA_UNALLOC) 
			printf("%d\n", uncnt);
		else
			printf("ERROR: unit is allocated, it will not be in an dls image\n");

		fs->close(fs);
		exit(0);
	}
	return WALK_CONT;
}

/*
** count how many unalloc blocks there are.
**
** This is called for unalloc blocks only
*/
static u_int8_t
count_dls(FS_INFO *fs, DADDR_T addr, char *buf, int flags, char *ptr)
{
	if (count-- == 0) {
		printf("%lu\n", (ULONG)addr);
		fs->close(fs);
		exit(0);
	}
	return WALK_CONT;
}


/* SLACK SPACE  call backs */
static OFF_T flen;

static u_int8_t
count_slack_file_act(FS_INFO *fs, DADDR_T addr, char *buf, int size,
  int flags, char *ptr)
{

	if (verbose)
		fprintf (logfp,
		  "count_slack_file_act: Remaining File:  %lu  Buffer: %lu\n",
		  (ULONG)flen, (ULONG)size);

	/* This is not the last data unit */
	if (flen >= size) {
		flen -= size;
	}
	/* We have passed the end of the allocated space */
	else if (flen == 0) {
		if (count-- == 0) {
			printf("%lu\n", (ULONG)addr);
			fs->close(fs);
			exit(0);
		}
	}
	/* This is the last data unit and there is unused space */
	else if (flen < size) {
		if (count-- == 0) {
			printf("%lu\n", (ULONG)addr);
			fs->close(fs);
			exit(0);
		}
		flen = 0;
	}

	return WALK_CONT;
}

static u_int8_t
count_slack_inode_act(FS_INFO *fs, INUM_T inum, FS_INODE *fs_inode, int flags,
  char *ptr)
{

	if (verbose)
		fprintf (logfp,
		  "count_slack_inode_act: Processing meta data: %lu\n",
		  (ULONG)inum);

	/* We will now do a file walk on the content */
	if ((fs->ftype & FSMASK) != NTFS_TYPE) {
		flen = fs_inode->size;
		fs->file_walk(fs, fs_inode, 0, 0,
		  FS_FLAG_FILE_SLACK | FS_FLAG_FILE_NOABORT,
		  count_slack_file_act, ptr);
	}

	/* For NTFS we go through each non-resident attribute */
	else {
		FS_DATA *fs_data = fs_inode->attr;

		while ((fs_data) && (fs_data->flags & FS_DATA_INUSE)) {

			if (fs_data->flags & FS_DATA_NONRES) {
				flen = fs_data->size;
				fs->file_walk(fs, fs_inode, fs_data->type, fs_data->id,
				  FS_FLAG_FILE_SLACK | FS_FLAG_FILE_NOABORT,
				  count_slack_file_act, ptr);
			}

			fs_data = fs_data->next;
		}
	}
	return WALK_CONT;
}






int 
main(int argc, char **argv)
{
	char   *fstype = DEF_FSTYPE;
	char 	ch, type = 0;
	FS_INFO 	*fs;
	count = -1;
	progname = argv[0];

    while ((ch = getopt(argc, argv, "d:f:s:u:vV")) > 0) {
        switch (ch) {
        case '?':
        default:
            usage(argv[0]);

		case 'd':
			type |= CALC_DD;
			count = atoi(optarg);
			break;

        case 'f':
			fstype = optarg;
			break;

		case 's':
			type |= CALC_SLACK;
			count = atoi(optarg);
			break;

		case 'u':
			type |= CALC_DLS;
			count = atoi(optarg);
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

	if (((optind+1) != argc) || (!type) || (count < 0))
		usage(argv[0]);

	if ( (type & CALC_DD) && (type & CALC_DLS) && (type & CALC_SLACK) ) {
		printf("Only one block type can be given\n");
		usage(argv[0]);
	}
	progname = argv[0];

    fs = fs_open(argv[optind++], fstype);

	if (type == CALC_DLS) {
		fs->block_walk(fs, fs->first_block, fs->last_block,
		  (FS_FLAG_DATA_UNALLOC | FS_FLAG_DATA_ALIGN | 
		  FS_FLAG_DATA_META | FS_FLAG_DATA_CONT),
		  count_dls, (char *) fs);
	}
	else if (type == CALC_DD) {
		fs->block_walk(fs, fs->first_block, fs->last_block,
		  (FS_FLAG_DATA_ALLOC | FS_FLAG_DATA_UNALLOC | 
		  FS_FLAG_DATA_ALIGN | FS_FLAG_DATA_META | FS_FLAG_DATA_CONT),
		  count_dd, (char *) fs);
	}
	else if (type == CALC_SLACK) {
		fs->inode_walk(fs, fs->first_inum, fs->last_inum,
		  (FS_FLAG_META_ALLOC | FS_FLAG_META_USED | FS_FLAG_META_LINK),
		  count_slack_inode_act, (char *)0);
	}

    fs->close(fs);

	/* We get here if the count is still > 0 */
	printf("Block too large\n");

    exit(0);
}
