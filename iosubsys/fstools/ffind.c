/*
** ffind  (file find)
** The Sleuth Kit 
**
** Find the file that uses the specified inode (including deleted files)
** 
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003-2004 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
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

/* NTFS has an optimized version of this function */
extern void ntfs_find_file (FS_INFO *, INUM_T, u_int32_t, u_int32_t, int, 
  FS_DENT_WALK_FN, char *);

void 
usage(char *myProg) 
{
	printf("usage: %s [-aduvV] [-f fstype] image inode\n", myProg);
	printf("\t-a: Find all occurrences\n");
	printf("\t-d: Find deleted entries ONLY\n");
	printf("\t-u: Find undeleted entries ONLY\n");
	printf("\t-v: Verbose output to stderr\n");
	printf("\t-V: Print version\n");
	printf("\t-f fstype: Image file system type\n");
	printf("Supported file system types:\n");
	fs_print_types();

	exit(1);
}

FILE *logfp;

/* local flags */
static unsigned char localflags;
#define FIND_ALL 0x1

static unsigned int inode = 0;
static unsigned char found = 0;

static u_int8_t
find_file (FS_INFO *fs, FS_DENT *fs_dent, int flags, char *ptr) 
{
	/* We found it! */
	if (fs_dent->inode == inode) {
		found = 1;
		if (flags & FS_FLAG_NAME_UNALLOC)
			printf("* ");

		printf("/%s%s\n", fs_dent->path, fs_dent->name);

		if (!(localflags & FIND_ALL)) {
			fs->close(fs);
			exit(0);
		}
	}
	return WALK_CONT;
}


int 
main(int argc, char **argv)
{
	char *fstype = DEF_FSTYPE;
	int flags = FS_FLAG_NAME_RECURSE;
	char ch;
	FS_INFO	*fs;
	extern int optind;
	u_int32_t type, id;
	char *dash;
	progname= argv[0];

	while ((ch = getopt(argc, argv, "adf:uvV")) > 0) {
		switch (ch) {
		case 'a':
			localflags |= FIND_ALL;
			break;
		case 'd':
			flags |= FS_FLAG_NAME_UNALLOC;
			break;
        case 'f':
            fstype = optarg;
            break;
		case 'u':
			flags |= FS_FLAG_NAME_ALLOC;
			break;
		case 'v':
			verbose++;
			logfp = stderr;
			break;
		case 'V':
			print_version();
			exit(0);
		case '?':
		default: 
			usage(argv[0]);
		}
	}

	/* if the user did not specify either of the alloc/unalloc flags
	** then show them all
	*/
	if ((!(flags & FS_FLAG_NAME_ALLOC)) && (!(flags & FS_FLAG_NAME_UNALLOC)))
		flags |= (FS_FLAG_NAME_ALLOC | FS_FLAG_NAME_UNALLOC);
		
	if (optind+2 != argc)
		usage(argv[0]);


	/* open image */
	fs = fs_open(argv[optind++], fstype);


	/* we have the inum-type or inum-type-id format */
	type = 0;
	id = 0;
	if ((dash = strchr(argv[optind], '-')) != NULL) {
		char *dash2;

		*dash = '\0'; 
		dash++;

		/* We have an id */
		if ((dash2 = strchr(dash, '-')) != NULL) {
			*dash2 = '\0';
			dash2++;

			id = atoi(dash2);
		}
		type = atoi(dash);
	}
	inode = atoi(argv[optind]);

	if (inode < fs->first_inum) {
		printf ("Inode is too small for image (%lu)\n", (ULONG)fs->first_inum);
		return 1;
	}
	if (inode > fs->last_inum) {
		printf ("Inode is too large for image (%lu)\n", (ULONG)fs->last_inum);
		return 1;
	}

	found = 0;

	/* Since we start the walk on the root inode, then this will not show
	** up in the above functions, so do it now
	*/
	if (inode == fs->root_inum) {
		if (flags & FS_FLAG_NAME_ALLOC)  {
			printf("/\n");
			found = 1;

			if (!(localflags & FIND_ALL)) 
				return 0;
		}
	}


	if ((fs->ftype & FSMASK) == NTFS_TYPE) {
		ntfs_find_file(fs, inode, type, id, flags, find_file, (char *)0);
	}
	else {
		fs->dent_walk(fs, fs->root_inum, flags, find_file, (char *)0);
	}

	if (!found) {

		/* With FAT, we can at least give the name of the file and call
		 * it orphan 
		 */
		if ((fs->ftype & FSMASK) == FATFS_TYPE) {
			FS_INODE *fs_inode = fs->inode_lookup(fs, inode);
			if (fs_inode->name != NULL) {
				if (fs_inode->flags & FS_FLAG_NAME_UNALLOC)
					printf("* ");
				printf ("%s/%s\n", ORPHAN_STR, fs_inode->name->name);
			}
		}
		else {
			printf("inode not currently used\n");
		}
	}

	fs->close(fs);

	return 0;
}

