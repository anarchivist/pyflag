/*
** ifind (inode find)
** The Sleuth Kit
**
** Given an image  and block number, identify which inode it is used by
** 
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003-2004 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
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
#include "mymalloc.h"

static DADDR_T block = 0;			/* the block to find */
static INUM_T parinode = 0;
static INUM_T curinode;			/* the inode being analyzed */

static u_int32_t curtype;		/* the type currently being analyzed: NTFS */
static u_int16_t curid;


static char *cur_dir;
static char *cur_attr;
static char *path;

FILE *logfp;

#define FIND_ALL	0x01
#define FOUND_ONE	0x02
#define USE_PATH	0x04
#define USE_DATA	0x08
#define USE_PAR		0x10
#define PAR_LONG	0x20
static u_int8_t localflags;

static void usage(char *prog) {
	printf("usage: %s [-alvV] [-f fstype] [-d unit_addr] [-n file] [-p par_addr] [-z ZONE] image\n", prog);
	printf("\t-a: find all inodes\n");
	printf("\t-d unit_addr: Find the meta data given the data unit\n");
	printf("\t-l: long format when -p is given\n");
	printf("\t-n file: Find the meta data given the file name\n");
	printf("\t-p par_addr: Find UNALLOCATED MFT entries given the parent's meta address (NTFS only)\n");
	printf("\t-v: Verbose output to stderr\n");
	printf("\t-V: Print version\n");
	printf("\t-z ZONE: Time zone setting when -l -p is given\n");
	printf("\t-f fstype: Image file system type\n");
	printf("Supported file system types:\n");
    fs_print_types();

	exit(1);
}



FS_DENT *fs_dent;

/* dent call back for finding unallocated files based on parent directory
 */
static u_int8_t
find_inode_parent(FS_INFO *fs, INUM_T inum, FS_INODE *fsi, int flags, char *ptr) 
{
	FS_NAME *fs_name;

	/* go through each file name structure */
	fs_name = fsi->name;
	while (fs_name) {
		if (fs_name->par_inode == parinode) {

			fs_dent->fsi = fsi;
			fs_dent->inode = inum;
			strncpy(fs_dent->name, fs_name->name, fs_dent->maxnamlen);
			if (localflags & PAR_LONG) {
				fs_dent_print_long(stdout, fs_dent, FS_FLAG_NAME_UNALLOC, fs, NULL);
			}
			else  {
				fs_dent_print(stdout, fs_dent, FS_FLAG_NAME_UNALLOC, fs, NULL);
				printf("\n");
			}
			fs_dent->fsi = NULL;
			localflags |= FOUND_ONE;
		}
		fs_name = fs_name->next;
	}

	return WALK_CONT;
}




/* 
 * dent_walk for finding the inode based on path
 *
 * This is run from the main function and from this function when
 * the needed directory is found
 */
static u_int8_t
find_inode_path (FS_INFO *fs, FS_DENT *fs_dent, int flags, char *ptr)
{

	/* This crashed because cur_dir was null, but I'm not sure how
	 * it got that way, so this was added
	 */
	if (cur_dir == NULL) {
		fprintf(stderr, 
		  "cur_dir is null: Please run with '-v' and send output to developers\n");
		return WALK_STOP;
	}

	/* 
	 * Check if this is the name that we are currently looking for,
	 * as identified in 'cur_dir'
	 *
	 * All non-matches will return from these checks
	 */

	if (((fs->ftype & FSMASK) == EXTxFS_TYPE) ||
	  ((fs->ftype & FSMASK) == FFS_TYPE)) {
		if (strcmp(fs_dent->name, cur_dir) != 0) {
			return WALK_CONT;
		}
	}

	/* NTFS gets a case insensitive comparison */
	else if ((fs->ftype & FSMASK) == NTFS_TYPE) {
		if (strcasecmp(fs_dent->name, cur_dir) != 0) {
			return WALK_CONT;
		}

		/*  ensure we have the right attribute name */
		if (cur_attr != NULL) {
			int fail = 1;

			if (fs_dent->fsi) {
	           	FS_DATA *fs_data;
				fs_data = fs_dent->fsi->attr;

				while ((fs_data) && (fs_data->flags & FS_DATA_INUSE)) {
					if (strcasecmp(fs_data->name, cur_attr) == 0) {
						fail = 0;
						break;
					}
					fs_data = fs_data->next;
				}
			}
			if (fail) {
				printf ("Attribute name (%s) not found in %s: %lu\n",
			  	  cur_attr, cur_dir, (ULONG)fs_dent->inode);

				return WALK_STOP;
			}
		}
	}
	/* FAT is a special case because there could be the short name
	 * in parens - abcdefasdfsdfa (abc..~1.sd)
	 */
	else if ((fs->ftype & FSMASK) == FATFS_TYPE) {

		/* try the full match first */
		if (strcasecmp(fs_dent->name, cur_dir) == 0) {
		
		}
		/* Do a quick 2 char sanity check */
		else if (strncasecmp(fs_dent->name, cur_dir, 2) != 0) {
			return WALK_CONT;
		}
		/* Check if there is a short name by looking for the
		 * paren at the end */
		else if (fs_dent->name[strlen(fs_dent->name)-1] == ')') {
			char *sh_ptr;
			int long_len = 0, sh_len = 0;

			/* Get the beginning of the short name */
			sh_ptr = strrchr (fs_dent->name, '(');
			if (sh_ptr == NULL)  {
				fprintf(stderr, "ifind: error parsing FAT name (no '('): %s\n", 
				  fs_dent->name);
				return WALK_CONT;
			}

			/* Advance to the first letter in the name */
			sh_ptr++;

			/* Length of long name - 2 for ' (' */
			long_len = (int)sh_ptr - (int)fs_dent->name - 2;

			/* Length of Short name - 3 for ' (' and ')' */
			sh_len = strlen (fs_dent->name) - long_len - 3;

			/* Sanity Check - there should be a space after the lfn */
			if (fs_dent->name[long_len] != ' ') {
				fprintf(stderr, "ifind: error parsing FAT name: %s\n", 
				  fs_dent->name);
				return WALK_CONT;
			}

			/* Check if the long name has the same length as the target */
			if (strlen(cur_dir) == long_len) {
				if (strncasecmp(fs_dent->name, cur_dir, long_len) != 0) {
					return WALK_CONT;
				}
			}
			/* check if the short name has the same length */
			else if (strlen(cur_dir) == sh_len) {
				if (strncasecmp(sh_ptr, cur_dir, sh_len) != 0) {
					return WALK_CONT;
				}
			}
			/* The length is not the same, so just return */
			else {
				return WALK_CONT;
			}
		}
		/* No short name at the end, so verify it is the right size */
		else if (strlen(fs_dent->name) < 13) {
			if (strcasecmp(fs_dent->name, cur_dir) != 0) {
				return WALK_CONT;
			}
		}
		/* No short name and too long - error */
		else {
			fprintf(stderr, "ifind: Error parsing FAT name: %s\n", 
			  fs_dent->name);
			return WALK_CONT;
		}
	}
		
	/* Get the next directory or file name */
	cur_dir = (char *)strtok (NULL, "/");
	cur_attr = NULL;

	if (verbose)
		fprintf(stderr, "Found it (%s), now looking for %s\n", 
		  fs_dent->name, cur_dir);

	/* That was the last one */
	if (cur_dir == NULL) {
		printf  ("%lu\n", (ULONG)fs_dent->inode);
		localflags |= FOUND_ONE;
		return WALK_STOP;
	}

	/* if it is an NTFS image with an ADS in the name, then
	 * break it up 
	 */
	if (((fs->ftype & FSMASK) == NTFS_TYPE) && 
	  ((cur_attr = strchr(cur_dir, ':')) != NULL ) ) {
		*cur_attr = '\0';
		cur_attr++;
	}

	/* it is a directory so we can recurse */
	if ((fs_dent->fsi->mode & FS_INODE_FMT) == FS_INODE_DIR) {

		fs->dent_walk(fs, fs_dent->inode,
		  FS_FLAG_NAME_ALLOC | FS_FLAG_NAME_UNALLOC,
		  find_inode_path, (char *) 0);
	}

	/* The name was correct, but it was not a directory */
	else {
		printf ("Invalid path (%s is a file)\n",
		  fs_dent->name);
	}

	return WALK_STOP;
}

/*
 * file_walk action for non-ntfs
 */
static u_int8_t
find_inode_file_act(FS_INFO *fs, DADDR_T addr, char *buf, 
  int size, int flags, char *ptr)
{
	/* Drop references to block zero (sparse)
	 * This becomes an issue with fragments and looking for fragments
	 * within the first block.  They will be triggered by sparse 
	 * entries, even though the first block can not be allocated
	 */
	if (!addr)
		return WALK_CONT;

	if ((block >= addr) && 
	  (block < (addr + (size + fs->block_size - 1) / fs->block_size))) {
		printf("%i\n", (int)curinode);

		if (!(localflags & FIND_ALL)) {
			fs->close(fs);
			exit (0);
		}
		localflags |= FOUND_ONE;
	}
	return WALK_CONT;
}


/* 
 * file_walk action callback for ntfs  
 *
 */
static u_int8_t
find_inode_ntfs_file(FS_INFO *fs, DADDR_T addr, char *buf, 
  int size, int flags, char *ptr)
{
	if (addr == block) {	
		printf("%i-%i-%i\n", (int)curinode, (int)curtype, (int)curid);

		if (!(localflags & FIND_ALL)) {
			fs->close(fs);
			exit (0);
		}
		localflags |= FOUND_ONE;
	}
	return WALK_CONT;
}



/*
** find_inode
**
** Callback action for inode_walk
*/
static u_int8_t
find_inode(FS_INFO *fs, INUM_T inum, FS_INODE *fsi, int flags, char *ptr) 
{
	int file_flags = (FS_FLAG_FILE_AONLY | FS_FLAG_FILE_NOABORT);

	/* If the meta data structure is unallocated, then set the recovery flag */
	if (flags & FS_FLAG_META_UNALLOC)
		file_flags |= FS_FLAG_FILE_RECOVER;

	curinode = inum;

	/* NT Specific Stuff: search all ADS */
	if ((fs->ftype & FSMASK) == NTFS_TYPE) {
		FS_DATA *data = fsi->attr;

		file_flags |= FS_FLAG_FILE_SLACK;
		while ((data) && (data->flags & FS_DATA_INUSE)) {
			curtype = data->type;
			curid = data->id;
			if (data->flags & FS_DATA_NONRES) {
				fs->file_walk(fs, fsi, data->type, data->id, file_flags, 
				  find_inode_ntfs_file, ptr);
			}
			data = data->next;
		}
		return WALK_CONT;
	}
	else if ((fs->ftype & FSMASK) == FATFS_TYPE) {
		file_flags |= (FS_FLAG_FILE_SLACK | FS_FLAG_FILE_NOID);
		fs->file_walk(fs, fsi, 0, 0, file_flags, 
		  find_inode_file_act, ptr);
	}
	/* UNIX do not need the SLACK flag because they use fragments - if the
	 * SLACK flag exists then any unused fragments in a block will be 
	 * correlated with the incorrect inode
	 */
	else {
		file_flags |= (FS_FLAG_FILE_NOID);
		fs->file_walk(fs, fsi, 0, 0, file_flags, 
		  find_inode_file_act, ptr);
	}

	return WALK_CONT;
}


/*
 * if the block is a meta data block, then report that, otherwise
 * this is where we say that the inode was not found
 */
static u_int8_t
block_act (FS_INFO *fs, DADDR_T addr, char *buf, int flags, char *ptr)
{
	if (flags & FS_FLAG_DATA_META)
		printf("Meta Data\n");
	else
		printf("Inode not found\n");

	return WALK_STOP;
}

int
main(int argc, char **argv) 
{
	char   *fstype = DEF_FSTYPE;

	FS_INFO	*fs;
	char ch;
	extern int optind;
	progname = argv[0];

	localflags = 0;

	while ((ch = getopt(argc, argv, "ad:f:ln:p:vVz:")) > 0) {  
		switch (ch) {
		 case 'a':
			localflags |= FIND_ALL;
			break;
		case 'd':
			if (localflags & (USE_PAR | USE_PATH)) {
				fprintf(stderr, "error: only one address type can be given\n");
				usage(argv[0]);
			}
			localflags |= USE_DATA;
			block = atoi(optarg);
			break;
	    	case 'f':
			fstype = optarg;
			break;
	    	case 'l':
			localflags |= PAR_LONG;
			break;
		case 'n':
			if (localflags & (USE_PAR | USE_DATA)) {
				fprintf(stderr, "error: only one address type can be given\n");
				usage(argv[0]);
			}
			localflags |= USE_PATH;
			path = mymalloc (strlen (optarg) + 1);
			strncpy (path, optarg, strlen(optarg) + 1);
			break;
		case 'p':
			if (localflags & (USE_PATH | USE_DATA)) {
				fprintf(stderr, "error: only one address type can be given\n");
				usage(argv[0]);
			}
			localflags |= USE_PAR;
			parinode = atoi(optarg);
			break;
		case 'v':
			verbose++;
			logfp = stderr;
			break;
		case 'V':
			print_version();
			exit(0);
		case 'z':
		{
			char envstr[32];
			snprintf(envstr, 32, "TZ=%s", optarg);
			if (0 != putenv(envstr)) {
				error ("error setting environment");
			}

			/* we should be checking this somehow */
			tzset();
			break;
		}
		case '?':  
			default:
			usage(argv[0]);
		}
	}
	
	if ((optind + 1) !=  argc) {
		fprintf(stderr, "Missing image name or too many arguments\n");
		usage(argv[0]);
	}

	if (0 == (localflags & (USE_PATH | USE_DATA | USE_PAR))) {
		fprintf(stderr, "-d, -n, or -p must be given\n");
		exit(1);
	}

	fs = fs_open(argv[optind++], fstype);

	if (localflags & USE_PATH) {

		if (localflags & FIND_ALL) {
			fprintf (stderr, "-a and -n must not be given together\n");
			exit(1);
		}

		cur_dir = (char *)strtok(path, "/");
		cur_attr = NULL;

		/* If there is no token, then only a '/' was given */
		if (!cur_dir) {
			printf("%lu\n", (ULONG)fs->root_inum);
			return 0;
		}

		/* If this is NTFS, ensure that we take out the attribute */
		if (((fs->ftype & FSMASK) == NTFS_TYPE) && 
		  ((cur_attr = strchr(cur_dir, ':')) != NULL ) ) {
			*cur_attr = '\0';
			cur_attr++;
		}

		if (verbose)
			fprintf(stderr, "Looking for %s\n", cur_dir);

		fs->dent_walk(fs, fs->root_inum,
	  	  FS_FLAG_NAME_ALLOC | FS_FLAG_NAME_UNALLOC,
		  find_inode_path, (char *) 0);

		if (0 == (localflags & FOUND_ONE)) {
			printf ("File not found: %s\n", cur_dir);
			exit (1);
		}

	}
	else if (localflags & USE_DATA) {


		if (block > fs->last_block) {
			fprintf(stderr, 
			  "Block %lu is larger than last block in image (%lu)\n",
			  (ULONG)block, (ULONG)fs->last_block);
			fs->close(fs);
			exit (1);
		}
		else if (block == 0) {
			printf("Inode not found\n");
			fs->close(fs);
			exit (1);
		}

		fs->inode_walk(fs, fs->first_inum, fs->last_inum,
	  	  FS_FLAG_META_LINK | FS_FLAG_META_UNLINK | 
	  	  FS_FLAG_META_ALLOC | FS_FLAG_META_UNALLOC | 
		  FS_FLAG_META_USED | FS_FLAG_META_UNUSED,
		  find_inode, (char *) 0);

		/* 
	 	 * If we did not find an inode yet, we call block_walk for the 
		 * block to find out the associated flags so we can identify it as
		 * a meta data block */
		if (0 == (localflags & FOUND_ONE)) {
			fs->block_walk(fs, block, block,
				FS_FLAG_DATA_UNALLOC | FS_FLAG_DATA_ALLOC | 
				FS_FLAG_DATA_META | FS_FLAG_DATA_CONT,
				block_act, (char *) 0);
		}
	}
	else if (localflags & USE_PAR) {
		if ((fs->ftype & FSMASK) != NTFS_TYPE) {
			fprintf(stderr, "-p works only with NTFS file systems\n");
			fs->close(fs);
			exit(1);
		}

		else if (parinode > fs->last_inum) {
			fprintf(stderr, 
			  "Meta data %lu is larger than last MFT entry in image (%lu)\n",
			  (ULONG)parinode, (ULONG)fs->last_inum);
			fs->close(fs);
			exit (1);
		}

		fs_dent = fs_dent_alloc(256);

		fs->inode_walk(fs, fs->first_inum, fs->last_inum,
	  	  FS_FLAG_META_LINK | FS_FLAG_META_UNLINK | 
	  	  FS_FLAG_META_UNALLOC | FS_FLAG_META_USED, 
		  find_inode_parent, (char *) 0);

		fs_dent_free(fs_dent);
	}

	fs->close(fs);

	exit (0);
}

