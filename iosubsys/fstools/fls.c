/*
** fls
** The Sleuth Kit 
**
** Given an image and directory inode, display the file names and 
** directories that exist (both active and deleted)
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003-2004 Brian Carier.  All rights reserved
**
** TASK
** Copyright (c) 2002 @stake Inc.  All rights reserved
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
#include "fs_io.h"
#include "ntfs.h"

/* Time skew of the system in seconds */
static int32_t sec_skew = 0;


void usage(char *myProg) {
	printf("usage: %s [-adDFlpruvV] [-i IOsubsystem] [-f fstype] [-m dir/] [-z ZONE] [-s seconds] image [inode]\n", 
	  myProg);
    printf("\tIf [inode] is not given, the root directory is used\n");
	printf("\t-a: Display \".\" and \"..\" entries\n");
	printf("\t-d: Display deleted entries only\n");
	printf("\t-D: Display directory entries only\n");
	printf("\t-F: Display file entries only (NOTE: This was -f in TCTUTILs)\n");
	printf("\t-i: select IO Subsystems. Try help for a list of subsystems\n");
	printf("\t-l: Display long version (like ls -l)\n");
	printf("\t-m: Display output in mactime input format with\n");
	printf("\t      dir/ as the actual mount point of the image\n");
	printf("\t-o: Subsystem specific option. Try help for specific help\n");
	printf("\t-p: Display full path for each file\n");
	printf("\t-r: Recurse on directory entries\n");
	printf("\t-u: Display undeleted entries only\n");
	printf("\t-v: verbose output to stderr\n");
	printf("\t-V: Print version\n");
	printf("\t-z: Time zone of original machine (i.e. EST5EDT or GMT) (only useful with -l)\n");
	printf("\t-s seconds: Time skew of original machine (in seconds) (only useful with -l & -m)\n");
    printf("\t-f fstype: Image file system type\n");
	printf("Supported file system types:\n");
	fs_print_types();

	exit(1);
}

FILE *logfp;

/*directory prefix for printing mactime output */
static char *macpre = NULL;	

static int localFlags;

/* Local Flags */
#define LCL_DOT		0x001
#define LCL_LONG	0x002
#define LCL_FILE	0x004
#define LCL_DIR		0x008
#define LCL_FULL	0x010
#define LCL_MAC		0x020



/* this is a wrapper type function that takes care of the runtime
 * flags
 * 
 * fs_data should be set to NULL for all NTFS file systems
 */
static void
printit (FS_INFO *fs, FS_DENT *fs_dent, int flags, FS_DATA *fs_data)
{
	int i;

	if (!(localFlags & LCL_FULL)) {
		for (i=0; i<fs_dent->pathdepth;i++) 
			fprintf(stdout, "+");

		if (fs_dent->pathdepth)
			fprintf(stdout, " ");
	}


	if (localFlags & LCL_MAC) {
		if ((sec_skew != 0) && (fs_dent->fsi)) {
			fs_dent->fsi->mtime -= sec_skew;
			fs_dent->fsi->atime -= sec_skew;
			fs_dent->fsi->ctime -= sec_skew;
		}

		fs_dent_print_mac(stdout, fs_dent, flags, fs, fs_data, macpre);

		if ((sec_skew != 0) && (fs_dent->fsi)) {
			fs_dent->fsi->mtime += sec_skew;
			fs_dent->fsi->atime += sec_skew;
			fs_dent->fsi->ctime += sec_skew;
		}
	}

	else if (localFlags & LCL_LONG) {
		if ((sec_skew != 0) && (fs_dent->fsi)) {
			fs_dent->fsi->mtime -= sec_skew;
			fs_dent->fsi->atime -= sec_skew;
			fs_dent->fsi->ctime -= sec_skew;
		}

		if (LCL_FULL & localFlags) 
			fs_dent_print_long(stdout, fs_dent, flags, fs, fs_data);
		else {
			char *tmpptr = fs_dent->path;
			fs_dent->path = NULL;
			fs_dent_print_long(stdout, fs_dent, flags, fs, fs_data);
			fs_dent->path = tmpptr;
		}

		if ((sec_skew != 0) && (fs_dent->fsi)) {
			fs_dent->fsi->mtime += sec_skew;
			fs_dent->fsi->atime += sec_skew;
			fs_dent->fsi->ctime += sec_skew;
		}
	}
	else {
		if (LCL_FULL & localFlags) 
			fs_dent_print(stdout, fs_dent, flags, fs, fs_data);
		else {
			char *tmpptr = fs_dent->path;
			fs_dent->path = NULL;
			fs_dent_print(stdout, fs_dent, flags, fs, fs_data);
			fs_dent->path = tmpptr;
		}
		printf("\n");
	}
}


/* 
 * call back action function for dent_walk
 */
static u_int8_t
print_dent (FS_INFO *fs, FS_DENT *fs_dent, int flags, char *ptr) 
{

	/* only print dirs if LCL_DIR is set and only print everything
	** else if LCL_FILE is set (or we aren't sure what it is)
	*/
    if ( ((localFlags & LCL_DIR) &&
         ((fs_dent->fsi) &&
         ((fs_dent->fsi->mode & FS_INODE_FMT) == FS_INODE_DIR))) ||
        ((localFlags & LCL_FILE) &&
         (((fs_dent->fsi) &&
         ((fs_dent->fsi->mode & FS_INODE_FMT) != FS_INODE_DIR)) ||
         (!fs_dent->fsi)))) {


		/* Make a special case for NTFS so we can identify all of the
		 * alternate data streams!
		 */
		if (((fs->ftype & FSMASK) == NTFS_TYPE) && (fs_dent->fsi)) {

			FS_DATA *fs_data = fs_dent->fsi->attr;

			while ((fs_data) && (fs_data->flags & FS_DATA_INUSE)) {

				if (fs_data->type == NTFS_ATYPE_DATA) {
					mode_t mode = fs_dent->fsi->mode; 
					u_int8_t ent_type = fs_dent->ent_type;


					/* 
					 * A directory can have a Data stream, in which
					 * case it would be printed with modes of a
					 * directory, although it is really a file
					 * So, to avoid confusion we will set the modes
					 * to a file so it is printed that way.  The
					 * entry for the directory itself will still be
					 * printed as a directory
					 */

					if ((fs_dent->fsi->mode & FS_INODE_FMT) == FS_INODE_DIR) {
						
						/* we don't want to print the ..:blah stream if
						 * the -a flag was not given
						 */
						if ((fs_dent->name[0] == '.') && (fs_dent->name[1])
						  && (fs_dent->name[2] == '\0') && 
					      ((localFlags & LCL_DOT) == 0)) {
							fs_data = fs_data->next;
							continue;
						}

						fs_dent->fsi->mode &= ~FS_INODE_FMT;	
						fs_dent->fsi->mode |= FS_INODE_REG;	
						fs_dent->ent_type = FS_DENT_REG;
					}
					
					printit(fs, fs_dent, flags, fs_data);

					fs_dent->fsi->mode = mode; 
					fs_dent->ent_type = ent_type;
				}
				else if (fs_data->type == NTFS_ATYPE_IDXROOT) {

					/* If it is . or .. only print it if the flags say so,
					 * we continue with other streams though in case the 
					 * directory has a data stream 
					 */
					if (!((ISDOT (fs_dent->name) ) && 
					  ((localFlags & LCL_DOT) == 0)))
						printit(fs, fs_dent, flags, fs_data);
				}

				fs_data = fs_data->next;
			}

		}
		else {
			/* skip it if it is . or .. and we don't want them */
			if (!((ISDOT (fs_dent->name) ) && ((localFlags & LCL_DOT) == 0)))
				printit(fs, fs_dent, flags, NULL);
		}
	}
	return WALK_CONT;
}


int 
main(int argc, char **argv) 
{
	char *fstype = DEF_FSTYPE;
	int inode;
	int flags = FS_FLAG_NAME_ALLOC | FS_FLAG_NAME_UNALLOC;
	char ch;
	FS_INFO 	*fs;
	extern int optind;
	char *io_subsys=NULL;
	char *io_subsys_opts=NULL;
	IO_INFO *io=NULL;
	progname = argv[0];

	localFlags =  LCL_DIR | LCL_FILE;

	while ((ch = getopt(argc, argv, "adDf:Fi:m:lpro:s:uvVz:")) > 0) {
		switch (ch) {
		case '?':
		default: 
			usage(argv[0]);
		case 'a':
			localFlags |= LCL_DOT;
			break;
		case 'd':
			flags &= ~FS_FLAG_NAME_ALLOC;
			break;
		case 'D':
			localFlags &= ~LCL_FILE;
			localFlags |= LCL_DIR;
			break;
        case 'f':
            fstype = optarg;
            break;
		case 'F':
			localFlags &= ~LCL_DIR;
			localFlags |= LCL_FILE;
			break;
		case 'i':
		  io_subsys=optarg;
		  break;

		case 'l':
			localFlags |= LCL_LONG;
			break;
		case 'm':
			localFlags |= LCL_MAC;
			macpre = optarg;
			break;
		case 'p':
			localFlags |= LCL_FULL;
			break;
		case 'o':
		  io_subsys_opts=optarg;
		  break;
		case 'r':
			flags |= FS_FLAG_NAME_RECURSE;
			break;
		case 's':
			sec_skew = atoi(optarg);
			break;
		case 'u':
			flags &= ~FS_FLAG_NAME_UNALLOC;
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
            }
            break;

		}
	}

	/* only the image and optional inode are left */
	/*	if ((optind == argc) || ((optind+2) < argc))
		usage(argv[0]); */

	/* User chose to set the io_subsystem */
	if(io_subsys) {
	  io=io_open(io_subsys);
	} else {
	  /* If the user did not specify a subsystem, we choose the standard one */
	  io=io_open("standard");
	};
	
	if(!io) {
	  RAISE(E_GENERIC,NULL,"Could not set io subsystem %s",io_subsys);
	};
	
	/* Send the options to the subsystem */
	if(io_subsys_opts) {
	  io_parse_options(io,io_subsys_opts);
	};

	/* Set the full flag to print the full path name if recursion is
	** set and we are only displaying files or deleted files
	*/
	if ((flags & FS_FLAG_NAME_RECURSE) && (
	  ((flags & FS_FLAG_NAME_UNALLOC) && (!(flags & FS_FLAG_NAME_ALLOC))) ||
	  ((localFlags & LCL_FILE) && (!(localFlags & LCL_DIR))) )) {

		localFlags |= LCL_FULL;
	}

	/* set flag to save full path for mactimes style printing */
	if (localFlags & LCL_MAC) {
		localFlags |= LCL_FULL;
	}

	/* we need to append a / to the end of the directory if
	 * one does not already exist
	 */
	if (macpre) {
		int len = strlen (macpre);
		if (macpre[len - 1] != '/') {
			char *tmp = macpre;
			macpre = (char *)malloc(len + 2);
			strncpy (macpre, tmp, len + 1);
			strncat (macpre, "/", len + 2);
		}
	}

	inode=-1;
	//Parse the rest of the args as options to the io filesystem:
	while(optind<argc) {
	  char *endptr;
	  int temp;

	  //We need to guess if this option is actually numeric, then its probably an inode number
	  temp = strtol(argv[optind],&endptr,10);
	  //Was this a valid number? If not it must be an option...
	  if(argv[optind] && *endptr=='\0') {
	    inode=temp;
	    optind++;
	  } else {

	    //	    TRY {
	    io_parse_options(io,argv[optind]);
	      /*} EXCEPT(E_ANY) {
		printf("Error loading option %s: %s\n",argv[optind],except_str);
		exit(-1);
	      };*/
	    optind++;
	  }
	};

	TRY {
	  fs = fs_open(io, fstype);
	  if(!fs) RAISE(E_GENERIC,NULL,"do you need to specify FS type?");

	} EXCEPT(E_ANY) {
	  printf("Could not open filesystem: %s\n",except_str);
	  exit(-1);
	};

	//If we dont have an inode still, we take the default:
	if(inode<0) {
	  inode = fs->root_inum;
	};

	/* begin walk */
	fs->dent_walk(fs, inode, flags, print_dent, (char *)0); 

	fs->close(fs);

	exit (0);
}

