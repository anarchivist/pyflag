/*
** The  Sleuth Kit 
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003-2004 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
** 
** Copyright (c) 1997,1998,1999, International Business Machines          
** Corporation and others. All Rights Reserved.

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
#include "fs_io.h"

FILE   *logfp;
extern char *progname;

/* usage - explain and terminate */

static void 
usage()
{
    printf("usage: %s [-hHrsvV] [-i IOsubsystem] [-o subsystem_opts] [-f fstype] device [inum[-typ[-id]] ...]\n", progname);
	printf("\t-h: Do not display holes in sparse files\n");
	printf("\t-r: Recover deleted file\n");
	printf("\t-i: select IO Subsystems. Try help for a list of subsystems\n");
	printf("\t-o: Subsystem specific option. Try help for specific help\n");
	printf("\t-s: Display slack space at end of file\n");
	printf("\t-v: verbose to stderr\n");
	printf("\t-V: Print version\n");
	printf("\t-f fstype: Image file system type\n");
	printf("Supported file system types:\n");
	fs_print_types();

	exit(1);
}

/* Call back action for file_walk
 */
static u_int8_t
icat_action(FS_INFO *fs, DADDR_T addr, char *buf, int size, 
  int flags, char *ptr)
{
	if (size == 0)
		return WALK_CONT;

	if (fwrite(buf, size, 1, stdout) != 1)
		error("icat_action: write: %m");

	return WALK_CONT;
}

int
main(int argc, char **argv)
{
	FS_INFO *fs;
	char   	*cp;
	INUM_T  inum;
	int	flags = 0;
	int     ch;
	char   	*fstype = DEF_FSTYPE;
	FS_INODE *inode;
	char *io_subsys=NULL;
	char *io_subsys_opts=NULL;
	IO_INFO *io;

	progname = argv[0];

    while ((ch = getopt(argc, argv, "f:hi:o:rsvV")) > 0) {
	switch (ch) {
		default:
		    usage();
		case 'f':
		    fstype = optarg;
		    break;
		case 'h':
		    flags |= FS_FLAG_FILE_NOSPARSE;
		    break;
		case 'r':
			flags |= FS_FLAG_FILE_RECOVER;
			break;
		case 's':
		    	flags |= FS_FLAG_FILE_SLACK;
			break;
		case 'i':
			io_subsys=optarg;
			break;
		case 'o':
			io_subsys_opts=optarg;
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

    if (argc < optind + 2)
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

    if(io_subsys_opts) {
      io_parse_options(io,io_subsys_opts);
    };
    
    //Parse the rest of the args as options to the io filesystem until the penultimate arg (the final arg is an inode number):
    while(optind<argc-1) {
      io_parse_options(io,argv[optind++]);
    };
    
    fs = fs_open(io,fstype);

	while (argv[++optind]) {
		int type = 0;
		int id = 0, id_used = 0;
		char 	*dash;

		/* simple inode usage */
		if ((dash = strchr(argv[optind], '-')) == NULL) {
			inum = STRTOUL(argv[optind], &cp, 0);
			if (*cp || cp == argv[optind])
				usage();
		}

		/* inum-type or inum-type-id format */
		else {
			char *dash2;
			*dash = '\0';
			dash++;

			if ((dash2 = strchr(dash, '-')) == NULL) {
				id = 0;
			}
			else {
				*dash2 = '\0';
				dash2++;

				id = STRTOUL(dash2, &cp, 0);
				id_used = 1;
				if (*cp || cp == dash2)
					usage();
			}

			inum = STRTOUL(argv[optind], &cp, 0);
			if (*cp || cp == argv[optind])
				usage();

			type = STRTOUL(dash, &cp, 0);
			if (*cp || cp == dash)
				usage();
		}

		inode = fs->inode_lookup(fs, inum);
		if (!inode)
			error ("error getting inode");

		if (id_used)
			fs->file_walk(fs, inode, type, id, flags, icat_action, "");
		/* If the id value was not used, then set the flag accordingly so the '0' value is ignored */
		else 
			fs->file_walk(fs, inode, type, id, flags | FS_FLAG_FILE_NOID, icat_action, "");

		fs_inode_free(inode);
	}
	fs->close(fs);
	exit(0);
}
