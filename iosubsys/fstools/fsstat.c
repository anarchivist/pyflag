/*
** fsstat
** The Sleuth Kit 
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc. All Rights reserved
**
*/
#include "fs_tools.h"
#include "error.h"

FILE   *logfp;

char *progname;

static void 
usage(char *prog)
{
	printf("usage: %s [-vV] [-f fstype] image\n", prog);
	printf("\t-v: verbose output to stderr\n");
	printf("\t-V: Print version\n");
	printf("\t-f fstype: Image file system type\n");
	printf("Supported file system types:\n");
	fs_print_types();

	exit(1);
}


int 
main(int argc, char **argv)
{
	char   *fstype = DEF_FSTYPE;
	char 	ch;
	FS_INFO 	*fs;
	progname = argv[0];

    while ((ch = getopt(argc, argv, "f:vV")) > 0) {
        switch (ch) {
        case '?':
        default:
            usage(argv[0]);

        case 'f':
			fstype = optarg;
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

	if ((optind+1) != argc) 
		usage(argv[0]);

	progname = argv[0];

    fs = fs_open(argv[optind++], fstype);

	fs->fsstat(fs, stdout);

    fs->close(fs);
    exit(0);
}
