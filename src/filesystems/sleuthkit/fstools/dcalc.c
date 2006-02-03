/*
** dcalc
** The Sleuth Kit 
**
** $Date: 2005/09/02 23:34:02 $
**
** Calculates the corresponding block number between 'dls' and 'dd' images
** when given an 'dls' block number, it determines the block number it
** had in a 'dd' image.  When given a 'dd' image, it determines the
** value it would have in a 'dls' image (if the block is unallocated)
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003-2005 Brian Carrier. All Rights reserved
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc. All Rights reserved
**
** TCTUTILs
** Copyright (c) 2001 Brian Carrier.  All rights reserved
**
**
** This software is distributed under the Common Public License 1.0
**
*/
#include "libfstools.h"

static void
usage()
{
    fprintf(stderr,
	    "usage: %s [-dsu unit_addr] [-vV] [-f fstype] [-i imgtype] [-o imgoffset] image [images]\n",
	    progname);
    fprintf(stderr, "Slowly calculates the opposite block number\n");
    fprintf(stderr, "\tOne of the following must be given:\n");
    fprintf(stderr, "\t  -d: The given address is from a 'dd' image \n");
    fprintf(stderr,
	    "\t  -s: The given address is from a 'dls -s' (slack) image\n");
    fprintf(stderr,
	    "\t  -u: The given address is from a 'dls' (unallocated) image\n");
    fprintf(stderr, "\t-i imgtype: The format of the image file\n");
    fprintf(stderr,
	    "\t-o imgoffset: The offset of the file system in the image (in sectors)\n");
    fprintf(stderr, "\t-v: verbose output to stderr\n");
    fprintf(stderr, "\t-V: Print version\n");
    fprintf(stderr, "\t-f fstype: The file system type\n");
    fprintf(stderr, "Supported file system types:\n");
    fs_print_types(stderr);
    fprintf(stderr, "Supported image format types:\n");
    img_print_types(stderr);


    exit(1);
}



int
main(int argc, char **argv)
{
    char *fstype = NULL;
    char ch, *cp, type = 0;
    FS_INFO *fs;
    IMG_INFO *img;
    int set = 0;
    char *imgtype = NULL, *imgoff = NULL;
    DADDR_T count = 0;

    progname = argv[0];
    setlocale(LC_ALL, "");

    while ((ch = getopt(argc, argv, "d:f:i:o:s:u:vV")) > 0) {
	switch (ch) {
	case '?':
	default:
	    fprintf(stderr, "Invalid argument: %s\n", argv[optind]);
	    usage();

	case 'd':
	    type |= DCALC_DD;
	    count = strtoull(optarg, &cp, 0);
	    if (*cp || cp == optarg) {
		fprintf(stderr, "Invalid address: %s\n", optarg);
		usage();
	    }

	    set = 1;
	    break;

	case 'f':
	    fstype = optarg;
	    break;

	case 'i':
	    imgtype = optarg;
	    break;

	case 'o':
	    imgoff = optarg;
	    break;

	case 's':
	    type |= DCALC_SLACK;
	    count = strtoull(optarg, &cp, 0);
	    if (*cp || cp == optarg) {
		fprintf(stderr, "Invalid address: %s\n", optarg);
		usage();
	    }

	    set = 1;
	    break;

	case 'u':
	    type |= DCALC_DLS;
	    count = strtoull(optarg, &cp, 0);
	    if (*cp || cp == optarg) {
		fprintf(stderr, "Invalid address: %s\n", optarg);
		usage();
	    }

	    set = 1;
	    break;

	case 'v':
	    verbose++;
	    break;

	case 'V':
	    print_version(stdout);
	    exit(0);
	}
    }

    /* We need at least one more argument */
    if (optind == argc) {
	fprintf(stderr, "Missing image name\n");
	usage();
    }

    if ((!type) || (set == 0)) {
	fprintf(stderr, "Calculation type not given (-u, -d, -s)\n");
	usage();
    }

    if ((type & DCALC_DD) && (type & DCALC_DLS) && (type & DCALC_SLACK)) {
	fprintf(stderr, "Only one block type can be given\n");
	usage();
    }


    img =
	img_open(imgtype, imgoff, argc - optind,
		 (const char **) &argv[optind]);
    fs = fs_open(img, fstype);

    fs_dcalc(fs, type, count);

    fs->close(fs);
    img->close(img);

    exit(0);
}
