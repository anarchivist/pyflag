/*
** fsstat
** The Sleuth Kit 
**
** $Date: 2005/09/02 23:34:03 $
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc. All Rights reserved
**
**
** This software is distributed under the Common Public License 1.0
**
*/
#include "fs_tools.h"

static void
usage()
{
    fprintf(stderr,
	    "usage: %s [-tvV] [-f fstype] [-i imgtype] [-o imgoffset] image\n",
	    progname);
    fprintf(stderr, "\t-t: display type only\n");
    fprintf(stderr, "\t-i imgtype: The format of the image file\n");
    fprintf(stderr,
	    "\t-o imgoffset: The offset of the file system in the image (in sectors)\n");
    fprintf(stderr, "\t-v: verbose output to stderr\n");
    fprintf(stderr, "\t-V: Print version\n");
    fprintf(stderr, "\t-f fstype: File system type\n");
    fprintf(stderr, "Supported file system types:\n");
    fs_print_types(stderr);
    fprintf(stderr, "Supported image format types:\n");
    img_print_types(stderr);

    exit(1);
}


int
main(int argc, char **argv)
{
    FS_INFO *fs;
    IMG_INFO *img;
    char *fstype = NULL;
    char ch, *imgtype = NULL, *imgoff = NULL;
    uint8_t type = 0;

    progname = argv[0];
    setlocale(LC_ALL, "");

    while ((ch = getopt(argc, argv, "f:i:o:tvV")) > 0) {
	switch (ch) {
	case '?':
	default:
	    fprintf(stderr, "Invalid argument: %s\n", argv[optind]);
	    usage();

	case 'f':
	    fstype = optarg;
	    break;

	case 'i':
	    imgtype = optarg;
	    break;

	case 'o':
	    imgoff = optarg;
	    break;

	case 't':
	    type = 1;
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
    if (optind >= argc) {
	fprintf(stderr, "Missing image name\n");
	usage();
    }

    img =
	img_open(imgtype, imgoff, argc - optind,
		 (const char **) &argv[optind]);
    fs = fs_open(img, fstype);

    if (type) {
	char *str = fs_get_type(fs->ftype);
	printf("%s\n", str);
    }
    else {
	fs->fsstat(fs, stdout);
    }

    fs->close(fs);
    img->close(img);

    exit(0);
}
