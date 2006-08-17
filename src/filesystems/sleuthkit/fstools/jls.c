/*
** jls
** The Sleuth Kit 
**
** $Date: 2006/07/10 13:26:20 $
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2006 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2004-2005 Brian Carrier.  All rights reserved
**
**
** This software is distributed under the Common Public License 1.0
**
*/

#include "fs_tools.h"


/* atoinum - convert string to inode number */
INUM_T
atoinum(const char *str)
{
    char *cp, *dash;
    INUM_T inum;

    if (*str == 0)
	return (0);

    /* if we are given the inode in the inode-type-id form, then ignore
     * the other stuff w/out giving an error 
     *
     * This will make scripting easier
     */
    if ((dash = strchr(str, '-')) != NULL) {
	*dash = '\0';
    }
    inum = strtoull(str, &cp, 0);
    if (*cp || cp == str) {
	fprintf(stderr, "bad inode number: %s", str);
	exit(1);
    }
    return (inum);
}


/* usage - explain and terminate */

static void
usage()
{
    fprintf(stderr,
	"usage: %s [-f fstype] [-i imgtype] [-o imgoffset] [-vV] image [inode]\n",
	progname);
    fprintf(stderr,
	"\t-i imgtype: The format of the image file (use '-i list' for supported types)\n");
    fprintf(stderr,
	"\t-f fstype: File system type (use '-f list' for supported types)\n");
    fprintf(stderr,
	"\t-o imgoffset: The offset of the file system in the image (in sectors)\n");
    fprintf(stderr, "\t-v: verbose output to stderr\n");
    fprintf(stderr, "\t-V: print version\n");
    exit(1);
}


int
main(int argc, char **argv)
{
    INUM_T inum;
    int ch;
    char *fstype = NULL;
    FS_INFO *fs;
    char *imgtype = NULL, *cp;
    SSIZE_T imgoff = 0;
    IMG_INFO *img;

    progname = argv[0];
    setlocale(LC_ALL, "");

    while ((ch = getopt(argc, argv, "f:i:o:vV")) > 0) {
	switch (ch) {

	case '?':
	default:
	    fprintf(stderr, "Invalid argument: %s\n", argv[optind]);
	    usage();
	case 'f':
	    fstype = optarg;
	    if (strcmp(fstype, "list") == 0) {
		fs_print_types(stderr);
		exit(1);
	    }

	    break;
	case 'i':
	    imgtype = optarg;
	    if (strcmp(imgtype, "list") == 0) {
		img_print_types(stderr);
		exit(1);
	    }

	    break;

	case 'o':
	    if ((imgoff = parse_offset(optarg)) == -1) {
		tsk_error_print(stderr);
		exit(1);
	    }
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
	fprintf(stderr, "Missing image name and/or address\n");
	usage();
    }


    /* open image - there is an optional inode address at the end of args 
     *
     * Check the final argument and see if it is a number
     */
    inum = strtoull(argv[argc - 1], &cp, 0);
    if (*cp || cp == argv[argc - 1]) {
	/* Not an inode at the end */
	if ((img =
		img_open(imgtype, argc - optind,
		    (const char **) &argv[optind])) == NULL) {
	    tsk_error_print(stderr);
	    exit(1);
	}

	if ((fs = fs_open(img, imgoff, fstype)) == NULL) {
	    tsk_error_print(stderr);
	    if (tsk_errno == TSK_ERR_FS_UNSUPTYPE)
		fs_print_types(stderr);
	    img->close(img);
	    exit(1);
	}

	inum = fs->journ_inum;
    }
    else {
	if ((img =
		img_open(imgtype, argc - optind - 1,
		    (const char **) &argv[optind])) == NULL) {
	    tsk_error_print(stderr);
	    exit(1);
	}

	if ((fs = fs_open(img, imgoff, fstype)) == NULL) {
	    tsk_error_print(stderr);
	    if (tsk_errno == TSK_ERR_FS_UNSUPTYPE)
		fs_print_types(stderr);
	    img->close(img);
	    exit(1);
	}

    }

    if (fs->jopen == NULL) {
	fprintf(stderr,
	    "Journal support does not exist for this file system\n");
	fs->close(fs);
	img->close(img);
	exit(1);
    }

    if (inum > fs->last_inum) {
	fprintf(stderr,
	    "Inode value is too large for image (%" PRIuINUM ")\n",
	    fs->last_inum);
	fs->close(fs);
	img->close(img);
	exit(1);
    }

    if (inum < fs->first_inum) {
	fprintf(stderr,
	    "Inode value is too small for image (%" PRIuINUM ")\n",
	    fs->first_inum);
	fs->close(fs);
	img->close(img);
	exit(1);
    }

    if (fs->jopen(fs, inum)) {
	tsk_error_print(stderr);
	fs->close(fs);
	img->close(img);
	exit(1);

    }
    if (fs->jentry_walk(fs, 0, 0, NULL)) {
	tsk_error_print(stderr);
	fs->close(fs);
	img->close(img);
	exit(1);
    }

    fs->close(fs);
    img->close(img);
    exit(0);
}
