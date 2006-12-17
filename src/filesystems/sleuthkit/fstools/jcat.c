/*
** jcat
** The Sleuth Kit 
**
** $Date: 2006/09/20 20:16:01 $
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2006 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2004-2005 Brian Carrier.  All rights reserved
**
**
** This software is distributed under the Common Public License 1.0
**
*/
#include <locale.h>
#include "fs_tools.h"

static TSK_TCHAR *progname;

/* usage - explain and terminate */
static void
usage()
{
    TFPRINTF(stderr,
	_TSK_T
	("usage: %s [-f fstype] [-i imgtype] [-o imgoffset] [-vV] image [images] [inode] blk\n"),
	progname);
    tsk_fprintf(stderr, "\tblk: The journal block to view\n");
    tsk_fprintf(stderr,
	"\tinode: The file system inode where the journal is located\n");
    tsk_fprintf(stderr,
	"\t-i imgtype: The format of the image file (use '-i list' for supported types)\n");
    tsk_fprintf(stderr,
	"\t-f fstype: File system type (use '-f list' for supported types)\n");
    tsk_fprintf(stderr,
	"\t-o imgoffset: The offset of the file system in the image (in sectors)\n");
    tsk_fprintf(stderr, "\t-v: verbose output to stderr\n");
    tsk_fprintf(stderr, "\t-V: print version\n");
    exit(1);
}


int
MAIN(int argc, TSK_TCHAR ** argv)
{
    TSK_TCHAR *fstype = NULL;
    TSK_TCHAR *imgtype = NULL;
    FS_INFO *fs;
    IMG_INFO *img;
    INUM_T inum;
    int ch;
    DADDR_T blk;
    TSK_TCHAR *cp;
    SSIZE_T imgoff = 0;

    progname = argv[0];
    setlocale(LC_ALL, "");

    while ((ch = getopt(argc, argv, _TSK_T("f:i:o:vV"))) > 0) {
	switch (ch) {
	case _TSK_T('?'):
	default:
	    TFPRINTF(stderr, _TSK_T("Invalid argument: %s\n"),
		argv[optind]);
	    usage();
	case _TSK_T('f'):
	    fstype = optarg;
	    if (TSTRCMP(fstype, _TSK_T("list")) == 0) {
		fs_print_types(stderr);
		exit(1);
	    }
	    break;
	case _TSK_T('i'):
	    imgtype = optarg;
	    if (TSTRCMP(imgtype, _TSK_T("list")) == 0) {
		img_print_types(stderr);
		exit(1);
	    }
	    break;
	case _TSK_T('o'):
	    if ((imgoff = parse_offset(optarg)) == -1) {
		tsk_error_print(stderr);
		exit(1);
	    }
	    break;
	case _TSK_T('v'):
	    verbose++;
	    break;
	case _TSK_T('V'):
	    print_version(stdout);
	    exit(0);
	}
    }

    /* We need at least two more arguments */
    if (optind + 1 >= argc) {
	tsk_fprintf(stderr, "Missing image name and/or block address\n");
	usage();
    }

    blk = TSTRTOULL(argv[argc - 1], &cp, 0);
    if (*cp || cp == argv[argc - 1]) {
	TFPRINTF(stderr, _TSK_T("bad block number: %s"), argv[argc - 1]);
	exit(1);
    }

    /* Do we have an inode as well? */
    if (parse_inum(argv[argc - 2], &inum, NULL, NULL, NULL)) {
	/* Not a number therefore an image */
	if ((img =
		img_open(imgtype, argc - optind - 1,
		    (const TSK_TCHAR **) &argv[optind])) == NULL) {
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
		img_open(imgtype, argc - optind - 2,
		    (const TSK_TCHAR **) &argv[optind])) == NULL) {
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

    if (inum > fs->last_inum) {
	tsk_fprintf(stderr,
	    "Inode value is too large for image (%" PRIuINUM ")\n",
	    fs->last_inum);
	fs->close(fs);
	img->close(img);
	exit(1);
    }

    if (inum < fs->first_inum) {
	tsk_fprintf(stderr,
	    "Inode value is too small for image (%" PRIuINUM ")\n",
	    fs->first_inum);
	fs->close(fs);
	img->close(img);
	exit(1);
    }

    if (fs->jopen == NULL) {
	tsk_fprintf(stderr,
	    "Journal support does not exist for this file system\n");
	fs->close(fs);
	img->close(img);
	return 1;
    }

#ifdef TSK_WIN32
    if (-1 == _setmode(_fileno(stdout), _O_BINARY)) {
	tsk_errno = TSK_ERR_FS_WRITE;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "jcat: error setting stdout to binary: %s", strerror(errno));
	return 1;
    }
#endif

    if (fs->jopen(fs, inum)) {
	tsk_error_print(stderr);
	fs->close(fs);
	img->close(img);
	exit(1);
    }
    if (fs->jblk_walk(fs, blk, blk, 0, 0, NULL)) {
	tsk_error_print(stderr);
	fs->close(fs);
	img->close(img);
	exit(1);
    }

    fs->close(fs);
    img->close(img);
    exit(0);
}
