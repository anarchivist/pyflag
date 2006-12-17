/*
** dstat
** The Sleuth Kit 
**
** $Date: 2006/09/20 20:16:01 $
**
** Get the details about a data unit
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2006 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
** This software is distributed under the Common Public License 1.0
**
*/
#include <locale.h>
#include "fs_tools.h"

static TSK_TCHAR *progname;

void
usage()
{
    TFPRINTF(stderr,
	_TSK_T
	("usage: %s [-vV] [-f fstype] [-i imgtype] [-o imgoffset] image [images] addr\n"),
	progname);
    tsk_fprintf(stderr,
	"\t-f fstype: File system type (use '-f list' for supported types)\n");
    tsk_fprintf(stderr,
	"\t-i imgtype: The format of the image file (use '-i list' for supported types)\n");
    tsk_fprintf(stderr,
	"\t-o imgoffset: The offset of the file system in the image (in sectors)\n");
    tsk_fprintf(stderr, "\t-v: Verbose output to stderr\n");
    tsk_fprintf(stderr, "\t-V: Print version\n");

    exit(1);
}



int
MAIN(int argc, TSK_TCHAR ** argv)
{
    TSK_TCHAR *fstype = NULL;
    TSK_TCHAR *imgtype = NULL;
    FS_INFO *fs;
    IMG_INFO *img;
    int ch;
    TSK_TCHAR *cp;
    extern int optind;
    DADDR_T addr;
    int flags =
	(FS_FLAG_DATA_UNALLOC | FS_FLAG_DATA_ALLOC | FS_FLAG_DATA_META |
	FS_FLAG_DATA_CONT);
    SSIZE_T imgoff = 0;

    progname = argv[0];
    setlocale(LC_ALL, "");

    while ((ch = getopt(argc, argv, _TSK_T("f:i:o:uvV"))) > 0) {
	switch (ch) {
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
	case _TSK_T('?'):
	default:
	    TFPRINTF(stderr, _TSK_T("Invalid argument: %s\n"),
		argv[optind]);
	    usage();
	}
    }

    if (optind + 1 >= argc) {
	tsk_fprintf(stderr, "Missing image name and/or address\n");
	usage();
    }

    /* Get the address */
    addr = TSTRTOULL(argv[argc - 1], &cp, 0);
    if (*cp || cp == argv[argc - 1]) {
	tsk_fprintf(stderr, "Invalid address\n");
	usage();
    }

    /* open image */
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


    if (addr > fs->last_block) {
	tsk_fprintf(stderr,
	    "Data unit address too large for image (%" PRIuDADDR ")\n",
	    fs->last_block);
	fs->close(fs);
	img->close(img);
	exit(1);
    }
    if (addr < fs->first_block) {
	tsk_fprintf(stderr,
	    "Data unit address too small for image (%" PRIuDADDR ")\n",
	    fs->first_block);
	fs->close(fs);
	img->close(img);
	exit(1);
    }

    if (fs_dstat(fs, 0, addr, flags)) {
	tsk_error_print(stderr);
	fs->close(fs);
	img->close(img);
	exit(1);
    }

    fs->close(fs);
    img->close(img);
    exit(0);
}
