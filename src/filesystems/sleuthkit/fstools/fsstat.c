/*
** fsstat
** The Sleuth Kit 
**
** $Date: 2006/09/20 20:16:01 $
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2006 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc. All Rights reserved
**
**
** This software is distributed under the Common Public License 1.0
**
*/
#include <locale.h>
#include "fs_tools.h"

static TSK_TCHAR *progname;

static void
usage()
{
    TFPRINTF(stderr,
	_TSK_T
	("usage: %s [-tvV] [-f fstype] [-i imgtype] [-o imgoffset] image\n"),
	progname);
    tsk_fprintf(stderr, "\t-t: display type only\n");
    tsk_fprintf(stderr,
	"\t-i imgtype: The format of the image file (use '-i list' for supported types)\n");
    tsk_fprintf(stderr,
	"\t-f fstype: File system type (use '-f list' for supported types)\n");
    tsk_fprintf(stderr,
	"\t-o imgoffset: The offset of the file system in the image (in sectors)\n");
    tsk_fprintf(stderr, "\t-v: verbose output to stderr\n");
    tsk_fprintf(stderr, "\t-V: Print version\n");

    exit(1);
}


int
MAIN(int argc, TSK_TCHAR ** argv)
{
    FS_INFO *fs;
    IMG_INFO *img;
    TSK_TCHAR *fstype = NULL;
    TSK_TCHAR *imgtype = NULL;
    int ch;
    uint8_t type = 0;
    SSIZE_T imgoff = 0;

    progname = argv[0];
    setlocale(LC_ALL, "");

    while ((ch = getopt(argc, argv, _TSK_T("f:i:o:tvV"))) > 0) {
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

	case _TSK_T('t'):
	    type = 1;
	    break;

	case _TSK_T('v'):
	    verbose++;
	    break;

	case _TSK_T('V'):
	    print_version(stdout);
	    exit(0);
	}
    }

    /* We need at least one more argument */
    if (optind >= argc) {
	tsk_fprintf(stderr, "Missing image name\n");
	usage();
    }

    if ((img =
	    img_open(imgtype, argc - optind,
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

    if (type) {
	char *str = fs_get_type(fs->ftype);
	tsk_printf("%s\n", str);
    }
    else {
	if (fs->fsstat(fs, stdout)) {
	    tsk_error_print(stderr);
	    fs->close(fs);
	    img->close(img);
	    exit(1);
	}
    }

    fs->close(fs);
    img->close(img);
    exit(0);
}
