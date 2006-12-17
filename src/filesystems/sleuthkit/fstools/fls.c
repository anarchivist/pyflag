/*
** fls
** The Sleuth Kit 
**
** $Date: 2006/09/20 20:16:01 $
**
** Given an image and directory inode, display the file names and 
** directories that exist (both active and deleted)
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2006 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carier.  All rights reserved
**
** TASK
** Copyright (c) 2002 @stake Inc.  All rights reserved
**
** TCTUTILs
** Copyright (c) 2001 Brian Carrier.  All rights reserved
**
**
** This software is distributed under the Common Public License 1.0
**
*/
#include <locale.h>
#include <time.h>
#include "fs_tools.h"

static TSK_TCHAR *progname;

void
usage()
{
    TFPRINTF(stderr,
	_TSK_T
	("usage: %s [-adDFlpruvV] [-f fstype] [-i imgtype] [-m dir/] [-o imgoffset] [-z ZONE] [-s seconds] image [images] [inode]\n"),
	progname);
    tsk_fprintf(stderr,
	"\tIf [inode] is not given, the root directory is used\n");
    tsk_fprintf(stderr, "\t-a: Display \".\" and \"..\" entries\n");
    tsk_fprintf(stderr, "\t-d: Display deleted entries only\n");
    tsk_fprintf(stderr, "\t-D: Display only directories\n");
    tsk_fprintf(stderr, "\t-F: Display only files\n");
    tsk_fprintf(stderr, "\t-l: Display long version (like ls -l)\n");
    tsk_fprintf(stderr,
	"\t-i imgtype: Format of image file (use '-i list' for supported types)\n");
    tsk_fprintf(stderr,
	"\t-f fstype: File system type (use '-f list' for supported types)\n");
    tsk_fprintf(stderr,
	"\t-m: Display output in mactime input format with\n");
    tsk_fprintf(stderr,
	"\t      dir/ as the actual mount point of the image\n");
    tsk_fprintf(stderr,
	"\t-o imgoffset: Offset into image file (in sectors)\n");
    tsk_fprintf(stderr, "\t-p: Display full path for each file\n");
    tsk_fprintf(stderr, "\t-r: Recurse on directory entries\n");
    tsk_fprintf(stderr, "\t-u: Display undeleted entries only\n");
    tsk_fprintf(stderr, "\t-v: verbose output to stderr\n");
    tsk_fprintf(stderr, "\t-V: Print version\n");
    tsk_fprintf(stderr,
	"\t-z: Time zone of original machine (i.e. EST5EDT or GMT) (only useful with -l)\n");
    tsk_fprintf(stderr,
	"\t-s seconds: Time skew of original machine (in seconds) (only useful with -l & -m)\n");

    exit(1);
}

int
MAIN(int argc, TSK_TCHAR ** argv)
{
    TSK_TCHAR *fstype = NULL;
    TSK_TCHAR *imgtype = NULL;
    INUM_T inode;
    int flags = FS_FLAG_NAME_ALLOC | FS_FLAG_NAME_UNALLOC;
    int ch;
    FS_INFO *fs;
    extern int optind;
    IMG_INFO *img;
    int lclflags;
    int32_t sec_skew = 0;
    static TSK_TCHAR *macpre = NULL;
    SSIZE_T imgoff = 0;

    progname = argv[0];
    setlocale(LC_ALL, "");

    lclflags = FLS_DIR | FLS_FILE;

    while ((ch = getopt(argc, argv, _TSK_T("adDf:Fi:m:lo:prs:uvVz:"))) > 0) {
	switch (ch) {
	case _TSK_T('?'):
	default:
	    TFPRINTF(stderr, _TSK_T("Invalid argument: %s\n"),
		argv[optind]);
	    usage();
	case _TSK_T('a'):
	    lclflags |= FLS_DOT;
	    break;
	case _TSK_T('d'):
	    flags &= ~FS_FLAG_NAME_ALLOC;
	    break;
	case _TSK_T('D'):
	    lclflags &= ~FLS_FILE;
	    lclflags |= FLS_DIR;
	    break;
	case _TSK_T('f'):
	    fstype = optarg;
	    if (TSTRCMP(fstype, _TSK_T("list")) == 0) {
		fs_print_types(stderr);
		exit(1);
	    }

	    break;
	case _TSK_T('F'):
	    lclflags &= ~FLS_DIR;
	    lclflags |= FLS_FILE;
	    break;
	case _TSK_T('i'):
	    imgtype = optarg;
	    if (TSTRCMP(imgtype, _TSK_T("list")) == 0) {
		img_print_types(stderr);
		exit(1);
	    }
	    break;
	case _TSK_T('l'):
	    lclflags |= FLS_LONG;
	    break;
	case _TSK_T('m'):
	    lclflags |= FLS_MAC;
	    macpre = optarg;
	    break;
	case _TSK_T('o'):
	    if ((imgoff = parse_offset(optarg)) == -1) {
		tsk_error_print(stderr);
		exit(1);
	    }
	    break;
	case _TSK_T('p'):
	    lclflags |= FLS_FULL;
	    break;
	case _TSK_T('r'):
	    flags |= FS_FLAG_NAME_RECURSE;
	    break;
	case _TSK_T('s'):
	    sec_skew = TATOI(optarg);
	    break;
	case _TSK_T('u'):
	    flags &= ~FS_FLAG_NAME_UNALLOC;
	    break;
	case _TSK_T('v'):
	    verbose++;
	    break;
	case _TSK_T('V'):
	    print_version(stdout);
	    exit(0);
	case 'z':
	    {
		TSK_TCHAR envstr[32];
		TSNPRINTF(envstr, 32, _TSK_T("TZ=%s"), optarg);
		if (0 != PUTENV(envstr)) {
		    tsk_fprintf(stderr, "error setting environment");
		    exit(1);
		}

		/* we should be checking this somehow */
		TZSET();
	    }
	    break;

	}
    }

    /* We need at least one more argument */
    if (optind == argc) {
	tsk_fprintf(stderr, "Missing image name\n");
	usage();
    }


    /* Set the full flag to print the full path name if recursion is
     ** set and we are only displaying files or deleted files
     */
    if ((flags & FS_FLAG_NAME_RECURSE) && (((flags & FS_FLAG_NAME_UNALLOC)
		&& (!(flags & FS_FLAG_NAME_ALLOC)))
	    || ((lclflags & FLS_FILE)
		&& (!(lclflags & FLS_DIR))))) {

	lclflags |= FLS_FULL;
    }

    /* set flag to save full path for mactimes style printing */
    if (lclflags & FLS_MAC) {
	lclflags |= FLS_FULL;
    }

    /* we need to append a / to the end of the directory if
     * one does not already exist
     */
    if (macpre) {
	size_t len = TSTRLEN(macpre);
	if (macpre[len - 1] != '/') {
	    TSK_TCHAR *tmp = macpre;
	    macpre = (TSK_TCHAR *) malloc(len + 2 * sizeof(TSK_TCHAR));
	    TSTRNCPY(macpre, tmp, len + 1);
	    TSTRNCAT(macpre, _TSK_T("/"), len + 2);
	}
    }

    /* open image - there is an optional inode address at the end of args 
     *
     * Check the final argument and see if it is a number
     */
    if (parse_inum(argv[argc - 1], &inode, NULL, NULL, NULL)) {
	/* Not an inode at the end */
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
	inode = fs->root_inum;
    }
    else {
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
    }

    if (fs_fls(fs, lclflags, inode, flags, macpre, sec_skew)) {
	tsk_error_print(stderr);
	fs->close(fs);
	img->close(img);
	exit(1);
    }

    fs->close(fs);
    img->close(img);

    exit(0);
}
