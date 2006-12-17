/*
** ffind  (file find)
** The Sleuth Kit 
**
** $Date: 2006/09/20 20:16:01 $
**
** Find the file that uses the specified inode (including deleted files)
** 
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2006 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
** TCTUTILs
** Copyright (c) 2001 Brian Carrier.  All rights reserved
**
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
	("usage: %s [-aduvV] [-f fstype] [-i imgtype] [-o imgoffset] image [images] inode\n"),
	progname);
    tsk_fprintf(stderr, "\t-a: Find all occurrences\n");
    tsk_fprintf(stderr, "\t-d: Find deleted entries ONLY\n");
    tsk_fprintf(stderr, "\t-u: Find undeleted entries ONLY\n");
    tsk_fprintf(stderr,
	"\t-f fstype: Image file system type (use '-f list' for supported types)\n");
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
    int flags = FS_FLAG_NAME_RECURSE;
    int ch;
    FS_INFO *fs;
    extern int optind;
    uint32_t type;
    uint16_t id;
    int id_used;
    IMG_INFO *img;
    uint8_t localflags = 0;
    INUM_T inode;
    SSIZE_T imgoff = 0;

    progname = argv[0];
    setlocale(LC_ALL, "");

    while ((ch = getopt(argc, argv, _TSK_T("adf:i:o:uvV"))) > 0) {
	switch (ch) {
	case _TSK_T('a'):
	    localflags |= FFIND_ALL;
	    break;
	case _TSK_T('d'):
	    flags |= FS_FLAG_NAME_UNALLOC;
	    break;
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
	case _TSK_T('u'):
	    flags |= FS_FLAG_NAME_ALLOC;
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

    /* if the user did not specify either of the alloc/unalloc flags
     ** then show them all
     */
    if ((!(flags & FS_FLAG_NAME_ALLOC))
	&& (!(flags & FS_FLAG_NAME_UNALLOC)))
	flags |= (FS_FLAG_NAME_ALLOC | FS_FLAG_NAME_UNALLOC);


    if (optind + 1 >= argc) {
	tsk_fprintf(stderr, "Missing image name and/or address\n");
	usage();
    }


    /* Get the inode */
    if (parse_inum(argv[argc - 1], &inode, &type, &id, &id_used)) {
	TFPRINTF(stderr, _TSK_T("Invalid inode: %s\n"), argv[argc - 1]);
	usage();
    }
    if (id_used == 0)
	flags |= FS_FLAG_FILE_NOID;

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

    if (inode < fs->first_inum) {
	tsk_fprintf(stderr,
	    "Inode is too small for image (%" PRIuINUM ")\n",
	    fs->first_inum);
	exit(1);
    }
    if (inode > fs->last_inum) {
	tsk_fprintf(stderr,
	    "Inode is too large for image (%" PRIuINUM ")\n",
	    fs->last_inum);
	exit(1);
    }

    if (fs_ffind(fs, localflags, inode, type, id, flags)) {
	tsk_error_print(stderr);
	fs->close(fs);
	img->close(img);
	exit(1);
    }

    fs->close(fs);
    img->close(img);
    exit(0);
}
