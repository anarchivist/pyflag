/*
** ifind (inode find)
** The Sleuth Kit
**
** $Date: 2006/12/05 21:39:52 $
**
** Given an image  and block number, identify which inode it is used by
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
#include <time.h>
#include "fs_tools.h"

static TSK_TCHAR *progname;
static uint8_t localflags;

static void
usage()
{
    TFPRINTF(stderr,
	_TSK_T
	("usage: %s [-alvV] [-f fstype] [-i imgtype] [-o imgoffset] [-d unit_addr] [-n file] [-p par_addr] [-z ZONE] image [images]\n"),
	progname);
    tsk_fprintf(stderr, "\t-a: find all inodes\n");
    tsk_fprintf(stderr,
	"\t-d unit_addr: Find the meta data given the data unit\n");
    tsk_fprintf(stderr, "\t-l: long format when -p is given\n");
    tsk_fprintf(stderr,
	"\t-n file: Find the meta data given the file name\n");
    tsk_fprintf(stderr,
	"\t-p par_addr: Find UNALLOCATED MFT entries given the parent's meta address (NTFS only)\n");
    tsk_fprintf(stderr,
	"\t-i imgtype: The format of the image file (use '-i list' for supported types)\n");
    tsk_fprintf(stderr,
	"\t-f fstype: File system type (use '-f list' for supported types)\n");
    tsk_fprintf(stderr,
	"\t-o imgoffset: The offset of the file system in the image (in sectors)\n");
    tsk_fprintf(stderr, "\t-v: Verbose output to stderr\n");
    tsk_fprintf(stderr, "\t-V: Print version\n");
    tsk_fprintf(stderr,
	"\t-z ZONE: Time zone setting when -l -p is given\n");

    exit(1);
}




int
MAIN(int argc, TSK_TCHAR ** argv)
{
    TSK_TCHAR *imgtype = NULL;
    TSK_TCHAR *fstype = NULL;
    FS_INFO *fs;
    IMG_INFO *img;
    int ch;
    TSK_TCHAR *cp;
    extern int optind;
    DADDR_T block = 0;		/* the block to find */
    INUM_T parinode = 0;
    TSK_TCHAR *path = NULL;
    SSIZE_T imgoff = 0;

    progname = argv[0];
    setlocale(LC_ALL, "");

    localflags = 0;

    while ((ch = getopt(argc, argv, _TSK_T("ad:f:i:ln:o:p:vVz:"))) > 0) {
	switch (ch) {
	case _TSK_T('a'):
	    localflags |= IFIND_ALL;
	    break;
	case _TSK_T('d'):
	    if (localflags & (IFIND_PAR | IFIND_PATH)) {
		tsk_fprintf(stderr,
		    "error: only one address type can be given\n");
		usage();
	    }
	    localflags |= IFIND_DATA;
	    block = TSTRTOULL(optarg, &cp, 0);
	    if (*cp || cp == optarg) {
		TFPRINTF(stderr, _TSK_T("Invalid block address: %s\n"),
		    optarg);
		usage();
	    }
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
	case _TSK_T('l'):
	    localflags |= IFIND_PAR_LONG;
	    break;
	case _TSK_T('n'):
	    {
		size_t len;
		if (localflags & (IFIND_PAR | IFIND_DATA)) {
		    tsk_fprintf(stderr,
			"error: only one address type can be given\n");
		    usage();
		}
		localflags |= IFIND_PATH;
		len = (TSTRLEN(optarg) + 1) * sizeof(TSK_TCHAR);
		if ((path = (TSK_TCHAR *) mymalloc(len)) == NULL) {
		    tsk_error_print(stderr);
		    exit(1);
		}
		TSTRNCPY(path, optarg, TSTRLEN(optarg) + 1);
		break;
	    }
	case 'o':
	    if ((imgoff = parse_offset(optarg)) == -1) {
		tsk_error_print(stderr);
		exit(1);
	    }
	    break;
	case 'p':
	    if (localflags & (IFIND_PATH | IFIND_DATA)) {
		tsk_fprintf(stderr,
		    "error: only one address type can be given\n");
		usage();
	    }
	    localflags |= IFIND_PAR;
	    parinode = TSTRTOULL(optarg, &cp, 0);
	    if (parse_inum(optarg, &parinode, NULL, NULL, NULL)) {
		TFPRINTF(stderr, _TSK_T("Invalid inode address: %s\n"),
		    optarg);
		usage();
	    }
	    break;
	case 'v':
	    verbose++;
	    break;
	case 'V':
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
		break;
	    }
	case '?':
	default:
	    tsk_fprintf(stderr, "Invalid argument: %s\n", argv[optind]);
	    usage();
	}
    }

    /* We need at least one more argument */
    if (optind >= argc) {
	tsk_fprintf(stderr, "Missing image name\n");
	if (path)
	    free(path);
	usage();
    }

    if (0 == (localflags & (IFIND_PATH | IFIND_DATA | IFIND_PAR))) {
	tsk_fprintf(stderr, "-d, -n, or -p must be given\n");
	usage();
    }


    if ((img =
	    img_open(imgtype, argc - optind,
		(const TSK_TCHAR **) &argv[optind])) == NULL) {
	tsk_error_print(stderr);
	if (path)
	    free(path);
	exit(1);
    }

    if ((fs = fs_open(img, imgoff, fstype)) == NULL) {
	tsk_error_print(stderr);
	if (tsk_errno == TSK_ERR_FS_UNSUPTYPE)
	    fs_print_types(stderr);
	img->close(img);
	if (path)
	    free(path);
	exit(1);
    }

    if (localflags & IFIND_DATA) {
	if (block > fs->last_block) {
	    tsk_fprintf(stderr,
		"Block %" PRIuDADDR
		" is larger than last block in image (%" PRIuDADDR
		")\n", block, fs->last_block);
	    fs->close(fs);
	    img->close(img);
	    exit(1);
	}
	else if (block == 0) {
	    tsk_printf("Inode not found\n");
	    fs->close(fs);
	    img->close(img);
	    exit(1);
	}
	if (fs_ifind_data(fs, localflags, block)) {
	    tsk_error_print(stderr);
	    fs->close(fs);
	    img->close(img);
	    exit(1);
	}
    }

    else if (localflags & IFIND_PAR) {
	if ((fs->ftype & FSMASK) != NTFS_TYPE) {
	    tsk_fprintf(stderr, "-p works only with NTFS file systems\n");
	    fs->close(fs);
	    img->close(img);
	    exit(1);
	}
	else if (parinode > fs->last_inum) {
	    tsk_fprintf(stderr,
		"Meta data %" PRIuINUM
		" is larger than last MFT entry in image (%" PRIuINUM
		")\n", parinode, fs->last_inum);
	    fs->close(fs);
	    img->close(img);
	    exit(1);
	}
	if (fs_ifind_par(fs, localflags, parinode)) {
	    tsk_error_print(stderr);
	    fs->close(fs);
	    img->close(img);
	    exit(1);
	}
    }

    else if (localflags & IFIND_PATH) {
	int retval;
	INUM_T inum;

	if (-1 == (retval = fs_ifind_path(fs, localflags, path, &inum))) {
	    tsk_error_print(stderr);
	    fs->close(fs);
	    img->close(img);
	    free(path);
	    exit(1);
	}
	free(path);
	if (retval == 1)
	    tsk_printf("File not found\n");
	else
	    tsk_printf("%" PRIuINUM "\n", inum);
    }
    fs->close(fs);
    img->close(img);

    exit(0);
}
