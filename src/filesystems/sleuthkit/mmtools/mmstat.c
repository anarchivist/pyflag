/*
 * The Sleuth Kit
 *
 * $Date: 2006/09/06 20:40:02 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2005 Brian Carrier.  All rights reserved
 *
 * mmstat - Get stats on the volume system / media management
 *
 *
 * This software is distributed under the Common Public License 1.0
 *
 */

#include "mm_tools.h"

static TSK_TCHAR *progname;

void
usage()
{
    TFPRINTF(stderr,
	_TSK_T
	("%s [-i imgtype] [-o imgoffset] [-vV] [-t mmtype] image [images]\n"),
	progname);
    tsk_fprintf(stderr,
	"\t-t mmtype: The type of partition system (use '-t list' for list of supported types)\n");
    tsk_fprintf(stderr,
	"\t-i imgtype: The format of the image file (use '-i list' for list of supported types)\n");
    tsk_fprintf(stderr,
	"\t-o imgoffset: Offset to the start of the volume that contains the partition system (in sectors)\n");
    tsk_fprintf(stderr, "\t-v: verbose output\n");
    tsk_fprintf(stderr, "\t-V: print the version\n");
    exit(1);
}

static void
print_stats(MM_INFO * mm)
{
    tsk_printf("%s\n", mm_get_type(mm->mmtype));
    //tsk_printf("Type: %s\n", mm->str_type);
    return;
}

int
MAIN(int argc, TSK_TCHAR ** argv)
{
    MM_INFO *mm;
    TSK_TCHAR *imgtype = NULL;
    TSK_TCHAR *mmtype = NULL;
    int ch;
    SSIZE_T imgoff = 0;
    IMG_INFO *img;

    progname = argv[0];

    while ((ch = getopt(argc, argv, _TSK_T("i:o:t:vV"))) > 0) {
	switch (ch) {
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
	    mmtype = optarg;
	    if (TSTRCMP(mmtype, _TSK_T("list")) == 0) {
		mm_print_types(stderr);
		exit(1);
	    }
	    break;
	case 'v':
	    verbose++;
	    break;
	case 'V':
	    print_version(stdout);
	    exit(0);
	case '?':
	default:
	    tsk_fprintf(stderr, "Unknown argument\n");
	    usage();
	}
    }

    /* We need at least one more argument */
    if (optind >= argc) {
	tsk_fprintf(stderr, "Missing image name\n");
	usage();
    }

    /* open the image */
    if ((img =
	    img_open(imgtype, argc - optind,
		(const TSK_TCHAR **) &argv[optind])) == NULL) {
	tsk_error_print(stderr);
	exit(1);
    }


    /* process the partition tables */
    if ((mm = mm_open(img, imgoff, mmtype)) == NULL) {
	tsk_error_print(stderr);
	if (tsk_errno == TSK_ERR_MM_UNSUPTYPE)
	    mm_print_types(stderr);

	exit(1);
    }

    print_stats(mm);

    mm->close(mm);
    img->close(img);
    exit(0);
}
