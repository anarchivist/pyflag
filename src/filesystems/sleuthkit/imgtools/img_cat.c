/*
 * img_cat
 * The Sleuth Kit 
 *
 * $Date: 2006/12/07 16:38:18 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2006 Brian Carrier, Basis Technology.  All rights reserved 
 *
 * This software is distributed under the Common Public License 1.0
 *
 */
#include "img_tools.h"

static TSK_TCHAR *progname;

static void
usage()
{
    TFPRINTF(stderr, _TSK_T("usage: %s [-vV] [-i imgtype] image\n"),
	progname);
    tsk_fprintf(stderr,
	"\t-i imgtype: The format of the image file (use 'i list' for supported types)\n");
    tsk_fprintf(stderr, "\t-v: verbose output to stderr\n");
    tsk_fprintf(stderr, "\t-V: Print version\n");

    exit(1);
}


int
MAIN(int argc, TSK_TCHAR ** argv)
{
    IMG_INFO *img;
    TSK_TCHAR *imgtype = NULL;
    int ch;
    SSIZE_T cnt, done;

    progname = argv[0];

    while ((ch = getopt(argc, argv, _TSK_T("i:vV"))) > 0) {
	switch (ch) {
	case _TSK_T('?'):
	default:
	    TFPRINTF(stderr, _TSK_T("Invalid argument: %s\n"),
		argv[optind]);
	    usage();

	case _TSK_T('i'):
	    imgtype = optarg;
	    if (TSTRCMP(imgtype, _TSK_T("list")) == 0) {
		img_print_types(stderr);
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

#ifdef TSK_WIN32
    if (-1 == _setmode(_fileno(stdout), _O_BINARY)) {
	tsk_errno = TSK_ERR_FS_WRITE;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "dls_lib: error setting stdout to binary: %s",
	    strerror(errno));
	return 1;
    }
#endif

    for (done = 0; done < img->size; done += cnt) {
	char buf[16 * 1024];
	OFF_T len;

	if (done + sizeof(buf) > img->size) {
	    len = img->size - done;
	}
	else {
	    len = sizeof(buf);
	}

	cnt = img->read_random(img, 0, buf, len, done);
	if (cnt != len) {
	    if (cnt != -1) {
		tsk_fprintf(stderr,
		    "img_cat: Error reading image file at offset: %"
		    PRIuOFF ", len: %" PRIuOFF ", return: %" PRIuOFF "\n",
		    done, len, cnt);
	    }
	    else {
		tsk_error_print(stderr);
	    }
	    img->close(img);
	    exit(1);
	}

	if (fwrite(buf, cnt, 1, stdout) != 1) {
	    tsk_errno = TSK_ERR_IMG_WRITE;
	    snprintf(tsk_errstr, TSK_ERRSTR_L,
		"img_cat: Error writing to stdout:  %s", strerror(errno));
	    tsk_error_print(stderr);
	    img->close(img);
	    exit(1);
	}
    }

    img->close(img);
    exit(0);
}
