/*
 * imgstat
 * The Sleuth Kit 
 *
 * $Date: 2007/03/20 21:54:53 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2005 Brian Carrier.  All rights reserved 
 *
 *
 * This software is distributed under the Common Public License 1.0
 *
 */
#include "img_tools.h"

static TSK_TCHAR *progname;

static void
usage()
{
    TFPRINTF(stderr, _TSK_T("usage: %s [-tvV] [-i imgtype] image\n"),
        progname);
    tsk_fprintf(stderr, "\t-t: display type only\n");
    tsk_fprintf(stderr,
        "\t-i imgtype: The format of the image file (use '-i list' for list of supported types)\n");
    tsk_fprintf(stderr, "\t-v: verbose output to stderr\n");
    tsk_fprintf(stderr, "\t-V: Print version\n");

    exit(1);
}


int
MAIN(int argc, TSK_TCHAR ** argv)
{
    TSK_IMG_INFO *img;
    TSK_TCHAR *imgtype = NULL;
    int ch;
    uint8_t type = 0;

    progname = argv[0];

    while ((ch = getopt(argc, argv, _TSK_T("i:tvV"))) > 0) {
        switch (ch) {
        case _TSK_T('?'):
        default:
            TFPRINTF(stderr, _TSK_T("Invalid argument: %s\n"),
                argv[optind]);
            usage();

        case _TSK_T('i'):
            imgtype = optarg;
            if (TSTRCMP(imgtype, _TSK_T("list")) == 0) {
                tsk_img_print_types(stderr);
                exit(1);
            }
            break;

        case _TSK_T('t'):
            type = 1;
            break;

        case _TSK_T('v'):
            tsk_verbose++;
            break;

        case _TSK_T('V'):
            tsk_print_version(stdout);
            exit(0);
        }
    }

    /* We need at least one more argument */
    if (optind >= argc) {
        tsk_fprintf(stderr, "Missing image name\n");
        usage();
    }

    if ((img =
            tsk_img_open(imgtype, argc - optind,
                (const TSK_TCHAR **) &argv[optind])) == NULL) {
        tsk_error_print(stderr);
        exit(1);
    }

    if (type) {
        char *str = tsk_img_get_type(img->itype);
        tsk_printf("%s\n", str);
    }
    else {
        img->imgstat(img, stdout);
    }

    img->close(img);
    exit(0);
}
