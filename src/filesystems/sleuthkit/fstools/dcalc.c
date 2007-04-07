/*
** dcalc
** The Sleuth Kit 
**
** $Date: 2007/03/23 15:01:31 $
**
** Calculates the corresponding block number between 'dls' and 'dd' images
** when given an 'dls' block number, it determines the block number it
** had in a 'dd' image.  When given a 'dd' image, it determines the
** value it would have in a 'dls' image (if the block is unallocated)
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2006-2007 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier. All Rights reserved
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc. All Rights reserved
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

static void
usage()
{
    TFPRINTF(stderr,
        _TSK_T
        ("usage: %s [-dsu unit_addr] [-vV] [-f fstype] [-i imgtype] [-o imgoffset] image [images]\n"),
        progname);
    tsk_fprintf(stderr, "Slowly calculates the opposite block number\n");
    tsk_fprintf(stderr, "\tOne of the following must be given:\n");
    tsk_fprintf(stderr,
        "\t  -d: The given address is from a 'dd' image \n");
    tsk_fprintf(stderr,
        "\t  -s: The given address is from a 'dls -s' (slack) image\n");
    tsk_fprintf(stderr,
        "\t  -u: The given address is from a 'dls' (unallocated) image\n");
    tsk_fprintf(stderr,
        "\t-f fstype: The file system type (use '-f list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-i imgtype: The format of the image file (use '-i list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-o imgoffset: The offset of the file system in the image (in sectors)\n");
    tsk_fprintf(stderr, "\t-v: verbose output to stderr\n");
    tsk_fprintf(stderr, "\t-V: Print version\n");

    exit(1);
}



int
MAIN(int argc, TSK_TCHAR ** argv)
{
    TSK_TCHAR *fstype = NULL;
    TSK_TCHAR *imgtype = NULL;
    int ch;
    TSK_TCHAR *cp;
    uint8_t type = 0;
    TSK_FS_INFO *fs;
    TSK_IMG_INFO *img;
    int set = 0;
    SSIZE_T imgoff = 0;
    DADDR_T count = 0;

    progname = argv[0];
    setlocale(LC_ALL, "");

    while ((ch = getopt(argc, argv, _TSK_T("d:f:i:o:s:u:vV"))) > 0) {
        switch (ch) {
        case _TSK_T('?'):
        default:
            TFPRINTF(stderr, _TSK_T("Invalid argument: %s\n"),
                argv[optind]);
            usage();

        case _TSK_T('d'):
            type |= TSK_FS_DCALC_DD;
            count = TSTRTOULL(optarg, &cp, 0);
            if (*cp || *cp == *optarg) {
                TFPRINTF(stderr, _TSK_T("Invalid address: %s\n"), optarg);
                usage();
            }
            set = 1;
            break;

        case _TSK_T('f'):
            fstype = optarg;
            if (TSTRCMP(fstype, _TSK_T("list")) == 0) {
                tsk_fs_print_types(stderr);
                exit(1);
            }
            break;

        case _TSK_T('i'):
            imgtype = optarg;
            if (TSTRCMP(imgtype, _TSK_T("list")) == 0) {
                tsk_img_print_types(stderr);
                exit(1);
            }
            break;

        case _TSK_T('o'):
            if ((imgoff = tsk_parse_offset(optarg)) == -1) {
                tsk_error_print(stderr);
                exit(1);
            }
            break;

        case _TSK_T('s'):
            type |= TSK_FS_DCALC_SLACK;
            count = TSTRTOULL(optarg, &cp, 0);
            if (*cp || *cp == *optarg) {
                TFPRINTF(stderr, _TSK_T("Invalid address: %s\n"), optarg);
                usage();
            }
            set = 1;
            break;

        case _TSK_T('u'):
            type |= TSK_FS_DCALC_DLS;
            count = TSTRTOULL(optarg, &cp, 0);
            if (*cp || *cp == *optarg) {
                TFPRINTF(stderr, _TSK_T("Invalid address: %s\n"), optarg);
                usage();
            }
            set = 1;
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
    if (optind == argc) {
        tsk_fprintf(stderr, "Missing image name\n");
        usage();
    }

    if ((!type) || (set == 0)) {
        tsk_fprintf(stderr, "Calculation type not given (-u, -d, -s)\n");
        usage();
    }

    if ((type & TSK_FS_DCALC_DD) && (type & TSK_FS_DCALC_DLS)
        && (type & TSK_FS_DCALC_SLACK)) {
        tsk_fprintf(stderr, "Only one block type can be given\n");
        usage();
    }


    if ((img =
            tsk_img_open(imgtype, argc - optind,
                (const TSK_TCHAR **) &argv[optind])) == NULL) {
        tsk_error_print(stderr);
        exit(1);
    }

    if ((fs = tsk_fs_open(img, imgoff, fstype)) == NULL) {
        tsk_error_print(stderr);
        if (tsk_errno == TSK_ERR_FS_UNSUPTYPE)
            tsk_fs_print_types(stderr);
        img->close(img);
        exit(1);
    }

    if (-1 == tsk_fs_dcalc(fs, type, count)) {
        tsk_error_print(stderr);
        fs->close(fs);
        img->close(img);
        exit(1);
    }

    fs->close(fs);
    img->close(img);

    exit(0);
}
