/*
** The Sleuth Kit
**
** $Date: 2007/04/04 18:18:52 $
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2006 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
** Copyright (c) 1997,1998,1999, International Business Machines
** Corporation and others. All Rights Reserved.
**
*/

/* TCT:
 *
 * LICENSE
 *	This software is distributed under the IBM Public License.
 * AUTHOR(S)
 *	Wietse Venema
 *	IBM T.J. Watson Research
 *	P.O. Box 704
 *	Yorktown Heights, NY 10598, USA
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
        ("usage: %s [-aAbelvV] [-f fstype] [-i imgtype] [-o imgoffset] image [images] [start-stop]\n"),
        progname);
    tsk_fprintf(stderr, "\t-b: no block padding\n");
    tsk_fprintf(stderr, "\t-e: every block\n");
    tsk_fprintf(stderr,
        "\t-l: print details in time machine list format\n");
    tsk_fprintf(stderr, "\t-a: Display allocated blocks\n");
    tsk_fprintf(stderr, "\t-A: Display unallocated blocks\n");
    tsk_fprintf(stderr,
        "\t-f fstype: File system type (use '-f list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-i imgtype: The format of the image file (use '-i list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-o imgoffset: The offset of the file system in the image (in sectors)\n");
    tsk_fprintf(stderr,
        "\t-s: print slack space only (other flags are ignored\n");
    tsk_fprintf(stderr, "\t-v: verbose to stderr\n");
    tsk_fprintf(stderr, "\t-V: print version\n");

    exit(1);
}






/* main - open file system, list block info */

int
MAIN(int argc, TSK_TCHAR ** argv)
{
    TSK_TCHAR *fstype = NULL;
    TSK_TCHAR *imgtype = NULL, *cp, *dash;
    TSK_FS_INFO *fs;
    TSK_IMG_INFO *img;
    DADDR_T bstart = 0, blast = 0;
    int ch;
    int flags =
        TSK_FS_BLOCK_FLAG_UNALLOC | TSK_FS_BLOCK_FLAG_ALIGN |
        TSK_FS_BLOCK_FLAG_META | TSK_FS_BLOCK_FLAG_CONT;

    char lclflags = TSK_FS_DLS_CAT, set_bounds = 1;
    SSIZE_T imgoff = 0;

    progname = argv[0];
    setlocale(LC_ALL, "");

    while ((ch = getopt(argc, argv, _TSK_T("aAbef:i:lo:svV"))) > 0) {
        switch (ch) {
        case _TSK_T('?'):
        default:
            TFPRINTF(stderr, _TSK_T("Invalid argument: %s\n"),
                argv[optind]);
            usage();
        case _TSK_T('a'):
            flags |= TSK_FS_BLOCK_FLAG_ALLOC;
            break;
        case _TSK_T('A'):
            flags |= TSK_FS_BLOCK_FLAG_UNALLOC;
            break;
        case _TSK_T('b'):
            flags &= ~TSK_FS_BLOCK_FLAG_ALIGN;
            break;
        case _TSK_T('e'):
            flags |= (TSK_FS_BLOCK_FLAG_ALLOC | TSK_FS_BLOCK_FLAG_UNALLOC);
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
        case _TSK_T('l'):
            lclflags = TSK_FS_DLS_LIST;
            break;
        case _TSK_T('o'):
            if ((imgoff = tsk_parse_offset(optarg)) == -1) {
                tsk_error_print(stderr);
                exit(1);
            }
            break;
        case _TSK_T('s'):
            lclflags |= TSK_FS_DLS_SLACK;
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

    /* Slack has only the image name */
    if (lclflags & TSK_FS_DLS_SLACK) {
        if (lclflags & TSK_FS_DLS_LIST) {
            tsk_fprintf(stderr,
                "Other options ignored with the slack space flag, try again\n");
            exit(1);
        }

        /* There should be no other arguments */
        img =
            tsk_img_open(imgtype, argc - optind,
            (const TSK_TCHAR **) &argv[optind]);

        if (img == NULL) {
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
    }
    else {

        /* We need to determine if the block range was given */
        if ((dash = TSTRCHR(argv[argc - 1], _TSK_T('-'))) == NULL) {
            /* No dash in arg - therefore it is an image file name */
            if ((img =
                    tsk_img_open(imgtype, argc - optind,
                        (const TSK_TCHAR **) &argv[optind])) == NULL) {
                tsk_error_print(stderr);
                exit(1);
            }

            set_bounds = 1;
        }
        else {
            /* We have a dash, but it could be part of the file name */
            *dash = '\0';

            bstart = TSTRTOULL(argv[argc - 1], &cp, 0);
            if (*cp || *cp == *argv[argc - 1]) {
                /* Not a number - consider it a file name */
                *dash = _TSK_T('-');
                if ((img =
                        tsk_img_open(imgtype, argc - optind,
                            (const TSK_TCHAR **) &argv[optind])) == NULL) {
                    tsk_error_print(stderr);
                    exit(1);
                }

                set_bounds = 1;
            }
            else {
                /* Check after the dash */
                dash++;
                blast = TSTRTOULL(dash, &cp, 0);
                if (*cp || *cp == *dash) {
                    /* Not a number - consider it a file name */
                    dash--;
                    *dash = _TSK_T('-');
                    if ((img =
                            tsk_img_open(imgtype, argc - optind,
                                (const TSK_TCHAR **) &argv[optind])) ==
                        NULL) {
                        tsk_error_print(stderr);
                        exit(1);
                    }

                    set_bounds = 1;
                }
                else {

                    set_bounds = 0;
                    /* It was a block range, so do not include it in the open */
                    if ((img =
                            tsk_img_open(imgtype, argc - optind - 1,
                                (const TSK_TCHAR **) &argv[optind])) ==
                        NULL) {
                        tsk_error_print(stderr);
                        exit(1);
                    }
                }
            }
        }

        if ((fs = tsk_fs_open(img, imgoff, fstype)) == NULL) {
            tsk_error_print(stderr);
            if (tsk_errno == TSK_ERR_FS_UNSUPTYPE)
                tsk_fs_print_types(stderr);
            img->close(img);
            exit(1);
        }


        /* do we need to set the range or just check them? */
        if (set_bounds) {
            bstart = fs->first_block;
            blast = fs->last_block;
        }
        else {
            if (bstart < fs->first_block)
                bstart = fs->first_block;

            if (blast > fs->last_block)
                blast = fs->last_block;
        }
    }

    if (tsk_fs_dls(fs, lclflags, bstart, blast, flags)) {
        tsk_error_print(stderr);
        fs->close(fs);
        img->close(img);
        exit(1);
    }

    fs->close(fs);
    img->close(img);
    exit(0);
}
