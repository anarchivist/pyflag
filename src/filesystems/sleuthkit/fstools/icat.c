/*
** icat 
** The Sleuth Kit 
**
** $Date: 2007/04/04 18:18:53 $
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

 * LICENSE
 *	This software is distributed under the IBM Public License.
 * AUTHOR(S)
 *	Wietse Venema
 *	IBM T.J. Watson Research
 *	P.O. Box 704
 *	Yorktown Heights, NY 10598, USA
 --*/
#include <locale.h>
#include "fs_tools.h"


/* usage - explain and terminate */

static TSK_TCHAR *progname;

static void
usage()
{
    TFPRINTF(stderr,
        _TSK_T
        ("usage: %s [-hHsvV] [-f fstype] [-i imgtype] [-o imgoffset] image [images] inum[-typ[-id]]\n"),
        progname);
    tsk_fprintf(stderr, "\t-h: Do not display holes in sparse files\n");
    tsk_fprintf(stderr, "\t-r: Recover deleted file\n");
    tsk_fprintf(stderr,
        "\t-R: Recover deleted file and suppress recovery errors\n");
    tsk_fprintf(stderr, "\t-s: Display slack space at end of file\n");
    tsk_fprintf(stderr,
        "\t-i imgtype: The format of the image file (use '-i list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-f fstype: File system type (use '-f list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-o imgoffset: The offset of the file system in the image (in sectors)\n");
    tsk_fprintf(stderr, "\t-v: verbose to stderr\n");
    tsk_fprintf(stderr, "\t-V: Print version\n");

    exit(1);
}

int
MAIN(int argc, TSK_TCHAR ** argv)
{
    TSK_TCHAR *fstype = NULL;
    TSK_TCHAR *imgtype = NULL;
    TSK_FS_INFO *fs;
    TSK_IMG_INFO *img;
    INUM_T inum;
    int flags = 0;
    int ch;
    uint32_t type = 0;
    uint16_t id = 0;
    int id_used = 0;
    int retval;
    SSIZE_T imgoff = 0;
    int suppress_recover_error = 0;

    progname = argv[0];
    setlocale(LC_ALL, "");

    while ((ch = getopt(argc, argv, _TSK_T("f:hi:o:rRsvV"))) > 0) {
        switch (ch) {
        case _TSK_T('?'):
        default:
            TFPRINTF(stderr, _TSK_T("Invalid argument: %s\n"),
                argv[optind]);
            usage();
        case _TSK_T('f'):
            fstype = optarg;
            if (TSTRCMP(fstype, _TSK_T("list")) == 0) {
                tsk_fs_print_types(stderr);
                exit(1);
            }
            break;
        case _TSK_T('h'):
            flags |= TSK_FS_FILE_FLAG_NOSPARSE;
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
        case _TSK_T('r'):
            flags |= TSK_FS_FILE_FLAG_RECOVER;
            break;
        case _TSK_T('R'):
            flags |= TSK_FS_FILE_FLAG_RECOVER;
            suppress_recover_error = 1;
            break;
        case _TSK_T('s'):
            flags |= TSK_FS_FILE_FLAG_SLACK;
            break;
        case _TSK_T('v'):
            tsk_verbose++;
            break;
        case _TSK_T('V'):
            tsk_print_version(stdout);
            exit(0);
        }
    }

    /* We need at least two more argument */
    if (optind + 1 >= argc) {
        tsk_fprintf(stderr, "Missing image name and/or address\n");
        usage();
    }

    /* Get the inode address */
    if (tsk_parse_inum(argv[argc - 1], &inum, &type, &id, &id_used)) {
        TFPRINTF(stderr, _TSK_T("Invalid inode address: %s\n"),
            argv[argc - 1]);
        usage();
    }

    if ((img =
            tsk_img_open(imgtype, argc - optind - 1,
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

    if (inum > fs->last_inum) {
        tsk_fprintf(stderr,
            "Metadata address too large for image (%" PRIuINUM ")\n",
            fs->last_inum);
        fs->close(fs);
        img->close(img);
        exit(1);
    }
    if (inum < fs->first_inum) {
        tsk_fprintf(stderr,
            "Metadata address too small for image (%" PRIuINUM ")\n",
            fs->first_inum);
        fs->close(fs);
        img->close(img);
        exit(1);
    }

    if (id_used)
        retval = tsk_fs_icat(fs, 0, inum, type, id, flags);
    /* If the id value was not used, then set the flag accordingly so the '0' value is ignored */
    else
        retval =
            tsk_fs_icat(fs, 0, inum, type, id,
            flags | TSK_FS_FILE_FLAG_NOID);

    if (retval) {
        if ((suppress_recover_error == 1)
            && (tsk_errno == TSK_ERR_FS_RECOVER)) {
            tsk_error_reset();
        }
        else {
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
