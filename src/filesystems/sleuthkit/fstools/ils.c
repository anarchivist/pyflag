/*
** The Sleuth Kit 
**
** $Date: 2007/04/05 16:01:59 $
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
*/

/* TCT */
/*++
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

static TSK_TCHAR *progname;

/* usage - explain and terminate */
static void
usage()
{
    TFPRINTF(stderr,
        _TSK_T
        ("usage: %s [-emOpvV] [-aAlLzZ] [-f fstype] [-i imgtype] [-o imgoffset] [-s seconds] image [images] [inum[-end]]\n"),
        progname);
    tsk_fprintf(stderr, "\t-e: Display all inodes\n");
    tsk_fprintf(stderr, "\t-m: Display output in the mactime format\n");
    tsk_fprintf(stderr,
        "\t-O: Display inodes that are unallocated, but were sill open (UFS/ExtX only)\n");
    tsk_fprintf(stderr,
        "\t-p: Display orphan inodes (unallocated with no file name)\n");
    tsk_fprintf(stderr,
        "\t-s seconds: Time skew of original machine (in seconds)\n");
    tsk_fprintf(stderr, "\t-a: Allocated inodes\n");
    tsk_fprintf(stderr, "\t-A: Unallocated inodes\n");
    tsk_fprintf(stderr, "\t-l: Linked inodes\n");
    tsk_fprintf(stderr, "\t-L: Unlinked inodes\n");
    tsk_fprintf(stderr, "\t-z: Unused inodes (ctime is 0)\n");
    tsk_fprintf(stderr, "\t-Z: Used inodes (ctime is not 0)\n");
    tsk_fprintf(stderr,
        "\t-i imgtype: The format of the image file (use '-i list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-f fstype: File system type (use '-f list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-o imgoffset: The offset of the file system in the image (in sectors)\n");
    tsk_fprintf(stderr, "\t-v: verbose output to stderr\n");
    tsk_fprintf(stderr, "\t-V: Display version number\n");
    exit(1);
}



/* main - open file system, list inode info */
int
MAIN(int argc, TSK_TCHAR ** argv)
{
    TSK_TCHAR *fstype = NULL;
    TSK_TCHAR *imgtype = NULL, *cp, *dash;
    TSK_IMG_INFO *img;
    TSK_FS_INFO *fs;
    INUM_T istart = 0, ilast = 0;
    int ch;
    int flags = TSK_FS_INODE_FLAG_UNALLOC;
    int argflags = 0;
    SSIZE_T imgoff = 0;
    int set_range = 1;
    TSK_TCHAR *image = NULL;
    int32_t sec_skew = 0;

    progname = argv[0];
    setlocale(LC_ALL, "");

    /*
     * Provide convenience options for the most commonly selected feature
     * combinations.
     */
    while ((ch = getopt(argc, argv, _TSK_T("aAef:i:lLmo:Oprs:vVzZ"))) > 0) {
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
        case _TSK_T('i'):
            imgtype = optarg;
            if (TSTRCMP(imgtype, _TSK_T("list")) == 0) {
                tsk_img_print_types(stderr);
                exit(1);
            }
            break;
        case _TSK_T('e'):
            flags |= (TSK_FS_INODE_FLAG_ALLOC | TSK_FS_INODE_FLAG_UNALLOC);
            break;
        case _TSK_T('m'):
            argflags |= TSK_FS_ILS_MAC;
            break;
        case _TSK_T('o'):
            if ((imgoff = tsk_parse_offset(optarg)) == -1) {
                tsk_error_print(stderr);
                exit(1);
            }
            break;
        case _TSK_T('O'):
            flags |= TSK_FS_INODE_FLAG_UNALLOC;
            flags &= ~TSK_FS_INODE_FLAG_ALLOC;
            argflags |= TSK_FS_ILS_OPEN;
            break;
        case _TSK_T('p'):
            flags |=
                (TSK_FS_INODE_FLAG_ORPHAN | TSK_FS_INODE_FLAG_UNALLOC);
            flags &= ~TSK_FS_INODE_FLAG_ALLOC;
            break;
        case _TSK_T('r'):
            flags |= TSK_FS_INODE_FLAG_UNALLOC;
            flags &= ~TSK_FS_INODE_FLAG_ALLOC;
            break;
        case _TSK_T('s'):
            sec_skew = TATOI(optarg);
            break;
        case _TSK_T('v'):
            tsk_verbose++;
            break;
        case _TSK_T('V'):
            tsk_print_version(stdout);
            exit(0);

            /*
             * Provide fine controls to tweak one feature at a time.
             */
        case _TSK_T('a'):
            flags |= TSK_FS_INODE_FLAG_ALLOC;
            break;
        case _TSK_T('A'):
            flags |= TSK_FS_INODE_FLAG_UNALLOC;
            break;
        case _TSK_T('l'):
            argflags |= TSK_FS_ILS_LINK;
            break;
        case _TSK_T('L'):
            argflags |= TSK_FS_ILS_UNLINK;
            break;
        case _TSK_T('z'):
            flags |= TSK_FS_INODE_FLAG_UNUSED;
            break;
        case _TSK_T('Z'):
            flags |= TSK_FS_INODE_FLAG_USED;
            break;
        }
    }

    if (optind >= argc) {
        tsk_fprintf(stderr, "Missing image name\n");
        usage();
    }

    if ((argflags & TSK_FS_ILS_LINK) && (argflags & TSK_FS_ILS_UNLINK)) {
        tsk_fprintf(stderr,
            "ERROR: Only linked or unlinked should be used\n");
        usage();
    }

    /* We need to determine if an inode or inode range was given */
    if ((dash = TSTRCHR(argv[argc - 1], _TSK_T('-'))) == NULL) {
        /* Check if is a single number */
        istart = TSTRTOULL(argv[argc - 1], &cp, 0);
        if (*cp || *cp == *argv[argc - 1]) {
            /* Not a number - consider it a file name */
            image = argv[optind];
            if ((img =
                    tsk_img_open(imgtype, argc - optind,
                        (const TSK_TCHAR **) &argv[optind])) == NULL) {
                tsk_error_print(stderr);
                exit(1);
            }
        }
        else {
            /* Single address set end addr to start */
            ilast = istart;
            set_range = 0;
            image = argv[optind];
            if ((img =
                    tsk_img_open(imgtype, argc - optind - 1,
                        (const TSK_TCHAR **) &argv[optind])) == NULL) {
                tsk_error_print(stderr);
                exit(1);
            }
        }
    }
    else {
        /* We have a dash, but it could be part of the file name */
        *dash = '\0';

        istart = TSTRTOULL(argv[argc - 1], &cp, 0);
        if (*cp || *cp == *argv[argc - 1]) {
            /* Not a number - consider it a file name */
            *dash = _TSK_T('-');
            image = argv[optind];
            if ((img =
                    tsk_img_open(imgtype, argc - optind,
                        (const TSK_TCHAR **) &argv[optind])) == NULL) {
                tsk_error_print(stderr);
                exit(1);
            }
        }
        else {
            dash++;
            ilast = TSTRTOULL(dash, &cp, 0);
            if (*cp || *cp == *dash) {
                /* Not a number - consider it a file name */
                dash--;
                *dash = '-';
                image = argv[optind];
                if ((img =
                        tsk_img_open(imgtype, argc - optind,
                            (const TSK_TCHAR **) &argv[optind])) == NULL) {
                    tsk_error_print(stderr);
                    exit(1);
                }
            }
            else {
                set_range = 0;
                /* It was a block range, so do not include it in the open */
                image = argv[optind];
                if ((img =
                        tsk_img_open(imgtype, argc - optind - 1,
                            (const TSK_TCHAR **) &argv[optind])) == NULL) {
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
    if (set_range) {
        istart = fs->first_inum;
        ilast = fs->last_inum;
    }
    else {
        if (istart < fs->first_inum)
            istart = fs->first_inum;

        if (ilast > fs->last_inum)
            ilast = fs->last_inum;
    }

    /* NTFS uses alloc and link different than UNIX so change
     * the default behavior
     *
     * The link value can be > 0 on deleted files (even when closed)
     */

    /* NTFS and FAT have no notion of deleted but still open */
    if ((argflags & TSK_FS_ILS_OPEN) &&
        (((fs->ftype & TSK_FS_INFO_TYPE_FS_MASK) ==
                TSK_FS_INFO_TYPE_NTFS_TYPE)
            || ((fs->ftype & TSK_FS_INFO_TYPE_FS_MASK) ==
                TSK_FS_INFO_TYPE_FAT_TYPE))) {
        fprintf(stderr,
            "Error: '-o' argument does not work with NTFS and FAT images\n");
        exit(1);
    }

    if (tsk_fs_ils(fs, argflags, istart, ilast, flags, sec_skew, image)) {
        tsk_error_print(stderr);
        fs->close(fs);
        img->close(img);
        exit(1);
    }

    fs->close(fs);
    img->close(img);
    exit(0);
}
