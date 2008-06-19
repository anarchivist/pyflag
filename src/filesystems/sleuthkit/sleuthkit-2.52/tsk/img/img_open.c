/*
 * $Date: 2007/12/20 16:06:58 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2006-2007 Brian Carrier, Basis Technology.  All Rights reserved
 * Copyright (c) 2005 Brian Carrier.  All rights reserved
 *
 * tsk_img_open
 *
 * This software is distributed under the Common Public License 1.0
 */

/**
 * \file img_open.c
 * Contains the basic img_open function call, that interfaces with
 * the format specific _open calls
 */

#include "tsk_img_i.h"

#include "raw.h"
#include "split.h"

#if HAVE_LIBAFFLIB
typedef int bool;
#include "aff.h"
#endif

#if HAVE_LIBEWF
#include "ewf.h"
#endif

/**
 * Open one or more files as a disk image.  This serves as a
 * wrapper around the specific types of disk image formats. You 
 * can specify the type or autodetection can be used.
 *
 * @param type The text a user supplied for the type of format.
 * Examples include "raw", "split", "aff", etc.
 * @param num_img The number of images that are being considered.
 * @param images The path to the files (the number of files must
 * be equal to num_img)
 *
 * @return Pointer to the Image state structure or NULL on error
 */
TSK_IMG_INFO *
tsk_img_open(const TSK_TCHAR * type, const int num_img,
    const TSK_TCHAR ** images)
{
    TSK_IMG_INFO *img_info = NULL;
    TSK_TCHAR *tp, *next;
    TSK_TCHAR type_lcl[128], *type_lcl_p;
    const TSK_TCHAR **img_tmp;
    int num_img_tmp = num_img;

    // Get rid of any old error messages laying around
    tsk_error_reset();

    if ((num_img == 0) || (images[0] == NULL)) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_IMG_NOFILE;
        snprintf(tsk_errstr, TSK_ERRSTR_L, "tsk_img_open");
        tsk_errstr2[0] = '\0';
        return NULL;
    }

    if (tsk_verbose)
        TFPRINTF(stderr,
            _TSK_T("tsk_img_open: Type: %s   NumImg: %d  Img1: %s\n"),
            (type ? type : _TSK_T("n/a")), num_img, images[0]);

    // only the first in list (lowest) layer gets the files
    img_tmp = images;

    /* If no type is given, then we use the autodetection methods 
     * In case the image file matches the signatures of multiple formats,
     * we try all of the embedded formats 
     */

    if (type == NULL) {
        TSK_IMG_INFO *img_set = NULL;
#if HAVE_LIBAFFLIB || HAVE_LIBEWF
        char *set = NULL;
#endif
        struct STAT_STR stat_buf;

        /* First verify that the image file exists */
        if (TSTAT(images[0], &stat_buf) < 0) {

            // special case to handle windows objects
#if defined(TSK_WIN32)
            if ((images[0][0] == _TSK_T('\\'))
                && (images[0][1] == _TSK_T('\\'))
                && (images[0][2] == _TSK_T('.'))
                && (images[0][3] == _TSK_T('\\'))) {
                if (tsk_verbose)
                    TFPRINTF(stderr,
                        _TSK_T
                        ("tsk_img_open: Ignoring stat error because of windows object: %s\n"),
                        images[0]);
            }
#endif

            /* AFFLIB supports s3 storage on Amazon, so skip those 'file' paths */
#if HAVE_LIBAFFLIB
#if defined(TSK_WIN32)
            else
#endif
                if (((images[0][0] == _TSK_T('s'))
                    && (images[0][1] == _TSK_T('3'))
                    && (images[0][2] == _TSK_T(':'))
                    && (images[0][3] == _TSK_T('/'))
                    && (images[0][4] == _TSK_T('/'))) ||
                ((images[0][0] == _TSK_T('h'))
                    && (images[0][1] == _TSK_T('t'))
                    && (images[0][2] == _TSK_T('t'))
                    && (images[0][3] == _TSK_T('p'))
                    && (images[0][4] == _TSK_T(':'))
                    && (images[0][5] == _TSK_T('/'))
                    && (images[0][6] == _TSK_T('/')))) {
                if (tsk_verbose)
                    TFPRINTF(stderr,
                        _TSK_T
                        ("tsk_img_open: Ignoring stat error because of s3/http object: %s\n"),
                        images[0]);

            }
#endif

#if HAVE_LIBAFFLIB || defined(TSK_WIN32)
            else {
#endif
                tsk_error_reset();
                tsk_errno = TSK_ERR_IMG_STAT;
                snprintf(tsk_errstr, TSK_ERRSTR_L, "%" PRIttocTSK " : %s",
                    images[0], strerror(errno));
                return NULL;
#if HAVE_LIBAFFLIB || defined(TSK_WIN32)
            }
#endif
        }

        // we rely on tsk_errno, so make sure it is 0
        tsk_error_reset();

        /* Try the non-raw formats first */
#if HAVE_LIBAFFLIB
        if ((img_info = aff_open(images, NULL)) != NULL) {
            set = "AFF";
            img_set = img_info;
        }
        else {
            tsk_error_reset();
        }
#endif

#if HAVE_LIBEWF
        if ((img_info = ewf_open(num_img, images, NULL)) != NULL) {
            if (set == NULL) {
                set = "EWF";
                img_set = img_info;
            }
            else {
                img_set->close(img_set);
                img_info->close(img_info);
                tsk_error_reset();
                tsk_errno = TSK_ERR_IMG_UNKTYPE;
                snprintf(tsk_errstr, TSK_ERRSTR_L, "EWF or %s", set);
                return NULL;
            }
        }
        else {
            tsk_error_reset();
        }
#endif
        if (img_set != NULL)
            return img_set;

        /* We'll use the raw format */
        if (num_img == 1) {
            if ((img_info = raw_open(images, NULL)) != NULL) {
                return img_info;
            }
            else if (tsk_errno) {
                return NULL;
            }
        }
        else {
            if ((img_info = split_open(num_img, images, NULL)) != NULL) {
                return img_info;
            }
            else if (tsk_errno) {
                return NULL;
            }
        }
        tsk_errno = TSK_ERR_IMG_UNKTYPE;
        tsk_errstr[0] = '\0';
        tsk_errstr2[0] = '\0';
        return NULL;
    }

    /*
     * Type values
     * Make a local copy that we can modify the string as we parse it
     */
    TSTRNCPY(type_lcl, type, 128);
    type_lcl_p = type_lcl;

    /* We parse this and go up in the layers */
    tp = TSTRTOK(type_lcl, _TSK_T(","));
    while (tp != NULL) {
        uint8_t imgtype;

        next = TSTRTOK(NULL, _TSK_T(","));

        imgtype = tsk_img_parse_type(type);
        switch (imgtype) {
        case TSK_IMG_INFO_TYPE_RAW_SING:

            /* If we have more than one image name, and raw was the only
             * type given, then use split */
            if ((num_img > 1) && (next == NULL) && (img_tmp != NULL)) {
                img_info = split_open(num_img_tmp, img_tmp, img_info);
                num_img_tmp = 0;
            }
            else {
                img_info = raw_open(img_tmp, img_info);
            }
            img_tmp = NULL;
            break;

        case TSK_IMG_INFO_TYPE_RAW_SPLIT:

            /* If only one image file is given, and only one type was
             * given then use raw */
            if ((num_img == 1) && (next == NULL) && (img_tmp != NULL)) {
                img_info = raw_open(img_tmp, img_info);
            }
            else {
                img_info = split_open(num_img_tmp, img_tmp, img_info);
                num_img_tmp = 0;
            }

            img_tmp = NULL;
            break;

#if HAVE_LIBAFFLIB
        case TSK_IMG_INFO_TYPE_AFF_AFF:
        case TSK_IMG_INFO_TYPE_AFF_AFD:
        case TSK_IMG_INFO_TYPE_AFF_AFM:
            img_info = aff_open(img_tmp, img_info);
            break;
#endif

#if HAVE_LIBEWF
        case TSK_IMG_INFO_TYPE_EWF_EWF:
            img_info = ewf_open(num_img_tmp, img_tmp, img_info);
            break;
#endif

        default:
            tsk_error_reset();
            tsk_errno = TSK_ERR_IMG_UNSUPTYPE;
            snprintf(tsk_errstr, TSK_ERRSTR_L, "%" PRIttocTSK, tp);
            return NULL;
        }

        /* Advance the pointer */
        tp = next;
    }

    /* Return the highest layer */
    return img_info;
}
