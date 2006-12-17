/*
 * $Date: 2006/12/07 16:38:18 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2006 Brian Carrier, Basis Technology.  All Rights reserved
 * Copyright (c) 2005 Brian Carrier.  All rights reserved
 *
 * img_open
 *
 *
 * This software is distributed under the Common Public License 1.0
 *
 */
#include <sys/stat.h>
#include <string.h>
#include "img_tools.h"

#include "raw.h"
#include "split.h"

#undef USE_LIBAFF
#if defined(USE_LIBAFF)
typedef int bool;
#include "aff.h"
#endif

#undef USE_LIBEWF
#if defined(USE_LIBEWF)
#include "ewf.h"
#endif

/*
 * type is a list of types: "raw", "split", "split,raid", 
 * offset is the sector offset for the file system or other code to use when reading:
 *      "63", "63@512", "62@2048"
 * num_img is the number of images in the last argument
 * images is the array of image names to open
 *
 * The highest layer is returned or NULL if an error occurs
 */
IMG_INFO *
img_open(const TSK_TCHAR * type, const int num_img,
    const TSK_TCHAR ** images)
{
    IMG_INFO *img_info = NULL;
    TSK_TCHAR *tp, *next;
    TSK_TCHAR type_lcl[128], *type_lcl_p;
    const TSK_TCHAR **img_tmp;
    int num_img_tmp = num_img;

    // Get rid of any old error messages laying around
    tsk_error_reset();

    if ((num_img == 0) || (images[0] == NULL)) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_IMG_NOFILE;
	snprintf(tsk_errstr, TSK_ERRSTR_L, "img_open");
	tsk_errstr2[0] = '\0';
	return NULL;
    }

    if (verbose)
	TFPRINTF(stderr,
	    _TSK_T("img_open: Type: %s   NumImg: %d  Img1: %s\n"),
	    (type ? type : _TSK_T("n/a")), num_img, images[0]);

    // only the first in list (lowest) layer gets the files
    img_tmp = images;

    /* If no type is given, then we use the autodetection methods 
     * In case the image file matches the signatures of multiple formats,
     * we try all of the embedded formats 
     */

    if (type == NULL) {
	IMG_INFO *img_set = NULL;
	char *set = NULL;
	struct STAT_STR stat_buf;

	/* First verify that the image file exists */
	if (TSTAT(images[0], &stat_buf) == -1) {
	    // special case to handle windows objects
#ifdef TSK_WIN32
	    if ((images[0][0] == _TSK_T('\\'))
		&& (images[0][1] == _TSK_T('\\'))
		&& (images[0][2] == _TSK_T('.'))
		&& (images[0][3] == _TSK_T('\\'))) {
		if (verbose)
		    TFPRINTF(stderr,
			_TSK_T
			("img_open: Ignoring stat error because of windows object: %s\n"),
			images[0]);
	    }
	    else {
#endif
		tsk_error_reset();
		tsk_errno = TSK_ERR_IMG_STAT;
		snprintf(tsk_errstr, TSK_ERRSTR_L, "%s : %s", images[0],
		    strerror(errno));
		return NULL;
#ifdef TSK_WIN32
	    }
#endif
	}

	// we rely on tsk_errno, so make sure it is 0
	tsk_error_reset();

	/* Try the non-raw formats first */
#if defined(USE_LIBAFF)
	if ((img_info = aff_open(images, NULL)) != NULL) {
	    set = "AFF";
	    img_set = img_info;
	}
	else {
	    tsk_error_reset();
	}
#endif

#if defined(USE_LIBEWF)
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

	imgtype = img_parse_type(type);
	switch (imgtype) {
	case RAW_SING:

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

	case RAW_SPLIT:

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

#if defined(USE_LIBAFF)
	case AFF_AFF:
	case AFF_AFD:
	case AFF_AFM:
	    img_info = aff_open(img_tmp, img_info);
	    break;
#endif

#if defined(USE_LIBEWF)
	case EWF_EWF:
	    img_info = ewf_open(num_img_tmp, img_tmp, img_info);
	    break;
#endif

	default:
	    tsk_error_reset();
	    tsk_errno = TSK_ERR_IMG_UNSUPTYPE;
	    snprintf(tsk_errstr, TSK_ERRSTR_L, "%s", tp);
	    return NULL;
	}

	/* Advance the pointer */
	tp = next;
    }

    /* Return the highest layer */
    return img_info;
}
