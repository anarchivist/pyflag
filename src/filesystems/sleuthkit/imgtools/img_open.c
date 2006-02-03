/*
 * $Date: 2005/09/02 23:34:04 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2005 Brian Carrier.  All rights reserved
 *
 * img_open
 *
 *
 * This software is distributed under the Common Public License 1.0
 *
 */

#include <string.h>
#include "img_tools.h"

#include "raw.h"
#include "split.h"


/*
 * type is a list of types: "raw", "split", "split,raid", 
 * offset is the sector offset for the file system or other code to use when reading:
 *      "63", "63@512", "62@2048"
 * num_img is the number of images in the last argument
 * images is the array of image names to open
 *
 * The highest layer is returned
 */
IMG_INFO *
img_open(const char *type, const char *offset, const int num_img,
	 const char **images)
{
    IMG_INFO *img_info = NULL;
    char *tp, type_lcl[128], *type_lcl_p, *next;
    const char **img_tmp;
    OFF_T offset_b = 0, offset_tmp = 0;
    int num_img_tmp = num_img;


    if ((num_img == 0) || (images[0] == NULL)) {
	fprintf(stderr, "img_open: invalid image names (0 or NULL)\n");
	exit(1);
    }

    if (verbose)
	fprintf(stderr,
		"img_open: Type: %s  Offset: %s:  NumImg: %d  Img1: %s\n",
		type, offset, num_img, images[0]);

    // only the first in list (lowest) layer gets the files
    img_tmp = images;

    /* Parse the offset value */
    if (offset != NULL) {
	char offset_lcl[32], *offset_lcl_p;
	DADDR_T num_blk;
	char *cp, *at;
	int bsize = 512;

	strncpy(offset_lcl, offset, 32);
	offset_lcl_p = offset_lcl;

	/* Check for the x@y setup */
	if ((at = strchr(offset_lcl_p, '@')) != NULL) {
	    *at = '\0';
	    at++;

	    bsize = strtoul(at, &cp, 0);
	    if (*cp || cp == at) {
		fprintf(stderr, "Invalid image offset block size: %s\n",
			at);
		exit(1);
	    }
	    else if (bsize % 512) {
		fprintf(stderr,
			"Invalid image offset block size (not multiple of 512): %d\n",
			bsize);
		exit(1);
	    }
	}

	offset_lcl_p = offset_lcl;

	/* remove leading 0s */
	while ((offset_lcl_p[0] != '\0') && (offset_lcl_p[0] == '0'))
	    offset_lcl_p++;

	if (offset_lcl_p[0] != '\0') {
	    num_blk = strtoull(offset_lcl_p, &cp, 0);
	    if (*cp || cp == offset_lcl_p) {
		fprintf(stderr, "Invalid image offset: %s\n",
			offset_lcl_p);
		exit(1);
	    }
	    offset_b = num_blk * bsize;
	}
    }

    /* If no type is given, then use raw or split */
    if (type == NULL) {
	if (num_img == 1)
	    return raw_open(offset_b, images, NULL);
	else
	    return split_open(offset_b, num_img, images, NULL);
    }

    /*
     * Type values
     * Make a local copy that we can modify the string as we parse it
     */
    strncpy(type_lcl, type, 128);
    type_lcl_p = type_lcl;

    /* We parse this and go up in the layers */
    tp = strtok(type_lcl, ",");
    while (tp != NULL) {
	next = strtok(NULL, ",");

	/* only the last in list (highest layer) gets the offset value */
	if ((next == NULL) && (offset != NULL))
	    offset_tmp = offset_b;

	if (strcmp(tp, "raw") == 0) {
	    /* If we have more than one image name, and raw was the only
	     * type given, then use split */
	    if ((num_img > 1) && (next == NULL) && (img_tmp != NULL)) {
		img_info =
		    split_open(offset_tmp, num_img_tmp, img_tmp, img_info);
		num_img_tmp = 0;
	    }
	    else {
		img_info = raw_open(offset_tmp, img_tmp, img_info);
	    }
	    img_tmp = NULL;
	}
	else if (strcmp(tp, "split") == 0) {
	    /* If only one image file is given, and only one type was
	     * given then use raw */
	    if ((num_img == 1) && (next == NULL) && (img_tmp != NULL)) {
		img_info = raw_open(offset_tmp, img_tmp, img_info);
	    }
	    else {
		img_info =
		    split_open(offset_tmp, num_img_tmp, img_tmp, img_info);
		num_img_tmp = 0;
	    }

	    img_tmp = NULL;
	}
	else {
	    fprintf(stderr, "Unknown image type: %s\n", tp);
	    exit(1);
	}

	/* Advance the pointer */
	tp = next;
    }

    /* Return the highest layer */
    return img_info;
}

void
img_print_types(FILE * hFile)
{
    fprintf(hFile, "\traw\n");
    fprintf(hFile, "\tsplit\n");
}

char *
img_get_type(uint8_t type)
{
    if (type == IMG_RAW)
	return "raw";
    else if (type == IMG_SPLIT)
	return "split";
    else
	return "unknown";
}
