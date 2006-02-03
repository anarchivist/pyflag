/*
 * $Date: 2005/09/02 23:34:04 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2005 Brian Carrier.  All rights reserved
 *
 * raw
 *
 * This software is distributed under the Common Public License 1.0
 *
 */

#include "img_tools.h"
#include "raw.h"



static OFF_T
raw_read_random(IMG_INFO * img_info, char *buf, OFF_T len, OFF_T offset)
{
    OFF_T cnt;
    IMG_RAW_INFO *raw_info = (IMG_RAW_INFO *) img_info;

    if (verbose)
	fprintf(stderr,
		"raw_read_random: byte offset: %" PRIuOFF " len: %" PRIuOFF
		"\n", offset, len);

    // is there another layer?
    if (img_info->next) {
	return img_info->next->read_random(img_info->next, buf, len,
					   offset);
    }

    // Read the data
    else {
	off_t tot_offset = offset + img_info->offset;

	if (raw_info->seek_pos != tot_offset) {
	    if (lseek(raw_info->fd, tot_offset, SEEK_SET) != tot_offset) {
		return 0;
	    }
	    raw_info->seek_pos = tot_offset;
	}

	cnt = read(raw_info->fd, buf, len);
	raw_info->seek_pos += cnt;
	return cnt;
    }
}

OFF_T
raw_get_size(IMG_INFO * img_info)
{
    return img_info->size;
}

void
raw_imgstat(IMG_INFO * img_info, FILE * hFile)
{
    fprintf(hFile, "IMAGE FILE INFORMATION\n");
    fprintf(hFile, "--------------------------------------------\n");
    fprintf(hFile, "Image Type: raw\n");
    fprintf(hFile, "\nSize in bytes: %" PRIuOFF "\n", img_info->size);
    return;
}

void
raw_close(IMG_INFO * img_info)
{
    IMG_RAW_INFO *raw_info = (IMG_RAW_INFO *) img_info;
    close(raw_info->fd);
}


IMG_INFO *
raw_open(OFF_T offset, const char **images, IMG_INFO * next)
{
    IMG_RAW_INFO *raw_info;
    IMG_INFO *img_info;

    raw_info = (IMG_RAW_INFO *) mymalloc(sizeof(IMG_RAW_INFO));
    memset((void *) raw_info, 0, sizeof(IMG_RAW_INFO));

    img_info = (IMG_INFO *) raw_info;

    img_info->itype = IMG_RAW;
    img_info->offset = offset;
    img_info->read_random = raw_read_random;
    img_info->get_size = raw_get_size;
    img_info->close = raw_close;
    img_info->imgstat = raw_imgstat;

    if (next) {
	img_info->next = next;
	img_info->size = next->get_size(next);
    }

    /* Open the file */
    else {
	if ((raw_info->fd = open(images[0], O_RDONLY)) < 0)
	    error("raw_open: open %s: %m", images[0]);

	img_info->size = lseek(raw_info->fd, 0, SEEK_END);
	lseek(raw_info->fd, 0, SEEK_SET);
	raw_info->seek_pos = 0;
    }

    return img_info;
}
