/*
 * $Date: 2006/07/05 18:54:16 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2006 Brian Carrier, Basis Technology.  All rights reserved
 * Copyright (c) 2005 Brian Carrier.  All rights reserved
 *
 * raw
 *
 * This software is distributed under the Common Public License 1.0
 *
 */


#include <sys/stat.h>
#include "img_tools.h"
#include "raw.h"


/* Return the size read and -1 if error */
static SSIZE_T
raw_read_random(IMG_INFO * img_info, OFF_T vol_offset, char *buf,
    OFF_T len, OFF_T offset)
{
    SSIZE_T cnt;
    IMG_RAW_INFO *raw_info = (IMG_RAW_INFO *) img_info;

    if (verbose)
	fprintf(stderr,
	    "raw_read_random: byte offset: %" PRIuOFF " len: %" PRIuOFF
	    "\n", offset, len);

    // is there another layer?
    if (img_info->next) {
	return img_info->next->read_random(img_info->next, vol_offset, buf,
	    len, offset);
    }

    // Read the data
    else {
	OFF_T tot_offset = offset + vol_offset;

#ifdef TSK_WIN32
	{
	    DWORD nread;

	    if (raw_info->seek_pos != tot_offset) {
		LONG lo, hi;
		OFF_T max = (OFF_T) MAXLONG + 1;

		hi = (LONG) (tot_offset / max);
		lo = (LONG) (tot_offset - max * hi);

		if (FALSE == SetFilePointer(raw_info->fd, lo, &hi,
			FILE_BEGIN)) {
		    tsk_errno = TSK_ERR_IMG_SEEK;
		    snprintf(tsk_errstr, TSK_ERRSTR_L,
			"raw_read_random - %" PRIuOFF, tot_offset);
		    tsk_errstr2[0] = '\0';
		    return -1;
		}
		raw_info->seek_pos = tot_offset;
	    }

	    if (FALSE == ReadFile(raw_info->fd, buf, (DWORD) len,
		    &nread, NULL)) {
		tsk_errno = TSK_ERR_IMG_READ;
		snprintf(tsk_errstr, TSK_ERRSTR_L,
		    "raw_read_random - offset: %" PRIuOFF " - len: %"
		    PRIuOFF, tot_offset, len);
		tsk_errstr2[0] = '\0';
		return -1;
	    }
	    cnt = (SSIZE_T) nread;
	}
#else
	if (raw_info->seek_pos != tot_offset) {
	    if (lseek(raw_info->fd, tot_offset, SEEK_SET) != tot_offset) {
		tsk_errno = TSK_ERR_IMG_SEEK;
		snprintf(tsk_errstr, TSK_ERRSTR_L,
		    "raw_read_random - %" PRIuOFF " - %s",
		    tot_offset, strerror(errno));
		tsk_errstr2[0] = '\0';
		return -1;
	    }
	    raw_info->seek_pos = tot_offset;
	}

	cnt = read(raw_info->fd, buf, len);
	if (cnt == -1) {
	    tsk_errno = TSK_ERR_IMG_READ;
	    snprintf(tsk_errstr, TSK_ERRSTR_L,
		"raw_read_random - offset: %" PRIuOFF " - len: %"
		PRIuOFF " - %s", tot_offset, len, strerror(errno));
	    tsk_errstr2[0] = '\0';
	    return -1;
	}
#endif
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
#ifdef TSK_WIN32
    CloseHandle(raw_info->fd);
#else
    close(raw_info->fd);
#endif
}


/*
 *  Open the file as a raw image.  Return the IMG_INFO structure
 *  or NULL if the file cannot be opened.  There are no magic values
 *  to test for a raw file
 */
IMG_INFO *
raw_open(const char **images, IMG_INFO * next)
{
    IMG_RAW_INFO *raw_info;
    IMG_INFO *img_info;

    if ((raw_info =
	    (IMG_RAW_INFO *) mymalloc(sizeof(IMG_RAW_INFO))) == NULL)
	return NULL;

    memset((void *) raw_info, 0, sizeof(IMG_RAW_INFO));

    img_info = (IMG_INFO *) raw_info;

    img_info->itype = RAW_SING;
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
	struct stat stat_buf;

	/* Exit if we are given a directory */
	if (stat(images[0], &stat_buf) == -1) {
	    tsk_errno = TSK_ERR_IMG_STAT;
	    snprintf(tsk_errstr, TSK_ERRSTR_L,
		"raw_open directory check: %s", strerror(errno));
	    tsk_errstr2[0] = '\0';
	    return NULL;
	}
	else if ((stat_buf.st_mode & S_IFMT) == S_IFDIR) {
	    if (verbose)
		fprintf(stderr, "raw_open: image %s is a directory\n",
		    images[0]);

	    tsk_errno = TSK_ERR_IMG_MAGIC;
	    snprintf(tsk_errstr, TSK_ERRSTR_L,
		"raw_open: Image is a directory");
	    tsk_errstr2[0] = '\0';
	    return NULL;
	}

#ifdef TSK_WIN32
	{
	    /* Convert to wide chars */
	    WCHAR img_name[1024];
	    unsigned int i;
	    for (i = 0; i < strlen(images[0]) && i < 1023; i++) {
		img_name[i] = images[0][i];
	    }
	    img_name[i] = '\0';

	    if ((raw_info->fd = CreateFile(img_name, GENERIC_READ,
			0, 0, OPEN_EXISTING, 0, 0)) ==
		INVALID_HANDLE_VALUE) {
		tsk_errno = TSK_ERR_IMG_OPEN;
		snprintf(tsk_errstr, TSK_ERRSTR_L,
		    "raw_open file: %s msg: %s", images[0],
		    strerror(errno));
		tsk_errstr2[0] = '\0';
		return NULL;
	    }
	}
#else
	if ((raw_info->fd = open(images[0], O_RDONLY)) < 0) {
	    tsk_errno = TSK_ERR_IMG_OPEN;
	    snprintf(tsk_errstr, TSK_ERRSTR_L, "raw_open file: %s msg: %s",
		images[0], strerror(errno));
	    tsk_errstr2[0] = '\0';
	    return NULL;
	}
#endif
	/* We don't use the stat output because it doesn't work on raw
	 * devices and such */
	img_info->size = lseek(raw_info->fd, 0, SEEK_END);
	lseek(raw_info->fd, 0, SEEK_SET);
	raw_info->seek_pos = 0;
    }

    return img_info;
}
