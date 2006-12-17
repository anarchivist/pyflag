/*
 * The Sleuth Kit
 *
 * $Date: 2006/09/06 20:40:00 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2005 Brian Carrier.  All rights reserved 
 */

#ifndef _SPLIT_H
#define _SPLIT_H

#ifdef __cplusplus
extern "C" {
#endif

    extern IMG_INFO *split_open(int, const TSK_TCHAR **, IMG_INFO *);

#define SPLIT_CACHE	15

    typedef struct {
#ifdef TSK_WIN32
	HANDLE fd;
#else
	int fd;
#endif
	int image;
	OFF_T seek_pos;
    } IMG_SPLIT_CACHE;

    typedef struct IMG_SPLIT_INFO IMG_SPLIT_INFO;

    struct IMG_SPLIT_INFO {
	IMG_INFO img_info;
	int num_img;
	const TSK_TCHAR **images;
	OFF_T *max_off;
	int *cptr;		/* exists for each image - points to entry in cache */
	IMG_SPLIT_CACHE cache[SPLIT_CACHE];	/* small number of fds for open images */
	int next_slot;
    };

#ifdef __cplusplus
}
#endif
#endif
