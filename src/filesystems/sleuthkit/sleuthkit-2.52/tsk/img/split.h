/*
 * The Sleuth Kit
 *
 * $Date: 2007/12/20 20:32:39 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2005 Brian Carrier.  All rights reserved 
 */

/** \file split.h
 * Contains the split raw data file-specific functions and structures.
 */

#ifndef _SPLIT_H
#define _SPLIT_H

#ifdef __cplusplus
extern "C" {
#endif

    extern TSK_IMG_INFO *split_open(int, const TSK_TCHAR **,
        TSK_IMG_INFO *);

#define SPLIT_CACHE	15

    typedef struct {
#ifdef TSK_WIN32
        HANDLE fd;
#else
        int fd;
#endif
        int image;
        TSK_OFF_T seek_pos;
    } IMG_SPLIT_CACHE;

    typedef struct {
        TSK_IMG_INFO img_info;
        int num_img;
        const TSK_TCHAR **images;
        TSK_OFF_T *max_off;
        int *cptr;              /* exists for each image - points to entry in cache */
        IMG_SPLIT_CACHE cache[SPLIT_CACHE];     /* small number of fds for open images */
        int next_slot;
    } IMG_SPLIT_INFO;

#ifdef __cplusplus
}
#endif
#endif
