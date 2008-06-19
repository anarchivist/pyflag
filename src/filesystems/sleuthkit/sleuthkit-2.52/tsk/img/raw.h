/*
 * The Sleuth Kit
 *
 * $Date: 2007/12/20 20:32:39 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2005 Brian Carrier.  All rights reserved 
 */

/** \file raw.h
 * Contains the single raw data file-specific functions and structures.
 */

#ifndef _RAW_H
#define _RAW_H

#ifdef __cplusplus
extern "C" {
#endif

    extern TSK_IMG_INFO *raw_open(const TSK_TCHAR **, TSK_IMG_INFO *);

    typedef struct {
        TSK_IMG_INFO img_info;
#ifdef TSK_WIN32
        HANDLE fd;
#else
        int fd;
#endif
        TSK_OFF_T seek_pos;
    } IMG_RAW_INFO;

#ifdef __cplusplus
}
#endif
#endif
