/*
 * The Sleuth Kit
 *
 * $Date: 2006/06/20 22:35:41 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2005 Brian Carrier.  All rights reserved 
 */
#ifndef _RAW_H
#define _RAW_H

#ifdef __cplusplus
extern "C" {
#endif

    extern IMG_INFO *raw_open(const char **, IMG_INFO *);

    typedef struct IMG_RAW_INFO IMG_RAW_INFO;
    struct IMG_RAW_INFO {
	IMG_INFO img_info;
#ifdef TSK_WIN32
	HANDLE fd;
#else
	int fd;
#endif
	OFF_T seek_pos;
    };

#ifdef __cplusplus
}
#endif
#endif
