/*
 * The Sleuth Kit
 *
 * $Date: 2005/09/02 19:53:28 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2005 Brian Carrier.  All rights reserved 
 */
#ifndef _RAW_H
#define _RAW_H

#ifdef __cplusplus
extern "C" {
#endif

    extern IMG_INFO *raw_open(OFF_T, const char **, IMG_INFO *);

    typedef struct IMG_RAW_INFO IMG_RAW_INFO;
    struct IMG_RAW_INFO {
	IMG_INFO img_info;
	int fd;
	off_t seek_pos;
    };

#ifdef __cplusplus
}
#endif
#endif
