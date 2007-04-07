/*
 * The Sleuth Kit
 *
 * $Date: 2007/03/20 21:54:54 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2005 Brian Carrier.  All rights reserved 
 */
#ifndef _RAW_H
#define _RAW_H

#ifdef __cplusplus
extern "C" {
#endif

    extern TSK_IMG_INFO *raw_open(const TSK_TCHAR **, TSK_IMG_INFO *);

    typedef struct IMG_RAW_INFO IMG_RAW_INFO;
    struct IMG_RAW_INFO {
        TSK_IMG_INFO img_info;
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
