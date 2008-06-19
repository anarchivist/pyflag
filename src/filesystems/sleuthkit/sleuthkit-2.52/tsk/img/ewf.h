/*
 * The Sleuth Kit - Add on for EWF image support
 * Eye Witness Compression Format Support
 *
 * $Date: 2007/12/20 20:32:39 $
 *
 * Joachim Metz <metz@studenten.net>
 * Copyright (c) 2006 Joachim Metz.  All rights reserved 
 *
 * Based on raw image support of the Sleuth Kit from
 * Brian Carrier.
 */

/** \file ewf.h
 * Header files for EWF-specific data structures and functions. 
 */

#ifndef _EWF_H
#define _EWF_H

#if HAVE_LIBEWF

#include <libewf.h>

#ifdef __cplusplus
extern "C" {
#endif
    extern TSK_IMG_INFO *ewf_open(int, const char **, TSK_IMG_INFO *);

    typedef struct {
        TSK_IMG_INFO img_info;
        LIBEWF_HANDLE *handle;
        char md5hash[33];
        int md5hash_isset;
    } IMG_EWF_INFO;

#ifdef __cplusplus
}
#endif
#endif
#endif
