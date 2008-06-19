/*
 * The Sleuth Kit
 *
 * $Date: 2007/12/20 20:32:38 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2005-1007 Brian Carrier.  All rights reserved 
 */

/** \file aff.h
 * Header files for AFF-specific data structures and functions. 
 */

#ifndef _AFF_H
#define _AFF_H

#if HAVE_LIBAFFLIB

#include <afflib/afflib.h>
#include <afflib/afflib_i.h>

extern TSK_IMG_INFO *aff_open(const char **, TSK_IMG_INFO *);

/** \internal
 * Stores AFF-specific data
 */
typedef struct {
    TSK_IMG_INFO img_info;
    AFFILE *af_file;
    TSK_OFF_T seek_pos;
    uint16_t type;              /* TYPE - uses AF_IDENTIFY_x values */
} IMG_AFF_INFO;

#endif
#endif
