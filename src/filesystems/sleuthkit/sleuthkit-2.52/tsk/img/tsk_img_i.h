/*
 * The Sleuth Kit
 *
 * $Date: 2007/12/19 20:28:17 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2005 Brian Carrier.  All rights reserved 
 */
#ifndef _TSK_IMG_I_H
#define _TSK_IMG_I_H

/**
 * \file tsk_img_i.h
 * Contains the internal library definitions for the disk image functions.  This should
 * be included by the code in the img library. 
 */

// include the base internal header file
#include "tsk/base/tsk_base_i.h"

// include the external disk image header file
#include "tsk_img.h"

// other standard includes
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#endif
