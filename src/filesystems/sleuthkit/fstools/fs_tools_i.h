/*
** fs_tools
** The Sleuth Kit 
**
** Contains random internal definitions needed to compile the 
** library. 
**
** $Date: 2006/08/30 21:09:00 $
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002 @stake Inc.  All rights reserved
** 
** Copyright (c) 1997,1998,1999, International Business Machines          
** Corporation and others. All Rights Reserved.
*/

#ifndef _FS_TOOLS_I_H
#define _FS_TOOLS_I_H

#ifdef __cplusplus
extern "C" {
#endif

    /*
     * External interface.
     */
#include <string.h>
#include <fcntl.h>

#include <time.h>
#include <locale.h>
#include <errno.h>

#include "tsk_os.h"

#if defined (HAVE_UNISTD)
#include <unistd.h>
#endif

#if !defined (TSK_WIN32)
#include <sys/fcntl.h>
#include <sys/param.h>
#include <sys/time.h>
#endif

// Include the external file 
#include "fs_tools.h"


#ifndef NBBY
#define NBBY 8
#endif

#ifndef isset
#define isset(a,i)	(((uint8_t *)(a))[(i)/NBBY] &  (1<<((i)%NBBY)))
#endif

#ifndef setbit
#define setbit(a,i)     (((uint8_t *)(a))[(i)/NBBY] |= (1<<((i)%NBBY)))
#endif


/* Data structure and action to internally load a file */
    typedef struct {
	char *base;
	char *cur;
	size_t total;
	size_t left;
    } FS_LOAD_FILE;

    extern uint8_t load_file_action(FS_INFO *, DADDR_T, char *,
	size_t, int, void *);


/* Specific file system routines */
    extern FS_INFO *ext2fs_open(IMG_INFO *, SSIZE_T, uint8_t, uint8_t);
    extern FS_INFO *fatfs_open(IMG_INFO *, SSIZE_T, uint8_t, uint8_t);
    extern FS_INFO *ffs_open(IMG_INFO *, SSIZE_T, uint8_t);
    extern FS_INFO *ntfs_open(IMG_INFO *, SSIZE_T, uint8_t, uint8_t);
    extern FS_INFO *rawfs_open(IMG_INFO *, SSIZE_T);
    extern FS_INFO *swapfs_open(IMG_INFO *, SSIZE_T);
    extern FS_INFO *iso9660_open(IMG_INFO *, SSIZE_T, unsigned char,
	uint8_t);
    extern FS_INFO *hfs_open(IMG_INFO *, SSIZE_T, unsigned char, uint8_t);


// Endian macros - actual functions in misc/

#define fs_guessu16(fs, x, mag)   \
	guess_end_u16(&(fs->endian), (x), (mag))

#define fs_guessu32(fs, x, mag)   \
	guess_end_u32(&(fs->endian), (x), (mag))

#ifdef __cplusplus
}
#endif
#endif
/* LICENSE
 * .ad
 * .fi
 *	This software is distributed under the IBM Public License.
 * AUTHOR(S)
 *	Wietse Venema
 *	IBM T.J. Watson Research
 *	P.O. Box 704
 *	Yorktown Heights, NY 10598, USA
 --*/
