/*
** fs_tools
** The Sleuth Kit 
**
** Contains random internal definitions needed to compile the 
** library. 
**
** $Date: 2007/04/25 21:46:05 $
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
     * Internal interface.
     */
// Include the external file 
#include "fs_tools.h"

#include <time.h>
#include <locale.h>

#if defined (HAVE_UNISTD)
#include <unistd.h>
#endif

#if !defined (TSK_WIN32)
#include <sys/fcntl.h>
#include <sys/time.h>
#endif



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
    } TSK_FS_LOAD_FILE;

    extern uint8_t tsk_fs_load_file_action(TSK_FS_INFO *, DADDR_T, char *,
        size_t, TSK_FS_BLOCK_FLAG_ENUM, void *);


/* Specific file system routines */
    extern TSK_FS_INFO *ext2fs_open(TSK_IMG_INFO *, SSIZE_T,
        TSK_FS_INFO_TYPE_ENUM, uint8_t);
    extern TSK_FS_INFO *fatfs_open(TSK_IMG_INFO *, SSIZE_T,
        TSK_FS_INFO_TYPE_ENUM, uint8_t);
    extern TSK_FS_INFO *ffs_open(TSK_IMG_INFO *, SSIZE_T,
        TSK_FS_INFO_TYPE_ENUM);
    extern TSK_FS_INFO *ntfs_open(TSK_IMG_INFO *, SSIZE_T,
        TSK_FS_INFO_TYPE_ENUM, uint8_t);
    extern TSK_FS_INFO *rawfs_open(TSK_IMG_INFO *, SSIZE_T);
    extern TSK_FS_INFO *swapfs_open(TSK_IMG_INFO *, SSIZE_T);
    extern TSK_FS_INFO *iso9660_open(TSK_IMG_INFO *, SSIZE_T,
        TSK_FS_INFO_TYPE_ENUM, uint8_t);
    extern TSK_FS_INFO *hfs_open(TSK_IMG_INFO *, SSIZE_T,
        TSK_FS_INFO_TYPE_ENUM, uint8_t);


// Endian macros - actual functions in misc/

#define tsk_fs_guessu16(fs, x, mag)   \
	tsk_guess_end_u16(&(fs->endian), (x), (mag))

#define tsk_fs_guessu32(fs, x, mag)   \
	tsk_guess_end_u32(&(fs->endian), (x), (mag))

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
