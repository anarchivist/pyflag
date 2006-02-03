/* 
 * The Sleuth Kit
 *
 * $Date: 2005/09/02 23:34:03 $
 * 
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2005 Brian Carrier.  All rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 *
 */

#include "fs_tools.h"


/* File Walk Action to load the journal 
 * FS_LOAD_FILE is defined in fs_tools.h
*/

uint8_t
load_file_action(FS_INFO * fs, DADDR_T addr, char *buf, unsigned int size,
		 int flags, void *ptr)
{
    FS_LOAD_FILE *buf1 = (FS_LOAD_FILE *) ptr;
    size_t cp_size;

    if (size > buf1->left)
	cp_size = buf1->left;
    else
	cp_size = size;

    memcpy(buf1->cur, buf, cp_size);
    buf1->left -= cp_size;
    buf1->cur = (char *) ((uintptr_t) buf1->cur + cp_size);

    if (buf1->left > 0)
	return WALK_CONT;
    else
	return WALK_STOP;
}
