/*
** The Sleuth Kit 
**
** $Date: 2006/09/21 16:47:06 $
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2006 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
** 
** Copyright (c) 1997,1998,1999, International Business Machines          
** Corporation and others. All Rights Reserved.
*/

/* TCT */
/*++
 * LICENSE
 *	This software is distributed under the IBM Public License.
 * AUTHOR(S)
 *	Wietse Venema
 *	IBM T.J. Watson Research
 *	P.O. Box 704
 *	Yorktown Heights, NY 10598, USA
 --*/

#include "fs_tools_i.h"

#ifdef TSK_WIN32
#include <Winsock2.h>
#endif

static TSK_TCHAR *image;

/* number of seconds time skew of system 
 * if the system was 100 seconds fast, the value should be +100 
 */
static int32_t sec_skew = 0;


/* print_header - print time machine header */

static void
print_header(FS_INFO * fs)
{
    char hostnamebuf[BUFSIZ];
    time_t now;

#ifndef TSK_WIN32
    if (gethostname(hostnamebuf, sizeof(hostnamebuf) - 1) < 0) {
	if (verbose)
	    tsk_fprintf(stderr, "error getting host by name\n");

	strcpy(hostnamebuf, "unknown");
    }
    hostnamebuf[sizeof(hostnamebuf) - 1] = 0;
#else
    strcpy(hostnamebuf, "unknown");
#endif
    now = time((time_t *) 0);

    /*
     * Identify table type and table origin.
     */
    tsk_printf("class|host|device|start_time\n");
    tsk_printf("ils|%s||%lu\n", hostnamebuf, (ULONG) now);

    /*
     * Identify the fields in the data that follow.
     */
    tsk_printf("st_ino|st_alloc|st_uid|st_gid|st_mtime|st_atime|st_ctime");

    tsk_printf("|st_mode|st_nlink|st_size|st_block0|st_block1\n");
}

static void
print_header_mac()
{
    char hostnamebuf[BUFSIZ];
    time_t now;

#ifndef TSK_WIN32
    if (gethostname(hostnamebuf, sizeof(hostnamebuf) - 1) < 0) {
	if (verbose)
	    tsk_fprintf(stderr, "Error getting host by name\n");
	strcpy(hostnamebuf, "unknown");
    }
    hostnamebuf[sizeof(hostnamebuf) - 1] = 0;
#else
    strcpy(hostnamebuf, "unknown");
#endif
    now = time((time_t *) 0);

    /*
     * Identify table type and table origin.
     */
    tsk_printf("class|host|start_time\n");
    tsk_printf("body|%s|%lu\n", hostnamebuf, (ULONG) now);

    /*
     * Identify the fields in the data that follow.
     */
    tsk_printf
	("md5|file|st_dev|st_ino|st_mode|st_ls|st_nlink|st_uid|st_gid|");
    printf
	("st_rdev|st_size|st_atime|st_mtime|st_ctime|st_blksize|st_blocks\n");

    return;
}


/* print_inode - list generic inode */

static uint8_t
ils_act(FS_INFO * fs, FS_INODE * fs_inode, int flags, void *ptr)
{
    uint8_t lclflags = *(uint8_t *) ptr;

    if ((fs_inode->nlink == 0) && ((lclflags & ILS_UNLINK) == 0)) {
	return WALK_CONT;
    }
    else if ((fs_inode->nlink == 1) && ((lclflags & ILS_LINK) == 0)) {
	return WALK_CONT;
    }

    if (sec_skew != 0) {
	fs_inode->mtime -= sec_skew;
	fs_inode->atime -= sec_skew;
	fs_inode->ctime -= sec_skew;
    }
    tsk_printf("%" PRIuINUM "|%c|%d|%d|%" PRIu32 "|%" PRIu32 "|%" PRIu32,
	fs_inode->addr, (flags & FS_FLAG_META_ALLOC) ? 'a' : 'f',
	(int) fs_inode->uid, (int) fs_inode->gid,
	(uint32_t) fs_inode->mtime, (uint32_t) fs_inode->atime,
	(uint32_t) fs_inode->ctime);

    if (sec_skew != 0) {
	fs_inode->mtime += sec_skew;
	fs_inode->atime += sec_skew;
	fs_inode->ctime += sec_skew;
    }

    tsk_printf("|%lo|%d|%" PRIuOFF "|%" PRIuDADDR "|%" PRIuDADDR "\n",
	(ULONG) fs_inode->mode, (int) fs_inode->nlink,
	fs_inode->size,
	(fs_inode->direct_count > 0) ? fs_inode->direct_addr[0] : 0,
	(fs_inode->direct_count > 1) ? fs_inode->direct_addr[1] : 0);

    return WALK_CONT;
}


/*
 * Print the inode information in the format that the mactimes program expects
 */

static uint8_t
ils_mac_act(FS_INFO * fs, FS_INODE * fs_inode, int flags, void *ptr)
{
    char ls[12];
    uint8_t lclflags = *(uint8_t *) ptr;

    if ((fs_inode->nlink == 0) && ((lclflags & ILS_UNLINK) == 0)) {
	return WALK_CONT;
    }
    else if ((fs_inode->nlink == 1) && ((lclflags & ILS_LINK) == 0)) {
	return WALK_CONT;
    }

    /* ADD image and file name (if we have one) */
    TFPRINTF(stdout, _TSK_T("0|<%s-"), image);
    tsk_printf("%s%s%s-%" PRIuINUM ">|0|%" PRIuINUM "|%d|",
	(fs_inode->name) ? fs_inode->name->name : "",
	(fs_inode->name) ? "-" : "",
	(flags & FS_FLAG_META_ALLOC) ? "alive" : "dead", fs_inode->addr,
	fs_inode->addr, (int) fs_inode->mode);

    /* Print the "ls" mode in ascii format */
    make_ls(fs_inode->mode, ls);

    if (sec_skew != 0) {
	fs_inode->mtime -= sec_skew;
	fs_inode->atime -= sec_skew;
	fs_inode->ctime -= sec_skew;
    }

    tsk_printf("%s|%d|%d|%d|0|%" PRIuOFF "|%lu|%" PRIu32 "|%" PRIu32 "|%"
	PRIu32 "|0\n", ls, (int) fs_inode->nlink, (int) fs_inode->uid,
	(int) fs_inode->gid, fs_inode->size, (uint32_t) fs_inode->atime,
	(uint32_t) fs_inode->mtime, (uint32_t) fs_inode->ctime,
	(ULONG) fs->block_size);

    if (sec_skew != 0) {
	fs_inode->mtime -= sec_skew;
	fs_inode->atime -= sec_skew;
	fs_inode->ctime -= sec_skew;
    }

    return WALK_CONT;
}



/* return 1 on error and 0 on success */
uint8_t
fs_ils(FS_INFO * fs, uint8_t lclflags, INUM_T istart, INUM_T ilast,
    int flags, int32_t skew, TSK_TCHAR * img)
{
    sec_skew = skew;

    /* If orphan is desired, then make sure LINK flags are set */
    if (flags & FS_FLAG_META_ORPHAN) {
	lclflags |= (ILS_LINK | ILS_UNLINK);
    }
    else {
	/* If LINK is not set at all, then set them */
	if (((lclflags & ILS_LINK) == 0) && ((lclflags & ILS_UNLINK) == 0))
	    lclflags |= (ILS_LINK | ILS_UNLINK);
    }


    /* Print the data */
    if (lclflags & ILS_MAC) {
	TSK_TCHAR *tmpptr;
	image = img;

#ifdef TSK_WIN32
	tmpptr = TSTRCHR(image, '\\');
#else
	tmpptr = strrchr(image, '/');
#endif

	if (tmpptr)
	    image = ++tmpptr;

	print_header_mac();

	if (fs->inode_walk(fs, istart, ilast, flags, ils_mac_act,
		&lclflags))
	    return 1;
    }
    else {
	print_header(fs);
	if (fs->inode_walk(fs, istart, ilast, flags, ils_act, &lclflags))
	    return 1;
    }

    return 0;
}
