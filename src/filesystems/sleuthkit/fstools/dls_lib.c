/*
** The Sleuth Kit
**
** $Date: 2007/04/05 16:01:57 $
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2006-2007 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
** Copyright (c) 1997,1998,1999, International Business Machines
** Corporation and others. All Rights Reserved.
**
*/

/* TCT:
 *
 * LICENSE
 *	This software is distributed under the IBM Public License.
 * AUTHOR(S)
 *	Wietse Venema
 *	IBM T.J. Watson Research
 *	P.O. Box 704
 *	Yorktown Heights, NY 10598, USA
 */

#include "fs_tools_i.h"

#ifdef TSK_WIN32
#include <Winsock2.h>
#endif

/* call backs for listing details 
 *
 * return 1 on error
 * */
static uint8_t
print_list_head(TSK_FS_INFO * fs)
{
    char hostnamebuf[BUFSIZ];

#ifndef TSK_WIN32
    if (gethostname(hostnamebuf, sizeof(hostnamebuf) - 1) < 0) {
        if (tsk_verbose)
            tsk_fprintf(stderr, "dls_lib: error getting hostname: %s\n",
                strerror(errno));
        strcpy(hostnamebuf, "unknown");
    }
    hostnamebuf[sizeof(hostnamebuf) - 1] = 0;
#else
    strcpy(hostnamebuf, "unknown");
#endif

    /*
     * Identify table type and table origin.
     */
    tsk_printf("class|host|image|first_time|unit\n");
    tsk_printf("dls|%s||%lu|%s\n", hostnamebuf, (ULONG) time(NULL),
        fs->duname);

    tsk_printf("addr|alloc\n");
    return 0;
}

static uint8_t
print_list(TSK_FS_INFO * fs, DADDR_T addr, char *buf,
    TSK_FS_BLOCK_FLAG_ENUM flags, void *ptr)
{
    tsk_printf("%" PRIuDADDR "|%s\n", addr,
        (flags & TSK_FS_BLOCK_FLAG_ALLOC) ? "a" : "f");
    return TSK_WALK_CONT;
}



/* print_block - write data block to stdout */
static uint8_t
print_block(TSK_FS_INFO * fs, DADDR_T addr, char *buf,
    TSK_FS_BLOCK_FLAG_ENUM flags, void *ptr)
{
    if (tsk_verbose)
        tsk_fprintf(stderr, "write block %" PRIuDADDR "\n", addr);

    if (fwrite(buf, fs->block_size, 1, stdout) != 1) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_WRITE;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "dls_lib: error writing to stdout: %s", strerror(errno));
        return TSK_WALK_ERROR;
    }

    return TSK_WALK_CONT;
}



/* SLACK SPACE  call backs */
static OFF_T flen;

static uint8_t
slack_file_act(TSK_FS_INFO * fs, DADDR_T addr, char *buf,
    size_t size, TSK_FS_BLOCK_FLAG_ENUM flags, void *ptr)
{

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "slack_file_act: Remaining File:  %" PRIuOFF
            "  Buffer: %u\n", flen, size);

    /* This is not the last data unit */
    if (flen >= size) {
        flen -= size;
    }
    /* We have passed the end of the allocated space */
    else if (flen == 0) {
        fwrite(buf, size, 1, stdout);
    }
    /* This is the last data unit and there is unused space */
    else if (flen < size) {
        /* Clear the used space and print it */
        memset(buf, 0, (size_t) flen);
        fwrite(buf, size, 1, stdout);
        flen = 0;
    }

    return TSK_WALK_CONT;
}

/* Call back for inode_walk */
static uint8_t
slack_inode_act(TSK_FS_INFO * fs, TSK_FS_INODE * fs_inode, void *ptr)
{

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "slack_inode_act: Processing meta data: %" PRIuINUM "\n",
            fs_inode->addr);

    /* We will now do a file walk on the content and print the
     * data after the specified size of the file */
    if ((fs->ftype & TSK_FS_INFO_TYPE_FS_MASK) !=
        TSK_FS_INFO_TYPE_NTFS_TYPE) {
        flen = fs_inode->size;
        if (fs->file_walk(fs, fs_inode, 0, 0,
                TSK_FS_FILE_FLAG_SLACK |
                TSK_FS_FILE_FLAG_NOID, slack_file_act, ptr)) {
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "slack_inode_act: error walking file: %" PRIuINUM,
                    fs_inode->addr);
            tsk_error_reset();
        }
    }

    /* For NTFS we go through each non-resident attribute */
    else {
        TSK_FS_DATA *fs_data;

        for (fs_data = fs_inode->attr;
            fs_data != NULL; fs_data = fs_data->next) {

            if ((fs_data->flags & TSK_FS_DATA_INUSE) == 0)
                continue;

            if (fs_data->flags & TSK_FS_DATA_NONRES) {
                flen = fs_data->size;
                if (fs->file_walk(fs, fs_inode, fs_data->type, fs_data->id,
                        TSK_FS_FILE_FLAG_SLACK, slack_file_act, ptr)) {
                    if (tsk_verbose)
                        tsk_fprintf(stderr,
                            "slack_inode_act: error walking file: %"
                            PRIuINUM, fs_inode->addr);
                    tsk_error_reset();
                }
            }
        }
    }

    return TSK_WALK_CONT;
}



/* Return 1 on error and 0 on success */
uint8_t
tsk_fs_dls(TSK_FS_INFO * fs, uint8_t lclflags, DADDR_T bstart,
    DADDR_T blast, TSK_FS_BLOCK_FLAG_ENUM flags)
{
    if (lclflags & TSK_FS_DLS_SLACK) {
        /* get the info on each allocated inode */
        if (fs->inode_walk(fs, fs->first_inum, fs->last_inum,
                TSK_FS_INODE_FLAG_ALLOC, slack_inode_act, NULL))
            return 1;
    }
    else if (lclflags & TSK_FS_DLS_LIST) {
        if (print_list_head(fs))
            return 1;

        if (fs->block_walk(fs, bstart, blast, flags, print_list, NULL))
            return 1;
    }
    else {
#ifdef TSK_WIN32
        if (-1 == _setmode(_fileno(stdout), _O_BINARY)) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_FS_WRITE;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "dls_lib: error setting stdout to binary: %s",
                strerror(errno));
            return 1;
        }
#endif
        if (fs->block_walk(fs, bstart, blast, flags, print_block, NULL))
            return 1;
    }

    return 0;
}
