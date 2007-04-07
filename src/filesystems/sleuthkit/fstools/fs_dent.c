/*
** fs_dent
** The Sleuth Kit 
**
** $Date: 2007/04/05 16:01:58 $
**
** Display and manipulate directory entries 
** This file contains generic functions that call the appropriate function
** depending on the file system type
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2006 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
** TCTUTILs
** Copyright (c) 2001 Brian Carrier.  All rights reserved
**
**
** This software is distributed under the Common Public License 1.0
**
*/
#include "fs_tools_i.h"
#include "ntfs.h"


char tsk_fs_dent_str[TSK_FS_DENT_TYPE_MAX_STR][2] =
    { "-", "p", "c", "", "d", "", "b", "", "r", "",
    "l", "", "s", "h", "w"
};

/* Allocate a fs_dent structure */
TSK_FS_DENT *
tsk_fs_dent_alloc(ULONG norm_namelen, ULONG shrt_namelen)
{
    TSK_FS_DENT *fs_dent;
    fs_dent = (TSK_FS_DENT *) tsk_malloc(sizeof(*fs_dent));
    if (fs_dent == NULL)
        return NULL;

    fs_dent->name = (char *) tsk_malloc(norm_namelen + 1);
    if (fs_dent->name == NULL) {
        free(fs_dent);
        return NULL;
    }
    fs_dent->name_max = norm_namelen;

    fs_dent->flags = 0;

    fs_dent->shrt_name_max = shrt_namelen;
    if (shrt_namelen == 0) {
        fs_dent->shrt_name = NULL;
    }
    else {
        fs_dent->shrt_name = (char *) tsk_malloc(shrt_namelen + 1);
        if (fs_dent->shrt_name == NULL) {
            free(fs_dent->name);
            free(fs_dent);
            return NULL;
        }
    }

    fs_dent->ent_type = TSK_FS_DENT_TYPE_UNDEF;
    fs_dent->path = NULL;
    fs_dent->pathdepth = 0;
    fs_dent->fsi = NULL;

    return fs_dent;
}

TSK_FS_DENT *
tsk_fs_dent_realloc(TSK_FS_DENT * fs_dent, ULONG namelen)
{
    if (fs_dent->name_max == namelen)
        return fs_dent;

    fs_dent->name = (char *) tsk_realloc(fs_dent->name, namelen + 1);
    if (fs_dent->name == NULL) {
        if (fs_dent->fsi)
            tsk_fs_inode_free(fs_dent->fsi);

        if (fs_dent->shrt_name)
            free(fs_dent->shrt_name);

        free(fs_dent);
        return NULL;
    }

    fs_dent->ent_type = TSK_FS_DENT_TYPE_UNDEF;
    fs_dent->name_max = namelen;

    return fs_dent;
}

void
tsk_fs_dent_free(TSK_FS_DENT * fs_dent)
{
    if (!fs_dent)
        return;

    if (fs_dent->fsi)
        tsk_fs_inode_free(fs_dent->fsi);

    free(fs_dent->name);
    if (fs_dent->shrt_name)
        free(fs_dent->shrt_name);

    free(fs_dent);
}


/***********************************************************************
 * Printing functions
 ***********************************************************************/

/*
 * make the ls -l output from the mode 
 *
 * ls must be 12 bytes or more!
 */
void
tsk_fs_make_ls(mode_t mode, char *ls)
{
    int typ;

    /* put the default values in */
    strcpy(ls, "----------");

    typ = (mode & TSK_FS_INODE_MODE_FMT) >> TSK_FS_INODE_MODE_TYPE_SHIFT;
    if (typ < TSK_FS_INODE_MODE_TYPE_STR_MAX)
        ls[0] = tsk_fs_inode_mode_str[typ][0];


    /* user perms */
    if (mode & TSK_FS_INODE_MODE_IRUSR)
        ls[1] = 'r';
    if (mode & TSK_FS_INODE_MODE_IWUSR)
        ls[2] = 'w';
    /* set uid */
    if (mode & TSK_FS_INODE_MODE_ISUID) {
        if (mode & TSK_FS_INODE_MODE_IXUSR)
            ls[3] = 's';
        else
            ls[3] = 'S';
    }
    else if (mode & TSK_FS_INODE_MODE_IXUSR)
        ls[3] = 'x';

    /* group perms */
    if (mode & TSK_FS_INODE_MODE_IRGRP)
        ls[4] = 'r';
    if (mode & TSK_FS_INODE_MODE_IWGRP)
        ls[5] = 'w';
    /* set gid */
    if (mode & TSK_FS_INODE_MODE_ISGID) {
        if (mode & TSK_FS_INODE_MODE_IXGRP)
            ls[6] = 's';
        else
            ls[6] = 'S';
    }
    else if (mode & TSK_FS_INODE_MODE_IXGRP)
        ls[6] = 'x';

    /* other perms */
    if (mode & TSK_FS_INODE_MODE_IROTH)
        ls[7] = 'r';
    if (mode & TSK_FS_INODE_MODE_IWOTH)
        ls[8] = 'w';

    /* sticky bit */
    if (mode & TSK_FS_INODE_MODE_ISVTX) {
        if (mode & TSK_FS_INODE_MODE_IXOTH)
            ls[9] = 't';
        else
            ls[9] = 'T';
    }
    else if (mode & TSK_FS_INODE_MODE_IXOTH)
        ls[9] = 'x';
}

void
tsk_fs_print_time(FILE * hFile, time_t time)
{
    if (time <= 0) {
        tsk_fprintf(hFile, "0000.00.00 00:00:00 (UTC)");
    }
    else {
        struct tm *tmTime = localtime(&time);

        tsk_fprintf(hFile, "%.4d.%.2d.%.2d %.2d:%.2d:%.2d (%s)",
            (int) tmTime->tm_year + 1900,
            (int) tmTime->tm_mon + 1, (int) tmTime->tm_mday,
            tmTime->tm_hour,
            (int) tmTime->tm_min, (int) tmTime->tm_sec,
            tzname[(tmTime->tm_isdst == 0) ? 0 : 1]);
    }
}


/* The only difference with this one is that the time is always
 * 00:00:00, which is applicable for the A-Time in FAT, which does
 * not have a time and if we do it normally it gets messed up because
 * of the timezone conversion
 */
void
tsk_fs_print_day(FILE * hFile, time_t time)
{
    if (time <= 0) {
        tsk_fprintf(hFile, "0000.00.00 00:00:00 (UTC)");
    }
    else {
        struct tm *tmTime = localtime(&time);

        tsk_fprintf(hFile, "%.4d.%.2d.%.2d 00:00:00 (%s)",
            (int) tmTime->tm_year + 1900,
            (int) tmTime->tm_mon + 1, (int) tmTime->tm_mday,
            tzname[(tmTime->tm_isdst == 0) ? 0 : 1]);
    }
}


/* simple print of dentry type / inode type, deleted, inode, and
 * name
 *
 * fs_data is used for alternate data streams in NTFS, set to NULL
 * for all other file systems
 *
 * A newline is not printed at the end
 *
 * If path is NULL, then skip else use. it has the full directory name
 *  It needs to end with "/"
 */
void
tsk_fs_dent_print(FILE * hFile, TSK_FS_DENT * fs_dent,
    TSK_FS_INFO * fs, TSK_FS_DATA * fs_data)
{
    TSK_FS_INODE *fs_inode = fs_dent->fsi;

    /* type of file - based on dentry type */
    if (fs_dent->ent_type < TSK_FS_DENT_TYPE_MAX_STR)
        tsk_fprintf(hFile, "%s/", tsk_fs_dent_str[fs_dent->ent_type]);
    else
        tsk_fprintf(hFile, "-/");

    /* type of file - based on inode type: we want letters though for
     * regular files so we use the dent_str though */
    if (fs_inode) {
        int typ =
            (fs_inode->
            mode & TSK_FS_INODE_MODE_FMT) >> TSK_FS_INODE_MODE_TYPE_SHIFT;
        if (typ < TSK_FS_DENT_TYPE_MAX_STR)
            tsk_fprintf(hFile, "%s ", tsk_fs_dent_str[typ]);
        else
            tsk_fprintf(hFile, "- ");
    }
    else {
        tsk_fprintf(hFile, "- ");
    }


    /* print a * if it is deleted */
    if (fs_dent->flags & TSK_FS_DENT_FLAG_UNALLOC)
        tsk_fprintf(hFile, "* ");

    tsk_fprintf(hFile, "%" PRIuINUM "", fs_dent->inode);

    /* print the id and type if we have fs_data (NTFS) */
    if (fs_data)
        tsk_fprintf(hFile, "-%lu-%lu", (ULONG) fs_data->type,
            (ULONG) fs_data->id);

    tsk_fprintf(hFile, "%s:\t",
        ((fs_inode) && (fs_inode->flags & TSK_FS_INODE_FLAG_ALLOC) &&
            (fs_dent->
                flags & TSK_FS_DENT_FLAG_UNALLOC)) ? "(realloc)" : "");

    if (fs_dent->path != NULL)
        tsk_fprintf(hFile, "%s", fs_dent->path);

    tsk_fprintf(hFile, "%s", fs_dent->name);

/*  This will add the short name in parentheses
    if (fs_dent->shrt_name != NULL && fs_dent->shrt_name[0] != '\0')
	tsk_fprintf(hFile, " (%s)", fs_dent->shrt_name);
*/

    /* print the data stream name if we the non-data NTFS stream */
    if (fs_data) {
        if (((fs_data->type == NTFS_ATYPE_DATA) &&
                (strcmp(fs_data->name, "$Data") != 0)) ||
            ((fs_data->type == NTFS_ATYPE_IDXROOT) &&
                (strcmp(fs_data->name, "$I30") != 0)))
            tsk_fprintf(hFile, ":%s", fs_data->name);
    }

    return;
}

/* Print contents of  fs_dent entry format like ls -l
**
** All elements are tab delimited 
**
** If path is NULL, then skip else use. it has the full directory name
**  It needs to end with "/"
*/
void
tsk_fs_dent_print_long(FILE * hFile, TSK_FS_DENT * fs_dent,
    TSK_FS_INFO * fs, TSK_FS_DATA * fs_data)
{
    TSK_FS_INODE *fs_inode = fs_dent->fsi;

    tsk_fs_dent_print(hFile, fs_dent, fs, fs_data);

    if ((fs == NULL) || (fs_inode == NULL)) {

        tsk_fprintf(hFile, "\t0000.00.00 00:00:00 (GMT)");
        tsk_fprintf(hFile, "\t0000.00.00 00:00:00 (GMT)");
        tsk_fprintf(hFile, "\t0000.00.00 00:00:00 (GMT)");

        tsk_fprintf(hFile, "\t0\t0\t0\n");
    }
    else {

        /* MAC times */
        tsk_fprintf(hFile, "\t");
        tsk_fs_print_time(hFile, fs_inode->mtime);

        tsk_fprintf(hFile, "\t");
        /* FAT only gives the day of last access */
        if ((fs->ftype & TSK_FS_INFO_TYPE_FS_MASK) !=
            TSK_FS_INFO_TYPE_FAT_TYPE)
            tsk_fs_print_time(hFile, fs_inode->atime);
        else
            tsk_fs_print_day(hFile, fs_inode->atime);

        tsk_fprintf(hFile, "\t");
        tsk_fs_print_time(hFile, fs_inode->ctime);


        /* use the stream size if one was given */
        if (fs_data)
            tsk_fprintf(hFile, "\t%llu", (ULLONG) fs_data->size);
        else
            tsk_fprintf(hFile, "\t%llu", (ULLONG) fs_inode->size);

        tsk_fprintf(hFile, "\t%lu\t%lu\n",
            (ULONG) fs_inode->gid, (ULONG) fs_inode->uid);
    }

    return;
}


/*
** Print output in the format that mactime reads.
** This allows the deleted files to be inserted to get a better
** picture of what happened
**
** Prepend fs_dent->path when printing full file name
**  dir needs to end with "/" 
**
** prepend *prefix to path as the mounting point that the original
** grave-robber was run on
**
** If the flags in the fs_inode structure are set to FS_FLAG_ALLOC
** then it is assumed that the inode has been reallocated and the
** contents are not displayed
**
** fs is not required (only used for block size).  
*/
void
tsk_fs_dent_print_mac(FILE * hFile, TSK_FS_DENT * fs_dent,
    TSK_FS_INFO * fs, TSK_FS_DATA * fs_data, char *prefix)
{
    TSK_FS_INODE *fs_inode;
    char ls[12];

    if ((!hFile) || (!fs_dent))
        return;

    fs_inode = fs_dent->fsi;

    /* md5 */
    tsk_fprintf(hFile, "0|");

    /* file name */
    tsk_fprintf(hFile, "%s%s%s", prefix, fs_dent->path, fs_dent->name);

    /* print the data stream name if it exists and is not the default NTFS */
    if ((fs_data) && (((fs_data->type == NTFS_ATYPE_DATA) &&
                (strcmp(fs_data->name, "$Data") != 0)) ||
            ((fs_data->type == NTFS_ATYPE_IDXROOT) &&
                (strcmp(fs_data->name, "$I30") != 0))))
        tsk_fprintf(hFile, ":%s", fs_data->name);

    if ((fs_inode)
        && ((fs_inode->mode & TSK_FS_INODE_MODE_FMT) ==
            TSK_FS_INODE_MODE_LNK) && (fs_inode->link)) {
        tsk_fprintf(hFile, " -> %s", fs_inode->link);
    }

    /* if filename is deleted add a comment and if the inode is now
     * allocated, then add realloc comment */
    if (fs_dent->flags & TSK_FS_DENT_FLAG_UNALLOC)
        tsk_fprintf(hFile, " (deleted%s)", ((fs_inode)
                && (fs_inode->
                    flags & TSK_FS_INODE_FLAG_ALLOC)) ? "-realloc" : "");

    /* device, inode */
    tsk_fprintf(hFile, "|0|%" PRIuINUM "", fs_dent->inode);
    if (fs_data)
        tsk_fprintf(hFile, "-%lu-%lu", (ULONG) fs_data->type,
            (ULONG) fs_data->id);

    /* mode val */
    tsk_fprintf(hFile, "|%lu|", (ULONG) ((fs_inode) ? fs_inode->mode : 0));

    /* TYPE as specified in the directory entry 
     * we want '-' for a regular file, so use the inode_str array
     */
    if (fs_dent->ent_type < TSK_FS_INODE_MODE_TYPE_STR_MAX)
        tsk_fprintf(hFile, "%s/",
            tsk_fs_inode_mode_str[fs_dent->ent_type]);
    else
        tsk_fprintf(hFile, "-/");

    if (!fs_inode) {
        tsk_fprintf(hFile, "----------|0|0|0|0|0|0|0|0|");
    }
    else {

        /* mode as string */
        tsk_fs_make_ls(fs_inode->mode, ls);
        tsk_fprintf(hFile, "%s|", ls);

        /* num link, uid, gid, rdev */
        tsk_fprintf(hFile, "%d|%d|%d|0|", (int) fs_inode->nlink,
            (int) fs_inode->uid, (int) fs_inode->gid);

        /* size - use data stream if we have it */
        if (fs_data)
            tsk_fprintf(hFile, "%" PRIuOFF "|", fs_data->size);
        else
            tsk_fprintf(hFile, "%" PRIuOFF "|", fs_inode->size);

        /* atime, mtime, ctime */
        tsk_fprintf(hFile, "%" PRIu32 "|%" PRIu32 "|%" PRIu32 "|",
            (uint32_t) fs_inode->atime, (uint32_t) fs_inode->mtime,
            (uint32_t) fs_inode->ctime);
    }

    /* block size and num of blocks */
    tsk_fprintf(hFile, "%u|0\n", (fs) ? fs->block_size : 0);

}
