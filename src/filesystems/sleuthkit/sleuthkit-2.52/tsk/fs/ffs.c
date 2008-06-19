/*
** The Sleuth Kit 
**
** $Date: 2008/01/29 22:44:20 $
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2006-2007 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002-2003 Brian Carrier, @stake Inc.  All rights reserved
** 
** Copyright (c) 1997,1998,1999, International Business Machines          
** Corporation and others. All Rights Reserved.
*/

/* TCT 
 * LICENSE
 *	This software is distributed under the IBM Public License.
 * AUTHOR(S)
 *	Wietse Venema
 *	IBM T.J. Watson Research
 *	P.O. Box 704
 *	Yorktown Heights, NY 10598, USA
 --*/

/**
 * \file ffs.c
 * General UFS / FFS file system functions
 */

#include "tsk_fs_i.h"
#include "tsk_ffs.h"



/* ffs_group_load - load cylinder group descriptor info into cache 
 *
 * return 1 on error and 0 on success
 * */
static uint8_t
ffs_group_load(FFS_INFO * ffs, FFS_GRPNUM_T grp_num)
{
    TSK_DADDR_T addr;
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & ffs->fs_info;

    /*
     * Sanity check
     */
    if (grp_num < 0 || grp_num >= ffs->groups_count) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_ARG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "ffs_group_load: invalid cylinder group number: %"
            PRI_FFSGRP "", grp_num);
        return 1;
    }

    /*
     * Allocate/read cylinder group info on the fly. Trust that a cylinder
     * group always fits within a logical disk block (as promised in the
     * 4.4BSD <ufs/ffs/fs.h> include file).
     */
    if (ffs->grp_buf == NULL) {
        if ((ffs->grp_buf = tsk_data_buf_alloc(ffs->ffsbsize_b)) == NULL)
            return 1;
    }

    addr = cgtod_lcl(fs, ffs->fs.sb1, grp_num);
    if (ffs->grp_buf->addr != addr) {
        ffs_cgd *cg;
        ssize_t cnt;
        cnt =
            tsk_fs_read_block(fs, ffs->grp_buf, ffs->grp_buf->size, addr);
        if (cnt != ffs->grp_buf->size) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_errno = TSK_ERR_FS_READ;
            }
            snprintf(tsk_errstr2, TSK_ERRSTR_L,
                "ffs_group_load: Group %" PRI_FFSGRP " at %" PRIuDADDR,
                grp_num, addr);
            return 1;
        }

        /* Perform a sanity check on the data to make sure offsets are in range */
        cg = (ffs_cgd *) ffs->grp_buf->data;
        if ((tsk_gets32(fs->endian, cg->cg_iusedoff) > ffs->grp_buf->size)
            || (tsk_gets32(fs->endian,
                    cg->cg_freeoff) > ffs->grp_buf->size)) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_FS_CORRUPT;
            snprintf(tsk_errstr2, TSK_ERRSTR_L,
                "ffs_group_load: Group %" PRI_FFSGRP
                " descriptor offsets too large at %" PRIuDADDR, grp_num,
                addr);
            return 1;
        }
    }

    ffs->grp_num = grp_num;
    return 0;
}


/* 
 * ffs_dinode_load - read disk inode and load into local cache (ffs->dino_buf)
 *
 * Return 0 on success and 1 on error
 */
static uint8_t
ffs_dinode_load(FFS_INFO * ffs, TSK_INUM_T inum)
{
    TSK_DADDR_T addr;
    TSK_OFF_T offs;
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & ffs->fs_info;

    /*
     * Sanity check.
     */
    if (inum < fs->first_inum || inum > fs->last_inum) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_INODE_NUM;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "ffs_dinode_load: address: %" PRIuINUM, inum);
        return 1;
    }

    /*
     * Allocate/read the inode table buffer on the fly.
     */
    if (ffs->itbl_buf == NULL) {
        if ((ffs->itbl_buf = tsk_data_buf_alloc(ffs->ffsbsize_b)) == NULL)
            return 1;
    }


    /* UFS2 is different because it does not initialize all inodes
     * when the file system is created.  Therefore we need to check
     * the group descriptor to find out if this is in the valid
     * range
     */
    if (fs->ftype == TSK_FS_INFO_TYPE_FFS_2) {
        ffs_cgd2 *cg2;
        FFS_GRPNUM_T grp_num;

        if (ffs->dino_buf == NULL) {
            ffs->dino_buf = (char *) tsk_malloc(sizeof(ffs_inode2));
            if (ffs->dino_buf == NULL)
                return 1;
        }
        else if (ffs->dino_inum == inum) {
            return 0;
        }

        /* Lookup the cylinder group descriptor if it isn't
         * cached
         */
        grp_num = (FFS_GRPNUM_T) itog_lcl(fs, ffs->fs.sb1, inum);
        if ((ffs->grp_buf == NULL) || (grp_num != ffs->grp_num)) {
            if (ffs_group_load(ffs, grp_num)) {
                return 1;
            }
        }

        cg2 = (ffs_cgd2 *) ffs->grp_buf->data;

        /* If the inode is not init, then do not worry about it */
        if ((inum - grp_num * tsk_getu32(fs->endian,
                    ffs->fs.sb2->cg_inode_num)) >= tsk_getu32(fs->endian,
                cg2->cg_initediblk)) {
            memset((char *) ffs->dino_buf, 0, sizeof(ffs_inode2));
        }

        else {
            ssize_t cnt;
            /* Get the base and offset addr for the inode in the tbl */
            addr = itod_lcl(fs, ffs->fs.sb1, inum);

            if (ffs->itbl_buf->addr != addr) {
                cnt = tsk_fs_read_block
                    (fs, ffs->itbl_buf, ffs->itbl_buf->size, addr);
                if (cnt != ffs->itbl_buf->size) {
                    if (cnt >= 0) {
                        tsk_error_reset();
                        tsk_errno = TSK_ERR_FS_READ;
                    }
                    snprintf(tsk_errstr2, TSK_ERRSTR_L,
                        "ffs_dinode_load: FFS2 inode table at %"
                        PRIuDADDR, addr);
                    return 1;
                }
            }

            offs = itoo_lcl(fs, ffs->fs.sb2, inum) * sizeof(ffs_inode2);

            memcpy((char *) ffs->dino_buf, ffs->itbl_buf->data + offs,
                sizeof(ffs_inode2));
        }
    }
    else {
        if (ffs->dino_buf == NULL) {
            ffs->dino_buf = (char *) tsk_malloc(sizeof(ffs_inode1));
            if (ffs->dino_buf == NULL)
                return 1;
        }
        else if (ffs->dino_inum == inum) {
            return 0;
        }

        addr = itod_lcl(fs, ffs->fs.sb1, inum);
        if (ffs->itbl_buf->addr != addr) {
            ssize_t cnt;
            cnt =
                tsk_fs_read_block(fs, ffs->itbl_buf, ffs->itbl_buf->size,
                addr);
            if (cnt != ffs->itbl_buf->size) {
                if (cnt >= 0) {
                    tsk_error_reset();
                    tsk_errno = TSK_ERR_FS_READ;
                }
                snprintf(tsk_errstr2, TSK_ERRSTR_L,
                    "ffs_dinode_load: FFS1 inode table at %"
                    PRIuDADDR, addr);
                return 1;
            }
        }

        offs = itoo_lcl(fs, ffs->fs.sb1, inum) * sizeof(ffs_inode1);

        memcpy((char *) ffs->dino_buf, ffs->itbl_buf->data + offs,
            sizeof(ffs_inode1));
    }
    ffs->dino_inum = inum;
    return 0;
}



/* ffs_dinode_copy - copy cached disk inode to generic inode  
 *
 * Return 1 on error and 0 on success
 */
static uint8_t
ffs_dinode_copy(FFS_INFO * ffs, TSK_FS_INODE * fs_inode)
{
    int i, j;
    unsigned int count;
    TSK_FS_INFO *fs = &(ffs->fs_info);
    FFS_GRPNUM_T grp_num;
    ffs_cgd *cg;
    unsigned char *inosused = NULL;
    TSK_INUM_T ibase;

    fs_inode->flags = 0;
    fs_inode->seq = 0;
    fs_inode->addr = ffs->dino_inum;

    /* If the symlink field is set from a previous run, then free it */
    if (fs_inode->link) {
        free(fs_inode->link);
        fs_inode->link = NULL;
    }

    /* OpenBSD and FreeBSD style */
    if (fs->ftype == TSK_FS_INFO_TYPE_FFS_1) {
        ffs_inode1 *in = (ffs_inode1 *) ffs->dino_buf;

        fs_inode->mode = tsk_getu16(fs->endian, in->di_mode);
        fs_inode->nlink = tsk_gets16(fs->endian, in->di_nlink);
        fs_inode->size = tsk_getu64(fs->endian, in->di_size);
        fs_inode->uid = tsk_getu32(fs->endian, in->di_uid);
        fs_inode->gid = tsk_getu32(fs->endian, in->di_gid);

        fs_inode->mtime = tsk_gets32(fs->endian, in->di_mtime);
        fs_inode->atime = tsk_gets32(fs->endian, in->di_atime);
        fs_inode->ctime = tsk_gets32(fs->endian, in->di_ctime);

        if (fs_inode->direct_count != FFS_NDADDR ||
            fs_inode->indir_count != FFS_NIADDR) {
            fs_inode =
                tsk_fs_inode_realloc(fs_inode, FFS_NDADDR, FFS_NIADDR);
            if (fs_inode == NULL) {
                return 1;
            }
        }

        for (i = 0; i < FFS_NDADDR; i++)
            fs_inode->direct_addr[i] =
                tsk_gets32(fs->endian, in->di_db[i]);

        for (i = 0; i < FFS_NIADDR; i++)
            fs_inode->indir_addr[i] = tsk_gets32(fs->endian, in->di_ib[i]);


        /* set the link string (if the file is a link) 
         * The size check is a sanity check so that we don't try and allocate
         * a huge amount of memory for a bad inode value
         */
        if (((fs_inode->mode & TSK_FS_INODE_MODE_FMT) ==
                TSK_FS_INODE_MODE_LNK) && (fs_inode->size < FFS_MAXPATHLEN)
            && (fs_inode->size >= 0)) {
            int i;

            fs_inode->link = tsk_malloc((size_t) fs_inode->size + 1);
            if (fs_inode->link == NULL) {
                return 1;
            }

            count = 0;          /* index into the link array */

            /* it is located directly in the pointers   */
            if (fs_inode->size < 4 * (FFS_NDADDR + FFS_NIADDR)) {
                char *ptr;

                /* Direct block pointer locations */
                for (i = 0; i < FFS_NDADDR && count < fs_inode->size; i++) {
                    ptr = (char *) &in->di_db[i];
                    for (j = 0; j < 4 && count < fs_inode->size; j++)
                        fs_inode->link[count++] = ptr[j];
                }

                /* indirect block pointers */
                for (i = 0; i < FFS_NIADDR && count < fs_inode->size; i++) {
                    ptr = (char *) &in->di_ib[i];
                    for (j = 0; j < 4 && count < fs_inode->size; j++)
                        fs_inode->link[count++] = ptr[j];
                }

                fs_inode->link[count] = '\0';

                /* clear the values to avoid other code from reading them */
                for (i = 0; i < FFS_NDADDR; i++)
                    fs_inode->direct_addr[i] = 0;

                for (i = 0; i < FFS_NIADDR; i++)
                    fs_inode->indir_addr[i] = 0;
            }

            /* it is in blocks (the regular way) */
            else {
                TSK_DATA_BUF *data_buf;
                char *ptr = fs_inode->link;

                if ((data_buf =
                        tsk_data_buf_alloc(fs->block_size)) == NULL) {
                    return 1;
                }

                /* there is a max link length of 1000, so we should never
                 * need the indirect blocks
                 */
                for (i = 0; i < FFS_NDADDR && count < fs_inode->size; i++) {
                    ssize_t cnt;

                    /* Do we need the entire block, or just part of it? */
                    int read_count =
                        (fs_inode->size - count <
                        fs->block_size) ? (int) fs_inode->size -
                        count : fs->block_size;

                    cnt = tsk_fs_read_block(fs, data_buf, fs->block_size,
                        fs_inode->direct_addr[i]);
                    if (cnt != fs->block_size) {
                        if (cnt >= 0) {
                            tsk_error_reset();
                            tsk_errno = TSK_ERR_FS_READ;
                        }
                        snprintf(tsk_errstr2, TSK_ERRSTR_L,
                            "ffs_dinode_copy: FFS1A symlink dest at %"
                            PRIuDADDR, fs_inode->direct_addr[i]);
                        tsk_data_buf_free(data_buf);
                        return 1;
                    }

                    memcpy(ptr, data_buf->data, read_count);
                    count += read_count;
                    ptr = (char *) ((uintptr_t) ptr + read_count);
                }
                /* terminate the string */
                *ptr = '\0';

                /* Clean up name */
                i = 0;
                while (fs_inode->link[i] != '\0') {
                    if (TSK_IS_CNTRL(fs_inode->link[i]))
                        fs_inode->link[i] = '^';
                    i++;
                }

                tsk_data_buf_free(data_buf);
            }
        }                       /* end of symlink */
    }
    /* TSK_FS_INFO_TYPE_FFS_1B - Solaris */
    else if (fs->ftype == TSK_FS_INFO_TYPE_FFS_1B) {
        ffs_inode1b *in = (ffs_inode1b *) ffs->dino_buf;

        fs_inode->mode = tsk_getu16(fs->endian, in->di_mode);
        fs_inode->nlink = tsk_gets16(fs->endian, in->di_nlink);
        fs_inode->size = tsk_getu64(fs->endian, in->di_size);
        fs_inode->uid = tsk_getu32(fs->endian, in->di_uid);
        fs_inode->gid = tsk_getu32(fs->endian, in->di_gid);

        fs_inode->mtime = tsk_gets32(fs->endian, in->di_mtime);
        fs_inode->atime = tsk_gets32(fs->endian, in->di_atime);
        fs_inode->ctime = tsk_gets32(fs->endian, in->di_ctime);

        if (fs_inode->direct_count != FFS_NDADDR ||
            fs_inode->indir_count != FFS_NIADDR) {
            fs_inode =
                tsk_fs_inode_realloc(fs_inode, FFS_NDADDR, FFS_NIADDR);
            if (fs_inode == NULL) {
                return 1;
            }
        }

        for (i = 0; i < FFS_NDADDR; i++)
            fs_inode->direct_addr[i] =
                tsk_gets32(fs->endian, in->di_db[i]);

        for (i = 0; i < FFS_NIADDR; i++)
            fs_inode->indir_addr[i] = tsk_gets32(fs->endian, in->di_ib[i]);

        if (((fs_inode->mode & TSK_FS_INODE_MODE_FMT) ==
                TSK_FS_INODE_MODE_LNK) && (fs_inode->size < FFS_MAXPATHLEN)
            && (fs_inode->size >= 0)) {

            count = 0;          /* index into the link array */

            /* it is located directly in the pointers   */
            if (fs_inode->size < 4 * (FFS_NDADDR + FFS_NIADDR)) {
                char *ptr;

                /* Direct block pointer locations */
                for (i = 0; i < FFS_NDADDR && count < fs_inode->size; i++) {
                    ptr = (char *) &in->di_db[i];
                    for (j = 0; j < 4 && count < fs_inode->size; j++)
                        fs_inode->link[count++] = ptr[j];
                }

                /* indirect block pointers */
                for (i = 0; i < FFS_NIADDR && count < fs_inode->size; i++) {
                    ptr = (char *) &in->di_ib[i];
                    for (j = 0; j < 4 && count < fs_inode->size; j++)
                        fs_inode->link[count++] = ptr[j];
                }

                fs_inode->link[count] = '\0';

                /* clear the values to avoid other code from reading them */
                for (i = 0; i < FFS_NDADDR; i++)
                    fs_inode->direct_addr[i] = 0;

                for (i = 0; i < FFS_NIADDR; i++)
                    fs_inode->indir_addr[i] = 0;
            }

            /* it is in blocks (the regular way) */
            else {
                TSK_DATA_BUF *data_buf;
                char *ptr;

                if ((data_buf =
                        tsk_data_buf_alloc(fs->block_size)) == NULL)
                    return 1;

                fs_inode->link = ptr =
                    tsk_malloc((size_t) fs_inode->size + 1);
                if (fs_inode->link == NULL) {
                    tsk_data_buf_free(data_buf);
                    return 1;
                }

                /* there is a max link length of 1000, so we should never
                 * need the indirect blocks
                 */
                for (i = 0; i < FFS_NDADDR && count < fs_inode->size; i++) {
                    ssize_t cnt;

                    /* Do we need the entire block, or just part of it? */
                    int read_count =
                        (fs_inode->size - count <
                        fs->block_size) ? (int) fs_inode->size -
                        count : fs->block_size;

                    cnt = tsk_fs_read_block(fs, data_buf, fs->block_size,
                        fs_inode->direct_addr[i]);
                    if (cnt != fs->block_size) {
                        if (cnt >= 0) {
                            tsk_error_reset();
                            tsk_errno = TSK_ERR_FS_READ;
                        }
                        snprintf(tsk_errstr2, TSK_ERRSTR_L,
                            "ffs_dinode_copy: FFS1B symlink dest at %"
                            PRIuDADDR, fs_inode->direct_addr[i]);
                        tsk_data_buf_free(data_buf);
                        return 1;
                    }

                    memcpy(ptr, data_buf->data, read_count);
                    count += read_count;
                    ptr = (char *) ((uintptr_t) ptr + read_count);
                }

                /* terminate the string */
                *ptr = '\0';

                tsk_data_buf_free(data_buf);
            }
        }
    }
    else if (fs->ftype == TSK_FS_INFO_TYPE_FFS_2) {
        ffs_inode2 *in = (ffs_inode2 *) ffs->dino_buf;

        fs_inode->mode = tsk_getu16(fs->endian, in->di_mode);
        fs_inode->nlink = tsk_gets16(fs->endian, in->di_nlink);
        fs_inode->size = tsk_getu64(fs->endian, in->di_size);
        fs_inode->uid = tsk_getu32(fs->endian, in->di_uid);
        fs_inode->gid = tsk_getu32(fs->endian, in->di_gid);

        fs_inode->mtime = (time_t) tsk_gets64(fs->endian, in->di_mtime);
        fs_inode->atime = (time_t) tsk_gets64(fs->endian, in->di_atime);
        fs_inode->ctime = (time_t) tsk_gets64(fs->endian, in->di_ctime);

        if (fs_inode->direct_count != FFS_NDADDR ||
            fs_inode->indir_count != FFS_NIADDR) {
            fs_inode =
                tsk_fs_inode_realloc(fs_inode, FFS_NDADDR, FFS_NIADDR);
            if (fs_inode == NULL) {
                return 1;
            }
        }

        for (i = 0; i < FFS_NDADDR; i++)
            fs_inode->direct_addr[i] =
                tsk_gets64(fs->endian, in->di_db[i]);

        for (i = 0; i < FFS_NIADDR; i++)
            fs_inode->indir_addr[i] = tsk_gets64(fs->endian, in->di_ib[i]);


        /* set the link string (if the file is a link) 
         * The size check is a sanity check so that we don't try and allocate
         * a huge amount of memory for a bad inode value
         */
        if (((fs_inode->mode & TSK_FS_INODE_MODE_FMT) ==
                TSK_FS_INODE_MODE_LNK) && (fs_inode->size < FFS_MAXPATHLEN)
            && (fs_inode->size >= 0)) {

            fs_inode->link = tsk_malloc((size_t) fs_inode->size + 1);
            if (fs_inode->link == NULL) {
                return 1;
            }

            count = 0;          /* index into the link array */

            /* it is located directly in the pointers  
             * Only the new style inode has this "fast link"
             */
            if (fs_inode->size < 8 * (FFS_NDADDR + FFS_NIADDR)) {
                char *ptr;

                /* Direct block pointer locations */
                for (i = 0; i < FFS_NDADDR && count < fs_inode->size; i++) {
                    ptr = (char *) &in->di_db[i];
                    for (j = 0; j < 8 && count < fs_inode->size; j++)
                        fs_inode->link[count++] = ptr[j];
                }

                /* indirect block pointers */
                for (i = 0; i < FFS_NIADDR && count < fs_inode->size; i++) {
                    ptr = (char *) &in->di_ib[i];
                    for (j = 0; j < 8 && count < fs_inode->size; j++)
                        fs_inode->link[count++] = ptr[j];
                }

                fs_inode->link[count] = '\0';

                /* clear the values to avoid other code from reading them */
                for (i = 0; i < FFS_NDADDR; i++)
                    fs_inode->direct_addr[i] = 0;

                for (i = 0; i < FFS_NIADDR; i++)
                    fs_inode->indir_addr[i] = 0;
            }

            /* it is in blocks (the regular way) */
            else {
                TSK_DATA_BUF *data_buf;
                char *ptr = fs_inode->link;

                if ((data_buf =
                        tsk_data_buf_alloc(fs->block_size)) == NULL) {
                    return 1;
                }

                /* there is a max link length of 1000, so we should never
                 * need the indirect blocks
                 */
                for (i = 0; i < FFS_NDADDR && count < fs_inode->size; i++) {
                    ssize_t cnt;

                    /* Do we need the entire block, or just part of it? */
                    int read_count =
                        (fs_inode->size - count <
                        fs->block_size) ? (int) fs_inode->size -
                        count : fs->block_size;

                    cnt = tsk_fs_read_block(fs, data_buf, fs->block_size,
                        fs_inode->direct_addr[i]);
                    if (cnt != fs->block_size) {
                        if (cnt >= 0) {
                            tsk_error_reset();
                            tsk_errno = TSK_ERR_FS_READ;
                        }
                        snprintf(tsk_errstr2, TSK_ERRSTR_L,
                            "ffs_dinode_copy: FFS2 symlink dest at %"
                            PRIuDADDR, fs_inode->direct_addr[i]);
                        tsk_data_buf_free(data_buf);
                        return 1;
                    }

                    memcpy(ptr, data_buf->data, read_count);
                    count += read_count;
                    ptr = (char *) ((uintptr_t) ptr + read_count);
                }
                /* terminate the string */
                *ptr = '\0';

                tsk_data_buf_free(data_buf);
            }
        }                       /* end of symlink */
    }
    else {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_ARG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "ffs_dinode_copy: Unknown FFS Type");
        return 1;
    }

    /* set the flags */
    grp_num = (FFS_GRPNUM_T) itog_lcl(fs, ffs->fs.sb1, ffs->dino_inum);
    if ((ffs->grp_buf == NULL) || (grp_num != ffs->grp_num)) {
        if (ffs_group_load(ffs, grp_num))
            return 1;
    }

    cg = (ffs_cgd *) ffs->grp_buf->data;

    inosused = (unsigned char *) cg_inosused_lcl(fs, cg);
    ibase = grp_num * tsk_gets32(fs->endian, ffs->fs.sb1->cg_inode_num);

    /* get the alloc flag */
    fs_inode->flags = (isset(inosused, ffs->dino_inum - ibase) ?
        TSK_FS_INODE_FLAG_ALLOC : TSK_FS_INODE_FLAG_UNALLOC);

    /* used/unused */
    fs_inode->flags |= (fs_inode->ctime ?
        TSK_FS_INODE_FLAG_USED : TSK_FS_INODE_FLAG_UNUSED);

    return 0;
}



/* ffs_inode_lookup - lookup inode, external interface 
 *
 * Return NULL on error
 *
 * */
static TSK_FS_INODE *
ffs_inode_lookup(TSK_FS_INFO * fs, TSK_INUM_T inum)
{
    FFS_INFO *ffs = (FFS_INFO *) fs;
    TSK_FS_INODE *fs_inode;

    // clean up any error messages that are lying around
    tsk_error_reset();

    /* Lookup the inode and store it in ffs */
    if (ffs_dinode_load(ffs, inum))
        return NULL;

    /* copy it to the TSK_FS_INODE structure */
    fs_inode = tsk_fs_inode_alloc(FFS_NDADDR, FFS_NIADDR);
    if (fs_inode == NULL)
        return NULL;

    if (ffs_dinode_copy(ffs, fs_inode)) {
        tsk_fs_inode_free(fs_inode);
        return NULL;
    }

    return (fs_inode);
}



/**************************************************************************
 *
 * INODE WALKING
 *
 **************************************************************************/


static TSK_WALK_RET_ENUM
inode_walk_dent_orphan_act(TSK_FS_INFO * fs, TSK_FS_DENT * fs_dent,
    void *ptr)
{
    if ((fs_dent->fsi)
        && (fs_dent->fsi->flags & TSK_FS_INODE_FLAG_UNALLOC)) {
        if (tsk_list_add(&fs->list_inum_named, fs_dent->fsi->addr))
            return TSK_WALK_STOP;
    }
    return TSK_WALK_CONT;
}


/* ffs_inode_walk - inode iterator 
 *
 * flags used: TSK_FS_INODE_FLAG_USED, TSK_FS_INODE_FLAG_UNUSED, 
 *  TSK_FS_INODE_FLAG_ALLOC, TSK_FS_INODE_FLAG_UNALLOC, TSK_FS_INODE_FLAG_ORPHAN
 *
 *  return 1 on error and 0 on success
 */
uint8_t
ffs_inode_walk(TSK_FS_INFO * fs, TSK_INUM_T start_inum, TSK_INUM_T end_inum,
    TSK_FS_INODE_FLAG_ENUM flags, TSK_FS_INODE_WALK_CB action, void *ptr)
{
    char *myname = "ffs_inode_walk";
    FFS_INFO *ffs = (FFS_INFO *) fs;
    FFS_GRPNUM_T grp_num;
    ffs_cgd *cg = NULL;
    TSK_INUM_T inum;
    unsigned char *inosused = NULL;
    TSK_FS_INODE *fs_inode;
    int myflags;
    TSK_INUM_T ibase = 0;

    // clean up any error messages that are lying around
    tsk_error_reset();

    /*
     * Sanity checks.
     */
    if (start_inum < fs->first_inum || start_inum > fs->last_inum) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_WALK_RNG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "%s: Start inode: %" PRIuINUM "", myname, start_inum);
        return 1;
    }
    else if (end_inum < fs->first_inum || end_inum > fs->last_inum
        || end_inum < start_inum) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_WALK_RNG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "%s: End inode: %" PRIuINUM "", myname, end_inum);
        return 1;
    }

    /* If ORPHAN is wanted, then make sure that the flags are correct */
    if (flags & TSK_FS_INODE_FLAG_ORPHAN) {
        flags |= TSK_FS_INODE_FLAG_UNALLOC;
        flags &= ~TSK_FS_INODE_FLAG_ALLOC;
    }

    else if (((flags & TSK_FS_INODE_FLAG_ALLOC) == 0) &&
        ((flags & TSK_FS_INODE_FLAG_UNALLOC) == 0)) {
        flags |= (TSK_FS_INODE_FLAG_ALLOC | TSK_FS_INODE_FLAG_UNALLOC);
    }

    /* If neither of the USED or UNUSED flags are set, then set them
     * both
     */
    if (((flags & TSK_FS_INODE_FLAG_USED) == 0) &&
        ((flags & TSK_FS_INODE_FLAG_UNUSED) == 0)) {
        flags |= (TSK_FS_INODE_FLAG_USED | TSK_FS_INODE_FLAG_UNUSED);
    }



    /* If we are looking for orphan files and have not yet filled
     * in the list of unalloc inodes that are pointed to, then fill
     * in the list
     * */
    if ((flags & TSK_FS_INODE_FLAG_ORPHAN)
        && (fs->list_inum_named == NULL)) {

        if (ffs_dent_walk(fs, fs->root_inum,
                TSK_FS_DENT_FLAG_ALLOC | TSK_FS_DENT_FLAG_UNALLOC |
                TSK_FS_DENT_FLAG_RECURSE, inode_walk_dent_orphan_act,
                NULL)) {
            strncat(tsk_errstr2,
                " - ffs_inode_walk: identifying inodes allocated by file names",
                TSK_ERRSTR_L);
            return 1;
        }
    }

    if ((fs_inode = tsk_fs_inode_alloc(FFS_NDADDR, FFS_NIADDR)) == NULL)
        return 1;

    /*
     * Iterate. This is easy because inode numbers are contiguous, unlike
     * data blocks which are interleaved with cylinder group blocks.
     */
    for (inum = start_inum; inum <= end_inum; inum++) {
        int retval;

        /*
         * Be sure to use the proper cylinder group data.
         */
        grp_num = itog_lcl(fs, ffs->fs.sb1, inum);

        if ((ffs->grp_buf == NULL) || (grp_num != ffs->grp_num)) {
            if (ffs_group_load(ffs, grp_num))
                return 1;
            cg = NULL;
        }

        /* Load up the cached one if the needed one was already loaded or if a new was just loaded */
        if (cg == NULL) {
            cg = (ffs_cgd *) ffs->grp_buf->data;
            inosused = (unsigned char *) cg_inosused_lcl(fs, cg);
            ibase =
                grp_num * tsk_gets32(fs->endian,
                ffs->fs.sb1->cg_inode_num);
        }

        /*
         * Apply the allocated/unallocated restriction.
         */
        myflags = (isset(inosused, inum - ibase) ?
            TSK_FS_INODE_FLAG_ALLOC : TSK_FS_INODE_FLAG_UNALLOC);
        if ((flags & myflags) != myflags)
            continue;

        if (ffs_dinode_load(ffs, inum)) {
            tsk_fs_inode_free(fs_inode);
            return 1;
        }


        if ((fs->ftype == TSK_FS_INFO_TYPE_FFS_1)
            || (fs->ftype == TSK_FS_INFO_TYPE_FFS_1B)) {
            /* both inode forms are the same for the required fields */
            ffs_inode1 *in1 = (ffs_inode1 *) ffs->dino_buf;

            /*
             * Apply the used/unused restriction.
             */
            myflags |= (tsk_gets32(fs->endian, in1->di_ctime) ?
                TSK_FS_INODE_FLAG_USED : TSK_FS_INODE_FLAG_UNUSED);
            if ((flags & myflags) != myflags)
                continue;
        }
        else {
            ffs_inode2 *in2 = (ffs_inode2 *) ffs->dino_buf;

            /*
             * Apply the used/unused restriction.
             */
            myflags |= (tsk_gets64(fs->endian, in2->di_ctime) ?
                TSK_FS_INODE_FLAG_USED : TSK_FS_INODE_FLAG_UNUSED);
            if ((flags & myflags) != myflags)
                continue;
        }

        /* If we want only orphans, then check if this
         * inode is in the seen list
         */
        if ((myflags & TSK_FS_INODE_FLAG_UNALLOC) &&
            (flags & TSK_FS_INODE_FLAG_ORPHAN) &&
            (tsk_list_find(fs->list_inum_named, inum))) {
            continue;
        }


        /*
         * Fill in a file system-independent inode structure and pass control
         * to the application.
         */
        if (ffs_dinode_copy(ffs, fs_inode)) {
            tsk_fs_inode_free(fs_inode);
            return 1;
        }

        retval = action(fs, fs_inode, ptr);
        if (retval == TSK_WALK_STOP) {
            tsk_fs_inode_free(fs_inode);
            return 0;
        }
        else if (retval == TSK_WALK_ERROR) {
            tsk_fs_inode_free(fs_inode);
            return 1;
        }
    }

    /*
     * Cleanup.
     */
    tsk_fs_inode_free(fs_inode);
    return 0;
}


/**************************************************************************
 *
 * BLOCK WALKING
 *
 **************************************************************************/

/* ffs_block_walk - block iterator 
 *
 * flags: TSK_FS_BLOCK_FLAG_ALLOC, TSK_FS_BLOCK_FLAG_UNALLOC, TSK_FS_BLOCK_FLAG_CONT,
 *  TSK_FS_BLOCK_FLAG_META, TSK_FS_BLOCK_FLAG_ALIGN
 *
 *  return 1 on error and 0 on success
 */

uint8_t
ffs_block_walk(TSK_FS_INFO * fs, TSK_DADDR_T start_blk, TSK_DADDR_T end_blk,
    TSK_FS_BLOCK_FLAG_ENUM flags, TSK_FS_BLOCK_WALK_CB action, void *ptr)
{
    char *myname = "ffs_block_walk";
    FFS_INFO *ffs = (FFS_INFO *) fs;
    TSK_DATA_BUF *data_buf;
    FFS_GRPNUM_T grp_num;
    ffs_cgd *cg = 0;
    TSK_DADDR_T dbase = 0;
    TSK_DADDR_T dmin = 0;           /* first data block in group */
    TSK_DADDR_T sblock = 0;         /* super block in group */
    TSK_DADDR_T addr;
    TSK_DADDR_T faddr;
    unsigned char *freeblocks = NULL;
    int myflags;
    int want;
    int frags;
    char *null_block = NULL;

    // clean up any error messages that are lying around
    tsk_error_reset();

    /*
     * Sanity checks.
     */
    if (start_blk < fs->first_block || start_blk > fs->last_block) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_WALK_RNG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "%s: Start block: %" PRIuDADDR "", myname, start_blk);
        return 1;
    }

    if (end_blk < fs->first_block || end_blk > fs->last_block
        || end_blk < start_blk) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_WALK_RNG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "%s: End block: %" PRIuDADDR "", myname, end_blk);
        return 1;
    }

    if ((flags & TSK_FS_BLOCK_FLAG_ALIGN)
        && (start_blk % ffs->ffsbsize_f) != 0) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_ARG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "%s: start block is not block-aligned", myname);
        return 1;
    }

    /* Sanity check on flags -- make sure at least one ALLOC is set */
    if (((flags & TSK_FS_BLOCK_FLAG_ALLOC) == 0) &&
        ((flags & TSK_FS_BLOCK_FLAG_UNALLOC) == 0)) {
        flags |= (TSK_FS_BLOCK_FLAG_ALLOC | TSK_FS_BLOCK_FLAG_UNALLOC);
    }


    /*
     * Other initialization.
     */

    if ((data_buf =
            tsk_data_buf_alloc(fs->block_size * ffs->ffsbsize_f)) ==
        NULL) {
        return 1;
    }

    if (flags & TSK_FS_BLOCK_FLAG_ALIGN) {
        null_block = tsk_malloc(fs->block_size);
        if (null_block == NULL) {
            tsk_data_buf_free(data_buf);
            return 1;
        }
        memset(null_block, 0, fs->block_size);
    }

    /*
     * Iterate. This is not as tricky as it could be, because the free list
     * map covers the entire disk partition, including blocks occupied by
     * cylinder group maps, boot blocks, and other non-data blocks.
     * 
     * Examine the disk one logical block at a time. A logical block may be
     * composed of a number of fragment blocks. For example, the 4.4BSD
     * filesystem has logical blocks of 8 fragments.
     */
    for (addr = start_blk; addr <= end_blk; addr += ffs->ffsbsize_f) {

        /*
         * Be sure to use the right cylinder group information.
         */
        grp_num = dtog_lcl(fs, ffs->fs.sb1, addr);
        if (cg == 0
            || (unsigned int) tsk_gets32(fs->endian,
                cg->cg_cgx) != grp_num) {

            if (ffs_group_load(ffs, grp_num)) {
                if (flags & TSK_FS_BLOCK_FLAG_ALIGN)
                    free(null_block);

                tsk_data_buf_free(data_buf);
                return 1;
            }

            cg = (ffs_cgd *) ffs->grp_buf->data;
            freeblocks = (unsigned char *) cg_blksfree_lcl(fs, cg);
            dbase = cgbase_lcl(fs, ffs->fs.sb1, grp_num);
            dmin = cgdmin_lcl(fs, ffs->fs.sb1, grp_num);
            sblock = cgsblock_lcl(fs, ffs->fs.sb1, grp_num);
        }

        /*
         * Prepare for file systems that have a partial last logical block.
         */
        frags = (end_blk + 1 - addr > ffs->ffsbsize_f ?
            ffs->ffsbsize_f : (int) (end_blk + 1 - addr));

        /*
         * See if this logical block contains any fragments of interest. If
         * not, skip the entire logical block.
         */
        for (want = 0, faddr = addr; want == 0 && faddr < addr + frags;
            faddr++) {
            want =
                (flags &
                (isset(freeblocks,
                        faddr -
                        dbase) ? TSK_FS_BLOCK_FLAG_UNALLOC :
                    TSK_FS_BLOCK_FLAG_ALLOC));
        }
        if (want == 0)
            continue;

        /*
         * Pass blocks of interest to the application, optionally padding the
         * data with null blocks in order to maintain logical block
         * alignment.
         *
         * Beware: FFS stores file data in the blocks between the start of a
         * cylinder group and the start of its super block.
         */
        for (faddr = addr; faddr < addr + frags; faddr++) {
            myflags = (isset(freeblocks, faddr - dbase) ?
                TSK_FS_BLOCK_FLAG_UNALLOC : TSK_FS_BLOCK_FLAG_ALLOC);
            if (faddr >= sblock && faddr < dmin)
                myflags |= TSK_FS_BLOCK_FLAG_META;
            else
                myflags |= TSK_FS_BLOCK_FLAG_CONT;

            if ((tsk_verbose) && (myflags & TSK_FS_BLOCK_FLAG_META)
                && (myflags & TSK_FS_BLOCK_FLAG_UNALLOC))
                tsk_fprintf(stderr,
                    "impossible: unallocated meta block %" PRIuDADDR,
                    faddr);

            if ((flags & myflags) != myflags) {
                /* we don't want this fragment, but there is another we want,
                 * so we only print it if ALIGN is set */
                if (flags & TSK_FS_BLOCK_FLAG_ALIGN) {
                    int retval;
                    retval = action(fs, faddr, null_block, myflags, ptr);
                    if (retval == TSK_WALK_STOP) {
                        free(null_block);
                        tsk_data_buf_free(data_buf);
                        return 0;
                    }
                    else if (retval == TSK_WALK_ERROR) {
                        free(null_block);
                        tsk_data_buf_free(data_buf);
                        return 1;
                    }
                }
            }
            else {
                int retval;
                if (data_buf->addr < 0
                    || faddr >= data_buf->addr + ffs->ffsbsize_f) {
                    ssize_t cnt;
                    cnt =
                        tsk_fs_read_block(fs, data_buf,
                        fs->block_size * frags, addr);
                    if (cnt != fs->block_size * frags) {
                        if (cnt >= 0) {
                            tsk_error_reset();
                            tsk_errno = TSK_ERR_FS_READ;
                        }
                        snprintf(tsk_errstr2, TSK_ERRSTR_L,
                            "ffs_block_walk: Block %" PRIuDADDR, addr);
                        tsk_data_buf_free(data_buf);
                        if (flags & TSK_FS_BLOCK_FLAG_ALIGN)
                            free(null_block);
                        return 1;
                    }
                }
                retval = action(fs, faddr,
                    data_buf->data +
                    fs->block_size * (faddr -
                        data_buf->addr), myflags, ptr);
                if (retval == TSK_WALK_STOP) {
                    tsk_data_buf_free(data_buf);
                    if (flags & TSK_FS_BLOCK_FLAG_ALIGN)
                        free(null_block);
                    return 0;
                }
                else if (retval == TSK_WALK_ERROR) {
                    tsk_data_buf_free(data_buf);
                    if (flags & TSK_FS_BLOCK_FLAG_ALIGN)
                        free(null_block);
                    return 1;
                }
            }
        }
    }

    /*
     * Cleanup.
     */
    if (flags & TSK_FS_BLOCK_FLAG_ALIGN)
        free(null_block);
    tsk_data_buf_free(data_buf);
    return 0;
}

/**************************************************************************
 *
 * FILE WALKING
 *
 **************************************************************************/
/** \internal
 * Read a direct block and call the callback.
 *
 * @param fs File system to analyze
 * @param buf Buffer of data to analyze
 * @param length Length of file remaining
 * @param addr Address of block to read
 * @param flags
 * @param action Callback to call for each block
 * @param ptr Data to pass with callback
 *
 * @returns the number of bytes processed during call, 0 if the action wanted to 
 * stop, and -1 if an error occurred
 */
static TSK_OFF_T
ffs_file_walk_direct(TSK_FS_INFO * fs, TSK_DATA_BUF * buf,
    TSK_OFF_T length, TSK_DADDR_T addr, int flags,
    TSK_FS_FILE_WALK_CB action, void *ptr)
{
    size_t read_count;
    int myflags;

    read_count = (length < buf->size ? (size_t) length : buf->size);

    if (addr > fs->last_block) {
        tsk_error_reset();
        if (flags & TSK_FS_FILE_FLAG_RECOVER)
            tsk_errno = TSK_ERR_FS_RECOVER;
        else
            tsk_errno = TSK_ERR_FS_INODE_INT;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "ffs: Invalid direct address (too large): %"
            PRIuDADDR "", addr);
        return -1;
    }

    /* Check if this goes over the end of the image 
     * This exists when the image size is not a multiple of the block
     * size and read_count is for a full block.
     * 
     */
    if (addr + (read_count / fs->block_size) > fs->last_block) {
        read_count =
             (size_t)(fs->last_block - addr + 1) * fs->block_size;
    }

    if (addr == 0) {
        if (0 == (flags & TSK_FS_FILE_FLAG_NOSPARSE)) {
            int retval;
            myflags =
                TSK_FS_BLOCK_FLAG_CONT | TSK_FS_BLOCK_FLAG_ALLOC |
                TSK_FS_BLOCK_FLAG_SPARSE;

            if ((flags & TSK_FS_FILE_FLAG_AONLY) == 0)
                memset(buf->data, 0, (size_t) read_count);

            retval = action(fs, addr, buf->data, read_count, myflags, ptr);
            if (retval == TSK_WALK_STOP)
                return 0;
            else if (retval == TSK_WALK_ERROR)
                return -1;
        }
    }
    else {
        int retval;
        myflags = TSK_FS_BLOCK_FLAG_CONT;

        if ((flags & TSK_FS_FILE_FLAG_AONLY) == 0) {
            ssize_t cnt;
            cnt =
                tsk_fs_read_block(fs, buf, roundup(read_count,
                    FFS_DEV_BSIZE), addr);
            if (cnt != (ssize_t) roundup(read_count, FFS_DEV_BSIZE)) {
                if (cnt >= 0) {
                    tsk_error_reset();
                    tsk_errno = TSK_ERR_FS_READ;
                }
                snprintf(tsk_errstr2, TSK_ERRSTR_L,
                    "ffs_file_walk_direct: Block %" PRIuDADDR, addr);
                return -1;
            }
        }

        retval = action(fs, addr, buf->data, read_count, myflags, ptr);
        if (retval == TSK_WALK_STOP)
            return 0;
        else if (retval == TSK_WALK_ERROR)
            return -1;
    }
    return (TSK_OFF_T)read_count;
}


/** \internal
 * Read an indirect block and process the contents. 
 *
 * @param fs File system to analyze
 * @param buf Buffer of data to analyze
 * @param length Length of file remaining
 * @param addr Address of block to read
 * @param level Level of the indirect pointers
 * @param flags
 * @param action Callback to call for each block
 * @param ptr Data to pass with callback
 *
 * @returns the number of bytes processed during call, 0 if the action wanted to 
 * stop, and -1 if an error occurred
 */
static TSK_OFF_T
ffs_file_walk_indir(TSK_FS_INFO * fs, TSK_DATA_BUF * buf[], TSK_OFF_T length,
    TSK_DADDR_T addr, int level, int flags, TSK_FS_FILE_WALK_CB action,
    void *ptr)
{
    char *myname = "ffs_file_walk_indir";
    TSK_OFF_T todo_count = length;
    unsigned int n;

    if (tsk_verbose)
        tsk_fprintf(stderr, "%s: level %d block %" PRIuDADDR "\n", myname,
            level, addr);

    if (addr > fs->last_block) {
        tsk_error_reset();
        if (flags & TSK_FS_FILE_FLAG_RECOVER)
            tsk_errno = TSK_ERR_FS_RECOVER;
        else
            tsk_errno = TSK_ERR_FS_INODE_INT;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "ffs: Indirect block address too large: %" PRIuDADDR "", addr);
        return -1;
    }

    /*
     * Read a block of disk addresses.
     */
    if (addr == 0) {
        memset(buf[level]->data, 0, buf[level]->size);
    }
    else {
        ssize_t cnt;
        cnt = tsk_fs_read_block(fs, buf[level], buf[level]->size, addr);
        if (cnt != buf[level]->size) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_errno = TSK_ERR_FS_READ;
            }
            snprintf(tsk_errstr2, TSK_ERRSTR_L,
                "ffs_file_walk_indir: Block %" PRIuDADDR, addr);
            return -1;
        }
    }


    /* we only call the action  if the META flag is set */
    if (flags & TSK_FS_FILE_FLAG_META) {
        int myflags = TSK_FS_BLOCK_FLAG_META;
        int retval;
        retval =
            action(fs, addr, buf[level]->data, buf[level]->size, myflags,
            ptr);
        if (retval == TSK_WALK_STOP)
            return 0;
        else if (retval == TSK_WALK_ERROR)
            return -1;
    }


    /*   
     * For each disk address, copy a direct block or process an indirect
     * block.
     */
    if ((fs->ftype == TSK_FS_INFO_TYPE_FFS_1)
        || (fs->ftype == TSK_FS_INFO_TYPE_FFS_1B)) {

        uint32_t *iaddr = (uint32_t *) buf[level]->data;
        for (n = 0;
            todo_count > 0 && n < buf[level]->size / sizeof(*iaddr); n++) {

            TSK_OFF_T prevcnt = todo_count;

            if (tsk_getu32(fs->endian,
                    (uint8_t *) & iaddr[n]) > fs->last_block) {
                tsk_error_reset();
                if (flags & TSK_FS_FILE_FLAG_RECOVER)
                    tsk_errno = TSK_ERR_FS_RECOVER;
                else
                    tsk_errno = TSK_ERR_FS_INODE_INT;
                snprintf(tsk_errstr, TSK_ERRSTR_L,
                    "ffs: Address in indirect block too large: %"
                    PRIu32 "", tsk_getu32(fs->endian,
                        (uint8_t *) & iaddr[n]));
                return -1;
            }

            if (level == 1)
                todo_count -= ffs_file_walk_direct(fs, buf[0], todo_count,
                    (TSK_DADDR_T) tsk_getu32(fs->endian,
                        (uint8_t *) & iaddr[n]), flags, action, ptr);
            else
                todo_count -= ffs_file_walk_indir(fs, buf, todo_count,
                    (TSK_DADDR_T) tsk_getu32(fs->endian,
                        (uint8_t
                            *) & iaddr[n]), level - 1, flags, action, ptr);
            /* This occurs when 0 is returned, which means we want to stop */
            if (prevcnt == todo_count)
                return 0;
            else if (prevcnt < todo_count)
                return -1;
        }
    }
    else {
        uint64_t *iaddr = (uint64_t *) buf[level]->data;
        for (n = 0;
            todo_count > 0 && n < buf[level]->size / sizeof(*iaddr); n++) {

            TSK_OFF_T prevcnt = todo_count;

            if (tsk_getu64(fs->endian,
                    (uint8_t *) & iaddr[n]) > fs->last_block) {
                tsk_error_reset();
                if (flags & TSK_FS_FILE_FLAG_RECOVER)
                    tsk_errno = TSK_ERR_FS_RECOVER;
                else
                    tsk_errno = TSK_ERR_FS_INODE_INT;
                snprintf(tsk_errstr, TSK_ERRSTR_L,
                    "ffs: Address in indirect block too large: %"
                    PRIuDADDR "", tsk_getu64(fs->endian,
                        (uint8_t *) & iaddr[n]));
                return -1;
            }

            if (level == 1)
                todo_count -= ffs_file_walk_direct(fs, buf[0], todo_count,
                    (TSK_DADDR_T) tsk_getu64(fs->endian,
                        (uint8_t *) & iaddr[n]), flags, action, ptr);
            else
                todo_count -= ffs_file_walk_indir(fs, buf, todo_count,
                    (TSK_DADDR_T) tsk_getu64(fs->endian,
                        (uint8_t
                            *) & iaddr[n]), level - 1, flags, action, ptr);

            /* This occurs when 0 is returned, which means we want to stop */
            if (prevcnt == todo_count)
                return 0;
            if (prevcnt < todo_count)
                return -1;
        }
    }

    return (length - todo_count);
}


/**
 * Calls a callback function with the contents of each block in a file. 
 * flag values: TSK_FS_FILE_FLAG_NOSPARSE, TSK_FS_FILE_FLAG_AONLY, TSK_FS_FILE_FLAG_SLACK
 * TSK_FS_FILE_FLAG_META
 *
 * If TSK_FS_FILE_FLAG_RECOVER is set, then most error codes are set to
 * _RECOVER.  No special recovery logic exists in this code. 
 *
 * The action will use the flags: TSK_FS_BLOCK_FLAG_CONT, TSK_FS_BLOCK_FLAG_META
 * -- @@@ Currently do not do _ALLOC and _UNALLOC
 *
 * @param fs File system file is located in
 * @param inode File to read and analyze
 * @param type Attribute type to read and analyze (does not apply to FFS)
 * @param id Attribute id to read and analyze (does not apply to FFS)
 * @param flags Flags to use while reading
 * @param action Callback function that is called for each block
 * @param ptr Pointer to data that is passed to the callback
 * @returns 1 on error and 0 on success
 */
uint8_t
ffs_file_walk(TSK_FS_INFO * fs, TSK_FS_INODE * inode, uint32_t type,
    uint16_t id, TSK_FS_FILE_FLAG_ENUM flags, TSK_FS_FILE_WALK_CB action,
    void *ptr)
{
    FFS_INFO *ffs = (FFS_INFO *) fs;
    TSK_OFF_T length = 0;
    TSK_OFF_T read_b = 0;
    TSK_DATA_BUF **buf;
    int n;
    int level;

    // clean up any error messages that are lying around
    tsk_error_reset();

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "ffs_file_walk: Processing file %" PRIuINUM "\n", inode->addr);

    /*
     * Initialize a buffer for each level of indirection that is supported by
     * this inode. The level 0 buffer is sized to the logical block size used
     * for files. The level 1.. buffers are sized to the block size used for
     * indirect blocks.
     */
    if ((buf =
            (TSK_DATA_BUF **) tsk_malloc(sizeof(*buf) *
                (inode->indir_count + 1))) == NULL)
        return 1;

    if ((buf[0] = tsk_data_buf_alloc(ffs->ffsbsize_b)) == NULL) {
        free(buf);
        return 1;
    }

    length = inode->size;
    /* If we want the slack of the last fragment, then roundup */
    if (flags & TSK_FS_FILE_FLAG_SLACK)
        length = roundup(length, fs->block_size);

    /*
     * Read the file blocks. First the direct blocks, then the indirect ones.
     */
    for (n = 0; length > 0 && n < inode->direct_count; n++) {
        read_b = ffs_file_walk_direct(fs, buf[0], length,
            inode->direct_addr[n], flags, action, ptr);

        if (read_b == -1) {
            tsk_data_buf_free(buf[0]);
            free(buf);
            return 1;
        }
        else if (read_b == 0) {
            tsk_data_buf_free(buf[0]);
            free(buf);
            return 0;
        }
        length -= read_b;
    }

    /* if there is still data left, read the indirect */
    if (length > 0) {

        /* allocate buffers */
        for (level = 1; level <= inode->indir_count; level++) {
            if ((buf[level] = tsk_data_buf_alloc(ffs->ffsbsize_b)) == NULL) {
                int f;
                for (f = 0; f < level; f++) {
                    tsk_data_buf_free(buf[f]);
                }
                free(buf);
                return 1;
            }
        }

        for (level = 1; length > 0 && level <= inode->indir_count; level++) {
            read_b = ffs_file_walk_indir(fs, buf, length,
                inode->indir_addr[level - 1], level, flags, action, ptr);

            if ((read_b == 0) || (read_b == -1))
                break;
            length -= read_b;
        }

        /*
         * Cleanup.
         */
        for (level = 1; level <= inode->indir_count; level++)
            tsk_data_buf_free(buf[level]);
    }

    tsk_data_buf_free(buf[0]);
    free(buf);

    if (read_b == -1)
        return 1;
    else
        return 0;
}


/*
 * return 1 on error and 0 on success
 */
static uint8_t
ffs_fscheck(TSK_FS_INFO * fs, FILE * hFile)
{
    tsk_error_reset();
    tsk_errno = TSK_ERR_FS_FUNC;
    snprintf(tsk_errstr, TSK_ERRSTR_L,
        "fscheck not implemented for ffs yet");
    return 1;
}


/**
 * Print details about the file system to a file handle. 
 *
 * @param fs File system to print details on
 * @param hFile File handle to print text to
 * 
 * @returns 1 on error and 0 on success
 */
static uint8_t
ffs_fsstat(TSK_FS_INFO * fs, FILE * hFile)
{
    unsigned int i;
    time_t tmptime;
    ffs_csum1 *csum1 = NULL;
    ffs_cgd *cgd = NULL;

    FFS_INFO *ffs = (FFS_INFO *) fs;
    ffs_sb1 *sb1 = ffs->fs.sb1;
    ffs_sb2 *sb2 = ffs->fs.sb2;
    int flags;

    // clean up any error messages that are lying around
    tsk_error_reset();

    tsk_fprintf(hFile, "FILE SYSTEM INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    if ((fs->ftype == TSK_FS_INFO_TYPE_FFS_1)
        || (fs->ftype == TSK_FS_INFO_TYPE_FFS_1B)) {
        tsk_fprintf(hFile, "File System Type: UFS 1\n");
        tmptime = tsk_getu32(fs->endian, sb1->wtime);
        tsk_fprintf(hFile, "Last Written: %s",
            (tmptime > 0) ? asctime(localtime(&tmptime)) : "empty");
        tsk_fprintf(hFile, "Last Mount Point: %s\n", sb1->last_mnt);

        flags = sb1->fs_flags;
    }
    else {
        tsk_fprintf(hFile, "File System Type: UFS 2\n");
        tmptime = tsk_getu32(fs->endian, sb2->wtime);
        tsk_fprintf(hFile, "Last Written: %s",
            (tmptime > 0) ? asctime(localtime(&tmptime)) : "empty");
        tsk_fprintf(hFile, "Last Mount Point: %s\n", sb2->last_mnt);
        tsk_fprintf(hFile, "Volume Name: %s\n", sb2->volname);
        tsk_fprintf(hFile, "System UID: %" PRIu64 "\n",
            tsk_getu64(fs->endian, sb2->swuid));
        flags = tsk_getu32(fs->endian, sb2->fs_flags);
    }

    if (flags) {
        int cnt = 0;

        tsk_fprintf(hFile, "Flags: ");

        if (flags & FFS_SB_FLAG_UNCLEAN)
            tsk_fprintf(hFile, "%s Unclean", (cnt++ == 0 ? "" : ","));

        if (flags & FFS_SB_FLAG_SOFTDEP)
            tsk_fprintf(hFile, "%s Soft Dependencies",
                (cnt++ == 0 ? "" : ","));

        if (flags & FFS_SB_FLAG_NEEDFSCK)
            tsk_fprintf(hFile, "%s Needs fsck", (cnt++ == 0 ? "" : ","));

        if (flags & FFS_SB_FLAG_INDEXDIR)
            tsk_fprintf(hFile, "%s Index directories",
                (cnt++ == 0 ? "" : ","));

        if (flags & FFS_SB_FLAG_ACL)
            tsk_fprintf(hFile, "%s ACLs", (cnt++ == 0 ? "" : ","));

        if (flags & FFS_SB_FLAG_MULTILABEL)
            tsk_fprintf(hFile, "%s TrustedBSD MAC Multi-label",
                (cnt++ == 0 ? "" : ","));

        if (flags & FFS_SB_FLAG_UPDATED)
            tsk_fprintf(hFile, "%s Updated Flag Location",
                (cnt++ == 0 ? "" : ","));

        tsk_fprintf(hFile, "\n");
    }



    tsk_fprintf(hFile, "\nMETADATA INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    tsk_fprintf(hFile, "Inode Range: %" PRIuINUM " - %" PRIuINUM "\n",
        fs->first_inum, fs->last_inum);
    tsk_fprintf(hFile, "Root Directory: %" PRIuINUM "\n", fs->root_inum);
    if ((fs->ftype == TSK_FS_INFO_TYPE_FFS_1)
        || (fs->ftype == TSK_FS_INFO_TYPE_FFS_1B)) {
        tsk_fprintf(hFile, "Num of Avail Inodes: %" PRIu32 "\n",
            tsk_getu32(fs->endian, sb1->cstotal.ino_free));
        tsk_fprintf(hFile, "Num of Directories: %" PRIu32 "\n",
            tsk_getu32(fs->endian, sb1->cstotal.dir_num));
    }
    else {
        tsk_fprintf(hFile, "Num of Avail Inodes: %" PRIu64 "\n",
            tsk_getu64(fs->endian, sb2->cstotal.ino_free));
        tsk_fprintf(hFile, "Num of Directories: %" PRIu64 "\n",
            tsk_getu64(fs->endian, sb2->cstotal.dir_num));
    }


    tsk_fprintf(hFile, "\nCONTENT INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    tsk_fprintf(hFile, "Fragment Range: %" PRIuDADDR " - %" PRIuDADDR "\n",
        fs->first_block, fs->last_block);

    if (fs->last_block != fs->last_block_act)
        tsk_fprintf(hFile,
            "Total Range in Image: %" PRIuDADDR " - %" PRIuDADDR "\n",
            fs->first_block, fs->last_block_act);

    tsk_fprintf(hFile, "Block Size: %u\n", ffs->ffsbsize_b);
    tsk_fprintf(hFile, "Fragment Size: %u\n", fs->block_size);

    if ((fs->ftype == TSK_FS_INFO_TYPE_FFS_1)
        || (fs->ftype == TSK_FS_INFO_TYPE_FFS_1B)) {
        tsk_fprintf(hFile, "Num of Avail Full Blocks: %" PRIu32 "\n",
            tsk_getu32(fs->endian, sb1->cstotal.blk_free));
        tsk_fprintf(hFile, "Num of Avail Fragments: %" PRIu32 "\n",
            tsk_getu32(fs->endian, sb1->cstotal.frag_free));
    }
    else {
        tsk_fprintf(hFile, "Num of Avail Full Blocks: %" PRIu64 "\n",
            tsk_getu64(fs->endian, sb2->cstotal.blk_free));
        tsk_fprintf(hFile, "Num of Avail Fragments: %" PRIu64 "\n",
            tsk_getu64(fs->endian, sb2->cstotal.frag_free));
    }

    tsk_fprintf(hFile, "\nCYLINDER GROUP INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    tsk_fprintf(hFile, "Number of Cylinder Groups: %" PRIu32 "\n",
        ffs->groups_count);
    tsk_fprintf(hFile, "Inodes per group: %" PRId32 "\n",
        tsk_gets32(fs->endian, sb1->cg_inode_num));
    tsk_fprintf(hFile, "Fragments per group: %" PRId32 "\n",
        tsk_gets32(fs->endian, sb1->cg_frag_num));


    /* UFS 1 and 2 use the same ssize field  and use the same csum1 */
    if (tsk_getu32(fs->endian, sb1->cg_ssize_b)) {
        ssize_t cnt;
        csum1 =
            (ffs_csum1 *) tsk_malloc(tsk_getu32(fs->endian,
                sb1->cg_ssize_b));
        if (csum1 == NULL)
            return 1;

        if ((fs->ftype == TSK_FS_INFO_TYPE_FFS_1)
            || (fs->ftype == TSK_FS_INFO_TYPE_FFS_1B)) {
            cnt =
                tsk_fs_read_block_nobuf(fs, (char *) csum1,
                tsk_getu32(fs->endian, sb1->cg_ssize_b),
                (TSK_DADDR_T) tsk_getu32(fs->endian, sb1->cg_saddr));

            if (cnt != tsk_getu32(fs->endian, sb1->cg_ssize_b)) {
                if (cnt >= 0) {
                    tsk_error_reset();
                    tsk_errno = TSK_ERR_FS_READ;
                }
                snprintf(tsk_errstr2, TSK_ERRSTR_L,
                    "ffs_fsstat: FFS1 group descriptor at %"
                    PRIu32, tsk_getu32(fs->endian, sb1->cg_saddr));
                return 1;
            }
        }
        else {
            cnt = tsk_fs_read_block_nobuf
                (fs, (char *) csum1, tsk_getu32(fs->endian,
                    sb2->cg_ssize_b), (TSK_DADDR_T) tsk_getu64(fs->endian,
                    sb2->cg_saddr));
            if (cnt != tsk_getu32(fs->endian, sb2->cg_ssize_b)) {
                if (cnt >= 0) {
                    tsk_error_reset();
                    tsk_errno = TSK_ERR_FS_READ;
                }
                snprintf(tsk_errstr2, TSK_ERRSTR_L,
                    "ffs_fsstat: FFS2 group descriptor at %"
                    PRIu64, tsk_getu64(fs->endian, sb2->cg_saddr));
                return 1;
            }
        }
    }

    for (i = 0; i < ffs->groups_count; i++) {

        if (ffs_group_load(ffs, i))
            return 1;
        cgd = (ffs_cgd *) ffs->grp_buf->data;

        tsk_fprintf(hFile, "\nGroup %d:\n", i);
        if (cgd) {
            if ((fs->ftype == TSK_FS_INFO_TYPE_FFS_1)
                || (fs->ftype == TSK_FS_INFO_TYPE_FFS_1B)) {
                tmptime = tsk_getu32(fs->endian, cgd->wtime);
            }
            else {
                ffs_cgd2 *cgd2 = (ffs_cgd2 *) cgd;
                tmptime = (uint32_t) tsk_getu64(fs->endian, cgd2->wtime);
            }
            tsk_fprintf(hFile, "  Last Written: %s",
                (tmptime > 0) ? asctime(localtime(&tmptime)) : "empty");
        }

        tsk_fprintf(hFile, "  Inode Range: %" PRIu32 " - %" PRIu32 "\n",
            (tsk_gets32(fs->endian, sb1->cg_inode_num) * i),
            ((uint32_t) ((tsk_gets32(fs->endian,
                            sb1->cg_inode_num) * (i + 1)) - 1)
                < fs->last_inum) ? (uint32_t) ((tsk_gets32(fs->endian,
                        sb1->cg_inode_num) * (i + 1)) -
                1) : (uint32_t) fs->last_inum);

        tsk_fprintf(hFile,
            "  Fragment Range: %" PRIuDADDR " - %" PRIuDADDR "\n",
            cgbase_lcl(fs, sb1, i),
            ((cgbase_lcl(fs, sb1, i + 1) - 1) <
                fs->last_block) ? (cgbase_lcl(fs, sb1,
                    i + 1) - 1) : fs->last_block);

        /* The first group is special because the first 16 sectors are
         * reserved for the boot block.  
         * the next contains the primary Super Block 
         */
        if (!i) {
            tsk_fprintf(hFile, "    Boot Block: 0 - %" PRIu32 "\n",
                (uint32_t) (15 * 512 / fs->block_size));


            tsk_fprintf(hFile,
                "    Super Block: %" PRIu32 " - %" PRIu32 "\n",
                (uint32_t) (16 * 512 / fs->block_size),
                (uint32_t) ((16 * 512 / fs->block_size) + ffs->ffsbsize_f -
                    1));
        }

        tsk_fprintf(hFile,
            "    Super Block: %" PRIuDADDR " - %" PRIuDADDR "\n",
            cgsblock_lcl(fs, sb1, i),
            (cgsblock_lcl(fs, sb1, i) + ffs->ffsbsize_f - 1));


        tsk_fprintf(hFile,
            "    Group Desc: %" PRIuDADDR " - %" PRIuDADDR "\n",
            cgtod_lcl(fs, sb1, i), (cgtod_lcl(fs, sb1,
                    i) + ffs->ffsbsize_f - 1));


        if (fs->ftype == TSK_FS_INFO_TYPE_FFS_2) {
            tsk_fprintf(hFile,
                "    Inode Table: %" PRIuDADDR " - %" PRIuDADDR "\n",
                cgimin_lcl(fs, sb1, i),
                (cgimin_lcl(fs, sb1, i) +
                    ((roundup
                            (tsk_gets32(fs->endian,
                                    sb1->cg_inode_num) *
                                sizeof(ffs_inode2), fs->block_size)
                            / fs->block_size) - 1)));
        }
        else {
            tsk_fprintf(hFile,
                "    Inode Table: %" PRIuDADDR " - %" PRIuDADDR "\n",
                cgimin_lcl(fs, sb1, i),
                (cgimin_lcl(fs, sb1, i) +
                    ((roundup
                            (tsk_gets32(fs->endian,
                                    sb1->cg_inode_num) *
                                sizeof(ffs_inode1), fs->block_size)
                            / fs->block_size) - 1)));
        }

        tsk_fprintf(hFile, "    Data Fragments: ");

        /* For all groups besides the first, the space before the
         * super block is also used for data
         */
        if (i)
            tsk_fprintf(hFile, "%" PRIuDADDR " - %" PRIuDADDR ", ",
                cgbase_lcl(fs, sb1, i), cgsblock_lcl(fs, sb1, i) - 1);

        tsk_fprintf(hFile, "%" PRIuDADDR " - %" PRIuDADDR "\n",
            cgdmin_lcl(fs, sb1, i),
            ((cgbase_lcl(fs, sb1, i + 1) - 1) < fs->last_block) ?
            (cgbase_lcl(fs, sb1, i + 1) - 1) : fs->last_block);


        if ((csum1)
            && ((i + 1) * sizeof(ffs_csum1) < tsk_getu32(fs->endian,
                    sb1->cg_ssize_b))) {
            tsk_fprintf(hFile,
                "  Global Summary (from the superblock summary area):\n");
            tsk_fprintf(hFile, "    Num of Dirs: %" PRIu32 "\n",
                tsk_getu32(fs->endian, &csum1[i].dir_num));
            tsk_fprintf(hFile, "    Num of Avail Blocks: %" PRIu32 "\n",
                tsk_getu32(fs->endian, &csum1[i].blk_free));
            tsk_fprintf(hFile, "    Num of Avail Inodes: %" PRIu32 "\n",
                tsk_getu32(fs->endian, &csum1[i].ino_free));
            tsk_fprintf(hFile, "    Num of Avail Frags: %" PRIu32 "\n",
                tsk_getu32(fs->endian, &csum1[i].frag_free));
        }

        if (cgd) {
            tsk_fprintf(hFile,
                "  Local Summary (from the group descriptor):\n");
            tsk_fprintf(hFile, "    Num of Dirs: %" PRIu32 "\n",
                tsk_getu32(fs->endian, &cgd->cs.dir_num));
            tsk_fprintf(hFile, "    Num of Avail Blocks: %" PRIu32 "\n",
                tsk_getu32(fs->endian, &cgd->cs.blk_free));
            tsk_fprintf(hFile, "    Num of Avail Inodes: %" PRIu32 "\n",
                tsk_getu32(fs->endian, &cgd->cs.ino_free));
            tsk_fprintf(hFile, "    Num of Avail Frags: %" PRIu32 "\n",
                tsk_getu32(fs->endian, &cgd->cs.frag_free));
            tsk_fprintf(hFile,
                "    Last Block Allocated: %" PRIuDADDR "\n",
                tsk_getu32(fs->endian,
                    &cgd->last_alloc_blk) + cgbase_lcl(fs, sb1, i));
            tsk_fprintf(hFile,
                "    Last Fragment Allocated: %" PRIuDADDR "\n",
                tsk_getu32(fs->endian,
                    &cgd->last_alloc_frag) + cgbase_lcl(fs, sb1, i));
            tsk_fprintf(hFile, "    Last Inode Allocated: %" PRIu32 "\n",
                tsk_getu32(fs->endian,
                    &cgd->last_alloc_ino) + (tsk_gets32(fs->endian,
                        sb1->cg_inode_num) * i));
        }
    }
    return 0;
}



/************************* istat *******************************/

/* indirect block accounting */
#define FFS_INDIR_SIZ   64

typedef struct {
    FILE *hFile;
    int idx;
    TSK_DADDR_T indirl[FFS_INDIR_SIZ];
    unsigned char indir_idx;
} FFS_PRINT_ADDR;


static TSK_WALK_RET_ENUM
print_addr_act(TSK_FS_INFO * fs, TSK_DADDR_T addr, char *buf,
    size_t size, TSK_FS_BLOCK_FLAG_ENUM flags, void *ptr)
{
    FFS_PRINT_ADDR *print = (FFS_PRINT_ADDR *) ptr;

    if (flags & TSK_FS_BLOCK_FLAG_CONT) {
        int i, s;
        /* cycle through the fragments if they exist */
        for (i = 0, s = (int) size; s > 0; s -= fs->block_size, i++) {

            /* sparse file */
            if (addr)
                tsk_fprintf(print->hFile, "%" PRIuDADDR " ", addr + i);
            else
                tsk_fprintf(print->hFile, "0 ");

            if (++(print->idx) == 8) {
                tsk_fprintf(print->hFile, "\n");
                print->idx = 0;
            }
        }
    }

    /* this must be an indirect block pointer, so put it in the list */
    else if (flags & TSK_FS_BLOCK_FLAG_META) {
        if (print->indir_idx < FFS_INDIR_SIZ)
            print->indirl[(print->indir_idx)++] = addr;
    }
    return TSK_WALK_CONT;
}



/**
 * Print details on a specific file to a file handle. 
 *
 * @param fs File system file is located in
 * @param hFile File handle to print text to
 * @param inum Address of file in file system
 * @param numblock The number of blocks in file to force print (can go beyond file size)
 * @param sec_skew Clock skew in seconds to also print times in
 * 
 * @returns 1 on error and 0 on success
 */
static uint8_t
ffs_istat(TSK_FS_INFO * fs, FILE * hFile, TSK_INUM_T inum, TSK_DADDR_T numblock,
    int32_t sec_skew)
{
    FFS_INFO *ffs = (FFS_INFO *) fs;
    TSK_FS_INODE *fs_inode;
    char ls[12];
    FFS_PRINT_ADDR print;

    // clean up any error messages that are lying around
    tsk_error_reset();

    fs_inode = ffs_inode_lookup(fs, inum);
    if (fs_inode == NULL)
        return 1;

    tsk_fprintf(hFile, "inode: %" PRIuINUM "\n", inum);
    tsk_fprintf(hFile, "%sAllocated\n",
        (fs_inode->flags & TSK_FS_INODE_FLAG_ALLOC) ? "" : "Not ");

    tsk_fprintf(hFile, "Group: %" PRI_FFSGRP "\n", ffs->grp_num);

    if (fs_inode->link)
        tsk_fprintf(hFile, "symbolic link to: %s\n", fs_inode->link);

    tsk_fprintf(hFile, "uid / gid: %"PRIuUID" / %"PRIuGID"\n",
        fs_inode->uid, fs_inode->gid);


    tsk_fs_make_ls(fs_inode->mode, ls);
    tsk_fprintf(hFile, "mode: %s\n", ls);

    tsk_fprintf(hFile, "size: %" PRIuOFF "\n", fs_inode->size);
    tsk_fprintf(hFile, "num of links: %u\n", fs_inode->nlink);


    if (sec_skew != 0) {
        tsk_fprintf(hFile, "\nAdjusted Inode Times:\n");
        fs_inode->mtime -= sec_skew;
        fs_inode->atime -= sec_skew;
        fs_inode->ctime -= sec_skew;

        tsk_fprintf(hFile, "Accessed:\t%s", ctime(&fs_inode->atime));
        tsk_fprintf(hFile, "File Modified:\t%s", ctime(&fs_inode->mtime));
        tsk_fprintf(hFile, "Inode Modified:\t%s", ctime(&fs_inode->ctime));

        fs_inode->mtime += sec_skew;
        fs_inode->atime += sec_skew;
        fs_inode->ctime += sec_skew;

        tsk_fprintf(hFile, "\nOriginal Inode Times:\n");
    }
    else {
        tsk_fprintf(hFile, "\nInode Times:\n");
    }

    tsk_fprintf(hFile, "Accessed:\t%s", ctime(&fs_inode->atime));
    tsk_fprintf(hFile, "File Modified:\t%s", ctime(&fs_inode->mtime));
    tsk_fprintf(hFile, "Inode Modified:\t%s", ctime(&fs_inode->ctime));

    if (fs->ftype == TSK_FS_INFO_TYPE_FFS_2) {
        ffs_inode2 *in = (ffs_inode2 *) ffs->dino_buf;
        /* Are there extended attributes */
        if (tsk_getu32(fs->endian, in->di_extsize) > 0) {
            ffs_extattr *ea;
            uint32_t size;
            char name[257];
            TSK_DATA_BUF *data_buf;

            if ((data_buf = tsk_data_buf_alloc(ffs->ffsbsize_b)) == NULL) {
                tsk_fs_inode_free(fs_inode);
                return 1;
            }

            size = tsk_getu32(fs->endian, in->di_extsize);
            tsk_fprintf(hFile, "\nExtended Attributes:\n");
            tsk_fprintf(hFile,
                "Size: %" PRIu32 " (%" PRIu64 ", %" PRIu64 ")\n", size,
                tsk_getu64(fs->endian, in->di_extb[0]),
                tsk_getu64(fs->endian, in->di_extb[1]));


            /* Process first block */
            // @@@ Incorporate values into this as well
            if ((tsk_getu64(fs->endian, in->di_extb[0]) >= fs->first_block)
                && (tsk_getu64(fs->endian,
                        in->di_extb[0]) <= fs->last_block)) {
                uintptr_t end;
                ssize_t cnt;

                cnt = tsk_fs_read_block(fs, data_buf, ffs->ffsbsize_b,
                    tsk_getu64(fs->endian, in->di_extb[0]));
                if (cnt != ffs->ffsbsize_b) {
                    if (cnt >= 0) {
                        tsk_error_reset();
                        tsk_errno = TSK_ERR_FS_READ;
                    }
                    snprintf(tsk_errstr2, TSK_ERRSTR_L,
                        "ffs_istat: FFS2 extended attribute 0 at %"
                        PRIu64, tsk_getu64(fs->endian, in->di_extb[0]));
                    tsk_fs_inode_free(fs_inode);
                    return 1;
                }

                ea = (ffs_extattr *) data_buf->data;

                if (size > ffs->ffsbsize_b) {
                    end = (uintptr_t) ea + ffs->ffsbsize_b;
                    size -= ffs->ffsbsize_b;
                }
                else {
                    end = (uintptr_t) ea + size;
                    size = 0;
                }

                for (; (uintptr_t) ea < end;
                    ea =
                    (ffs_extattr *) ((uintptr_t) ea +
                        tsk_getu32(fs->endian, ea->reclen))) {
                    memcpy(name, ea->name, ea->nlen);
                    name[ea->nlen] = '\0';
                    tsk_fprintf(hFile, "%s\n", name);
                }
            }
            if ((tsk_getu64(fs->endian, in->di_extb[1]) >= fs->first_block)
                && (tsk_getu64(fs->endian,
                        in->di_extb[1]) <= fs->last_block)) {
                uintptr_t end;
                ssize_t cnt;

                cnt = tsk_fs_read_block(fs, data_buf, ffs->ffsbsize_b,
                    tsk_getu64(fs->endian, in->di_extb[1]));
                if (cnt != ffs->ffsbsize_b) {
                    if (cnt >= 0) {
                        tsk_error_reset();
                        tsk_errno = TSK_ERR_FS_FUNC;
                    }
                    snprintf(tsk_errstr2, TSK_ERRSTR_L,
                        "ffs_istat: FFS2 extended attribute 1 at %"
                        PRIu64, tsk_getu64(fs->endian, in->di_extb[1]));
                    tsk_fs_inode_free(fs_inode);
                    return 1;
                }

                ea = (ffs_extattr *) data_buf->data;

                if (size > ffs->ffsbsize_b)
                    end = (uintptr_t) ea + ffs->ffsbsize_b;
                else
                    end = (uintptr_t) ea + size;

                for (; (uintptr_t) ea < end;
                    ea =
                    (ffs_extattr *) ((uintptr_t) ea +
                        tsk_getu32(fs->endian, ea->reclen))) {
                    memcpy(name, ea->name, ea->nlen);
                    name[ea->nlen] = '\0';
                    tsk_fprintf(hFile, "%s\n", name);
                }
            }
        }
    }


    /* A bad hack to force a specified number of blocks */
    if (numblock > 0)
        fs_inode->size = numblock * ffs->ffsbsize_b;

    tsk_fprintf(hFile, "\nDirect Blocks:\n");


    print.indir_idx = 0;
    print.idx = 0;
    print.hFile = hFile;

    if (ffs_file_walk(fs, fs_inode, 0, 0,
            TSK_FS_FILE_FLAG_AONLY | TSK_FS_FILE_FLAG_META |
            TSK_FS_FILE_FLAG_NOID, print_addr_act, (void *) &print)) {
        tsk_fprintf(hFile, "\nError reading blocks in file\n");
        tsk_error_print(hFile);
        tsk_fs_inode_free(fs_inode);
        return 1;
    }

    if (print.idx != 0)
        tsk_fprintf(hFile, "\n");

    /* print indirect blocks */
    if (print.indir_idx > 0) {
        int i, printidx;
        tsk_fprintf(hFile, "\nIndirect Blocks:\n");

        printidx = 0;

        for (i = 0; i < print.indir_idx; i++) {
            unsigned int a;
            /* Cycle through the fragments in the block */
            for (a = 0; a < ffs->ffsbsize_f; a++) {
                tsk_fprintf(hFile, "%" PRIuDADDR " ", print.indirl[i] + a);
                if (++printidx == 8) {
                    tsk_fprintf(hFile, "\n");
                    printidx = 0;
                }
            }
        }
        if (printidx != 0)
            tsk_fprintf(hFile, "\n");
    }

    tsk_fs_inode_free(fs_inode);
    return 0;
}

/* Return 1 on error and 0 on success */
uint8_t
ffs_jopen(TSK_FS_INFO * fs, TSK_INUM_T inum)
{
    tsk_error_reset();
    tsk_errno = TSK_ERR_FS_FUNC;
    snprintf(tsk_errstr, TSK_ERRSTR_L, "UFS does not have a journal");
    return 1;
}

uint8_t
ffs_jentry_walk(TSK_FS_INFO * fs, int flags, TSK_FS_JENTRY_WALK_CB action,
    void *ptr)
{
    tsk_error_reset();
    tsk_errno = TSK_ERR_FS_FUNC;
    snprintf(tsk_errstr, TSK_ERRSTR_L, "UFS does not have a journal");
    return 1;
}


uint8_t
ffs_jblk_walk(TSK_FS_INFO * fs, TSK_DADDR_T start, TSK_DADDR_T end, int flags,
    TSK_FS_JBLK_WALK_CB action, void *ptr)
{
    tsk_error_reset();
    tsk_errno = TSK_ERR_FS_FUNC;
    snprintf(tsk_errstr, TSK_ERRSTR_L, "UFS does not have a journal");
    return 1;
}



/* ffs_close - close a fast file system */
static void
ffs_close(TSK_FS_INFO * fs)
{
    FFS_INFO *ffs = (FFS_INFO *) fs;

    if (ffs->grp_buf)
        tsk_data_buf_free(ffs->grp_buf);

    if (ffs->itbl_buf)
        tsk_data_buf_free(ffs->itbl_buf);

    if (ffs->dino_buf)
        free(ffs->dino_buf);

    if (fs->list_inum_named) {
        tsk_list_free(fs->list_inum_named);
        fs->list_inum_named = NULL;
    }

    free((char *) ffs->fs.sb1);
    free(ffs);
}

/**
 * Open part of a disk image as a FFS/UFS file system. 
 *
 * @param img_info Disk image to analyze
 * @param offset Byte offset where file system starts
 * @param ftype Specific type of file system
 * @returns NULL on error or if data is not a FFS file system
 */
TSK_FS_INFO *
ffs_open(TSK_IMG_INFO * img_info, TSK_OFF_T offset,
    TSK_FS_INFO_TYPE_ENUM ftype)
{
    char *myname = "ffs_open";
    FFS_INFO *ffs;
    unsigned int len;
    TSK_FS_INFO *fs;
    ssize_t cnt;

    // clean up any error messages that are lying around
    tsk_error_reset();

    if ((ftype & TSK_FS_INFO_TYPE_FS_MASK) != TSK_FS_INFO_TYPE_FFS_TYPE) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_ARG;
        snprintf(tsk_errstr, TSK_ERRSTR_L, "Invalid FS Type in ffs_open");
        return NULL;
    }

    ffs = (FFS_INFO *) tsk_malloc(sizeof(*ffs));
    if (ffs == NULL)
        return NULL;
    fs = &(ffs->fs_info);

    fs->ftype = ftype;
    fs->flags = 0;
    fs->duname = "Fragment";


    fs->img_info = img_info;
    fs->offset = offset;

    /* Both sbs are the same size */
    len = roundup(sizeof(ffs_sb1), FFS_DEV_BSIZE);
    ffs->fs.sb1 = (ffs_sb1 *) tsk_malloc(len);
    if (ffs->fs.sb1 == NULL) {
        free(ffs);
        return NULL;
    }

    /* check the magic and figure out the endian ordering */

    /* Try UFS2 first - I read somewhere that some upgrades
     * kept the original UFS1 superblock in addition to 
     * the new one */
    cnt = tsk_fs_read_random
        (fs, (char *) ffs->fs.sb2, sizeof(ffs_sb2), (TSK_OFF_T) UFS2_SBOFF);
    if (cnt != sizeof(ffs_sb2)) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_FS_READ;
        }
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "%s: Superblock at %" PRIuDADDR, myname, (TSK_OFF_T) UFS2_SBOFF);
        free(ffs->fs.sb1);
        free(ffs);
        return NULL;
    }

    /* If that didn't work, try the 256KB UFS2 location */
    if (tsk_fs_guessu32(fs, ffs->fs.sb2->magic, UFS2_FS_MAGIC)) {
        cnt = tsk_fs_read_random
            (fs, (char *) ffs->fs.sb2, sizeof(ffs_sb2),
            (TSK_OFF_T) UFS2_SBOFF2);
        if (cnt != sizeof(ffs_sb2)) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_errno = TSK_ERR_FS_READ;
            }
            snprintf(tsk_errstr2, TSK_ERRSTR_L,
                "%s: Superblock at %" PRIuDADDR,
                myname, (TSK_OFF_T) UFS2_SBOFF2);
            free(ffs->fs.sb1);
            free(ffs);
            return NULL;
        }

        /* Try UFS1 if that did not work */
        if (tsk_fs_guessu32(fs, ffs->fs.sb2->magic, UFS2_FS_MAGIC)) {
            cnt = tsk_fs_read_random
                (fs, (char *) ffs->fs.sb1, len, (TSK_OFF_T) UFS1_SBOFF);
            if (cnt != len) {
                if (cnt >= 0) {
                    tsk_error_reset();
                    tsk_errno = TSK_ERR_FS_READ;
                }
                snprintf(tsk_errstr2, TSK_ERRSTR_L,
                    "%s: Superblock at %" PRIuDADDR,
                    myname, (TSK_OFF_T) UFS1_SBOFF);
                free(ffs->fs.sb1);
                free(ffs);
                return NULL;
            }
            if (tsk_fs_guessu32(fs, ffs->fs.sb1->magic, UFS1_FS_MAGIC)) {
                free(ffs->fs.sb1);
                free(ffs);
                tsk_error_reset();
                tsk_errno = TSK_ERR_FS_MAGIC;
                snprintf(tsk_errstr, TSK_ERRSTR_L, "No UFS Magic Found");
                return NULL;
            }
            else {
                // @@@ NEED TO DIFFERENTIATE BETWEEN A & B - UID/GID location in inode
                fs->ftype = TSK_FS_INFO_TYPE_FFS_1;
            }
        }
        else {
            fs->ftype = TSK_FS_INFO_TYPE_FFS_2;
        }
    }
    else {
        fs->ftype = TSK_FS_INFO_TYPE_FFS_2;
    }


    /*
     * Translate some filesystem-specific information to generic form.
     */

    if (fs->ftype == TSK_FS_INFO_TYPE_FFS_2) {
        fs->block_count = tsk_gets64(fs->endian, ffs->fs.sb2->frag_num);
        fs->block_size = tsk_gets32(fs->endian, ffs->fs.sb2->fsize_b);
        ffs->ffsbsize_b = tsk_gets32(fs->endian, ffs->fs.sb2->bsize_b);
        ffs->ffsbsize_f = tsk_gets32(fs->endian, ffs->fs.sb2->bsize_frag);
        ffs->groups_count = tsk_gets32(fs->endian, ffs->fs.sb2->cg_num);
    }
    else {
        fs->block_count = tsk_gets32(fs->endian, ffs->fs.sb1->frag_num);
        fs->block_size = tsk_gets32(fs->endian, ffs->fs.sb1->fsize_b);
        ffs->ffsbsize_b = tsk_gets32(fs->endian, ffs->fs.sb1->bsize_b);
        ffs->ffsbsize_f = tsk_gets32(fs->endian, ffs->fs.sb1->bsize_frag);
        ffs->groups_count = tsk_gets32(fs->endian, ffs->fs.sb1->cg_num);
    }



    fs->first_block = 0;
    fs->last_block = fs->last_block_act = fs->block_count - 1;
    fs->dev_bsize = FFS_DEV_BSIZE;

    // determine the last block we have in this image
    if ((TSK_DADDR_T)((img_info->size - offset) / fs->block_size) < fs->last_block)
        fs->last_block_act =
            (img_info->size - offset) / fs->block_size - 1;

    if ((fs->block_size % 512) || (ffs->ffsbsize_b % 512)) {
        free(ffs->fs.sb1);
        free(ffs);
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_MAGIC;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "Not a UFS FS (invalid fragment or block size)");
        return NULL;
    }

    if ((ffs->ffsbsize_b / fs->block_size) != ffs->ffsbsize_f) {
        free(ffs->fs.sb1);
        free(ffs);
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_MAGIC;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "Not a UFS FS (frag / block size mismatch)");
        return NULL;
    }


    if (fs->ftype == TSK_FS_INFO_TYPE_FFS_2) {
        fs->inum_count =
            ffs->groups_count * tsk_gets32(fs->endian,
            ffs->fs.sb2->cg_inode_num);
    }
    else {
        fs->inum_count =
            ffs->groups_count * tsk_gets32(fs->endian,
            ffs->fs.sb1->cg_inode_num);
    }

    fs->root_inum = FFS_ROOTINO;
    fs->first_inum = FFS_FIRSTINO;
    fs->last_inum = fs->inum_count - 1;


    /*
     * Other initialization: caches, callbacks.
     */
    ffs->grp_buf = NULL;
    ffs->grp_num = 0xffffffff;

    ffs->dino_buf = NULL;
    ffs->dino_inum = 0xffffffff;

    ffs->itbl_buf = NULL;

    fs->inode_walk = ffs_inode_walk;
    fs->block_walk = ffs_block_walk;
    fs->inode_lookup = ffs_inode_lookup;
    fs->dent_walk = ffs_dent_walk;
    fs->file_walk = ffs_file_walk;
    fs->fsstat = ffs_fsstat;
    fs->fscheck = ffs_fscheck;
    fs->istat = ffs_istat;
    fs->close = ffs_close;
    fs->jblk_walk = ffs_jblk_walk;
    fs->jentry_walk = ffs_jentry_walk;
    fs->jopen = ffs_jopen;
    fs->journ_inum = 0;

    fs->list_inum_named = NULL;

    /*
     * Print some stats.
     */
    if (tsk_verbose)
        tsk_fprintf(stderr,
            "inodes %" PRIuINUM " root ino %" PRIuINUM " cyl groups %"
            PRId32 " blocks %" PRIuDADDR "\n", fs->inum_count,
            fs->root_inum, ffs->groups_count, fs->block_count);

    return (fs);
}
