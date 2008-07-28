/*
** The Sleuth Kit
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2007 Brian Carrier.  All rights reserved.
**
** This software is subject to the IBM Public License ver. 1.0,
** which was displayed prior to download and is included in the readme.txt
** file accompanying the Sleuth Kit files.  It may also be requested from:
** Crucial Security Inc.
** 14900 Conference Center Drive
** Chantilly, VA 20151
**
** Wyatt Banks [wbanks@crucialsecurity.com]
** Copyright (c) 2005 Crucial Security Inc.  All rights reserved.
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
**
** Copyright (c) 1997,1998,1999, International Business Machines
** Corporation and others. All Rights Reserved.
*/
/* TCT
 * LICENSE
 *      This software is distributed under the IBM Public License.
 * AUTHOR(S)
 *      Wietse Venema
 *      IBM T.J. Watson Research
 *      P.O. Box 704
 *      Yorktown Heights, NY 10598, USA
 --*/
/*
** You may distribute the Sleuth Kit, or other software that incorporates
** part of all of the Sleuth Kit, in object code form under a license agreement,
** provided that:
** a) you comply with the terms and conditions of the IBM Public License
**    ver 1.0; and
** b) the license agreement
**     i) effectively disclaims on behalf of all Contributors all warranties
**        and conditions, express and implied, including warranties or 
**        conditions of title and non-infringement, and implied warranties
**        or conditions of merchantability and fitness for a particular
**        purpose.
**    ii) effectively excludes on behalf of all Contributors liability for
**        damages, including direct, indirect, special, incidental and
**        consequential damages such as lost profits.
**   iii) states that any provisions which differ from IBM Public License
**        ver. 1.0 are offered by that Contributor alone and not by any
**        other party; and
**    iv) states that the source code for the program is available from you,
**        and informs licensees how to obtain it in a reasonable manner on or
**        through a medium customarily used for software exchange.
**
** When the Sleuth Kit or other software that incorporates part or all of
** the Sleuth Kit is made available in source code form:
**     a) it must be made available under IBM Public License ver. 1.0; and
**     b) a copy of the IBM Public License ver. 1.0 must be included with 
**        each copy of the program.
*/

/**
 * \file iso9660.c
 * ISO9660 file system code to handle basic file system processing for opening
 * file system, processing sectors, and directory entries. 
 */

#include "tsk_fs_i.h"
#include "tsk_iso9660.h"
#include <ctype.h>


/* free all memory used by inode linked list */
void
iso9660_inode_list_free(TSK_FS_INFO * fs)
{
    ISO_INFO *iso = (ISO_INFO *) fs;
    if(iso->in_list) {
	    talloc_free(iso->in_list);
	    iso->in_list = NULL;
	}

	/*
    iso9660_inode_node *tmp;

    while (iso->in_list) {
        tmp = iso->in_list;
        iso->in_list = iso->in_list->next;
        free(tmp);
    }
    iso->in_list = NULL;
    */
}


/**
 * Process the System Use Sharing Protocol (SUSP) data.  Typically,
 * rockridge data are stored in this.
 *
 * @param fs File system to process
 * @param buf Buffer of data to process
 * @param count Length of buffer in bytes.
 * @param hFile File handle to print details to  (or NULL for no printing)
 * @returns NULL on error
 */
rockridge_ext *
parse_susp(void *context, TSK_FS_INFO * fs, char *buf, int count, FILE * hFile)
{
    rockridge_ext *rr;
    ISO_INFO *iso = (ISO_INFO *) fs;

    char *end = buf + count - 1;

    if (tsk_verbose)
        tsk_fprintf(stderr, "parse_susp: count is: %d\n", count);

    // allocate the output data structure
    rr = talloc(context, rockridge_ext);
    if (rr == NULL) {
        return NULL;
    }
    memset(rr, 0, sizeof(rockridge_ext));

    while (buf < end) {
        iso9660_susp_head *head = (iso9660_susp_head *) buf;

        if (((uintptr_t) & (head->len) >= (uintptr_t) end) ||
            (buf + head->len - 1 > end))
            break;

        /* Identify the entry type -- listed in the order
         * that they are listed in the specs */

        // SUSP Continuation Entry -- NOT SUPPORTED
        if ((head->sig[0] == 'C') && (head->sig[1] == 'E')) {
            iso9660_susp_ce *ce = (iso9660_susp_ce *) buf;

            if (hFile) {
                fprintf(hFile, "CE Entry\n");
                fprintf(hFile, "* Block: %" PRIu32 "\n",
                    tsk_getu32(fs->endian, ce->blk_m));
                fprintf(hFile, "* Offset: %" PRIu32 "\n",
                    tsk_getu32(fs->endian, ce->offset_m));
                fprintf(hFile, "* Len: %" PRIu32 "\n",
                    tsk_getu32(fs->endian, ce->celen_m));
            }

            if ((tsk_getu32(fs->endian, ce->blk_m) < fs->last_block) &&
                (tsk_getu32(fs->endian, ce->offset_m) < fs->block_size)) {
                ssize_t cnt;
                TSK_OFF_T off;
                char *buf2;

                off =
                    tsk_getu32(fs->endian,
                    ce->blk_m) * fs->block_size + tsk_getu32(fs->endian,
                    ce->offset_m);
                buf2 =
                    (char *) talloc_size(rr, tsk_getu32(fs->endian,
                        ce->celen_m));

                if (buf2 != NULL) {
                    cnt =
                        tsk_fs_read_random(fs, buf2,
                        tsk_getu32(fs->endian, ce->celen_m), off);
                    if (cnt == tsk_getu32(fs->endian, ce->celen_m)) {
                        parse_susp(rr, fs, buf2, (int) cnt, hFile);
                    }
                    else if (tsk_verbose) {
                        fprintf(stderr,
                            "parse_susp: error reading CE entry\n");
                        tsk_error_print(stderr);
                        tsk_error_reset();
                    }
                    talloc_free(buf2);
                }
                else {
                    if (tsk_verbose)
                        fprintf(stderr,
                            "parse_susp: error allocating memory to process CE entry\n");
                    tsk_error_reset();
                }
            }
            else {
                if (tsk_verbose)
                    fprintf(stderr,
                        "parse_susp: CE offset or block too large to process\n");
            }

            buf += head->len;
        }
        // SUSP Padding Entry
        else if ((head->sig[0] == 'P') && (head->sig[1] == 'D')) {
            if (hFile) {
                fprintf(hFile, "PD Entry\n");
            }
            buf += head->len;
        }
        // SUSP Sharing Protocol Entry -- we ignore
        else if ((head->sig[0] == 'S') && (head->sig[1] == 'P')) {
            iso9660_susp_sp *sp = (iso9660_susp_sp *) buf;
            if (hFile) {
                fprintf(hFile, "SP Entry\n");
                fprintf(hFile, "* SKip Len: %d\n", sp->skip);
            }
            buf += head->len;
        }
        // SUSP System Terminator
        else if ((head->sig[0] == 'S') && (head->sig[1] == 'T')) {
            if (hFile) {
                fprintf(hFile, "ST Entry\n");
            }
            buf += head->len;
        }
        // SUSP Extention Registration -- not used
        else if ((head->sig[0] == 'E') && (head->sig[1] == 'R')) {
            iso9660_susp_er *er = (iso9660_susp_er *) buf;
            if (hFile) {
                char buf[258];
                fprintf(hFile, "ER Entry\n");

                memcpy(buf, er->ext_id, er->len_id);
                buf[er->len_id] = '\0';
                fprintf(hFile, "* Extension ID: %s\n", buf);

                memcpy(buf, er->ext_id + er->len_id, er->len_des);
                buf[er->len_des] = '\0';
                fprintf(hFile, "* Extension Descriptor: %s\n", buf);

                memcpy(buf, er->ext_id + er->len_id + er->len_des,
                    er->len_src);
                buf[er->len_src] = '\0';
                fprintf(hFile, "* Extension Spec Source: %s\n", buf);
            }
            buf += head->len;
        }
        // SUSP Extention Sigs  -- not used
        else if ((head->sig[0] == 'E') && (head->sig[1] == 'S')) {
            if (hFile) {
                fprintf(hFile, "ES Entry\n");
            }
            buf += head->len;
        }

        /* 
         * Rock Ridge Extensions 
         */

        /* POSIX file attributes */
        else if ((head->sig[0] == 'P') && (head->sig[1] == 'X')) {
            iso9660_rr_px_entry *rr_px;
            rr_px = (iso9660_rr_px_entry *) buf;
            rr->uid = tsk_getu32(fs->endian, rr_px->uid_m);
            rr->gid = tsk_getu32(fs->endian, rr_px->gid_m);
            rr->mode = tsk_getu16(fs->endian, rr_px->mode_m);
            rr->nlink = tsk_getu32(fs->endian, rr_px->links_m);
            if (hFile) {
                fprintf(hFile, "PX Entry\n");
                fprintf(hFile, "* UID: %"PRIuUID"\n", rr->uid);
                fprintf(hFile, "* GID: %"PRIuGID"\n", rr->gid);
                fprintf(hFile, "* Mode: %d\n", rr->mode);
                fprintf(hFile, "* Links: %"PRIu32"\n", rr->nlink);
            }
            buf += head->len;
        }

        // RR - device information 
        else if ((head->sig[0] == 'P') && (head->sig[1] == 'N')) {
            iso9660_rr_pn_entry *rr_pn = (iso9660_rr_pn_entry *) buf;
            if (hFile) {
                fprintf(hFile, "PN Entry\n");
                fprintf(hFile, "* Device ID High: %"PRIu32"\n",
                    tsk_getu32(fs->endian, rr_pn->dev_h_m));
                fprintf(hFile, "* Device ID Low: %"PRIu32"\n",
                    tsk_getu32(fs->endian, rr_pn->dev_l_m));
            }
            buf += head->len;
        }

        // RR - symbolic link
        else if ((head->sig[0] == 'S') && (head->sig[1] == 'L')) {
            //iso9660_rr_sl_entry *rr_sl = (iso9660_rr_sl_entry *) buf;
            if (hFile) {
                fprintf(hFile, "SL Entry\n");
            }
            buf += head->len;
        }
        // RR -- alternative name
        else if ((head->sig[0] == 'N') && (head->sig[1] == 'M')) {
            iso9660_rr_nm_entry *rr_nm;
            rr_nm = (iso9660_rr_nm_entry *) buf;
            strncpy(rr->fn, &rr_nm->name[0], (int) rr_nm->len - 5);
            rr->fn[(int) rr_nm->len - 5] = '\0';
            if (hFile) {
                fprintf(hFile, "NM Entry\n");
                fprintf(hFile, "* %s\n", rr->fn);
            }
            buf += head->len;
        }
        // RR - relocated directory
        else if ((head->sig[0] == 'C') && (head->sig[1] == 'L')) {
            if (hFile) {
                fprintf(hFile, "CL Entry\n");
            }
            buf += head->len;
        }
        // RR - parent of relocated directory
        else if ((head->sig[0] == 'P') && (head->sig[1] == 'L')) {
            if (hFile) {
                fprintf(hFile, "PL Entry\n");
            }
            buf += head->len;
        }
        // RR - relocation signal
        else if ((head->sig[0] == 'R') && (head->sig[1] == 'E')) {
            if (hFile) {
                fprintf(hFile, "RE Entry\n");
            }
            buf += head->len;
        }
        // RR - time stamps
        else if ((head->sig[0] == 'T') && (head->sig[1] == 'F')) {
            if (hFile) {
                fprintf(hFile, "TF Entry\n");
            }
            buf += head->len;
        }
        // RR - sparse file
        else if ((head->sig[0] == 'S') && (head->sig[1] == 'F')) {
            if (hFile) {
                fprintf(hFile, "SF Entry\n");
            }
            buf += head->len;
        }

        /* RR is a system use field indicating RockRidge, but not part of RockRidge */
        else if ((head->sig[0] == 'R') && (head->sig[1] == 'R')) {
            iso->rr_found = 1;
            if (hFile) {
                fprintf(hFile, "RR Entry\n");
            }
            buf += head->len;
        }

        else {
            buf += 2;
            if ((uintptr_t) buf % 2)
                buf--;
        }
    }

    return rr;
}

/* get directory entries from current directory and add them to the inode list.
 * Type: ISO9660_TYPE_PVD for primary volume descriptor, ISO9660_TYPE_SVD for
 * supplementary volume descriptor (do Joliet utf-8 conversion).
 *
 * @param fs File system to analyze
 * @param a_offs Byte offset of directory start
 * @param count previous file count
 * @param ctype Character set used for the names
 * @param a_fn Name of the directory  (in UTF-8)
 *
 * @returns total number of files or -1 on error
 */

int
iso9660_load_inodes_dir(TSK_FS_INFO * fs, TSK_OFF_T a_offs, int count,
    int ctype, char *a_fn)
{
    ISO_INFO *iso = (ISO_INFO *) fs;
    int s_cnt = 1;              // count of sectors needed for dir
    TSK_OFF_T s_offs = a_offs;      // offset for sector reads
    int i;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "iso9660_load_inodes_dir: fs: %lu offs: %"PRIuOFF
            " count: %d ctype: %d fn: %s\n",
            (uintptr_t) fs, a_offs, count, ctype, a_fn);

    // cycle through each sector -- entries will not cross them
    for (i = 0; i < s_cnt; i++) {
        ssize_t cnt1;
        int b_offs;             // offset in buffer
        char buf[ISO9660_SSIZE_B];

        cnt1 = tsk_fs_read_random(fs, buf, ISO9660_SSIZE_B, s_offs);
        if (cnt1 != ISO9660_SSIZE_B) {
            if (cnt1 >= 0) {
                tsk_error_reset();
                tsk_errno = TSK_ERR_FS_READ;
            }
            snprintf(tsk_errstr2, TSK_ERRSTR_L, "iso_get_dentries");
            return -1;
        }

        // @@@@ We  need to add more checks when reading from buf to make sure b_off is still in the buffer 
        /* process the directory entries */
        for (b_offs = 0; b_offs < ISO9660_SSIZE_B;) {
            iso9660_inode_node *in_node;
            iso9660_dentry *dentry;

            dentry = (iso9660_dentry *) & buf[b_offs];

            if (dentry->entry_len == 0) {
                b_offs += 2;
                continue;
            }
            b_offs += sizeof(iso9660_dentry);

            // allocate a node for this entry
            if(iso->in_list)
                in_node = talloc(iso->in_list, iso9660_inode_node);
            else
            	in_node = talloc(iso, iso9660_inode_node);

            if (in_node == NULL) {
                return -1;
            }

	    memset(in_node, 0 , sizeof(iso9660_inode_node));

            // the first entry should have no name and is for the current directory
            if ((i == 0) && (b_offs == sizeof(iso9660_dentry))) {
                if (dentry->fi_len != 0) {
                    // XXX
                }

                /* find how many more sectors are in the directory */
                s_cnt =
                    tsk_getu32(fs->endian,
                    dentry->data_len_m) / ISO9660_SSIZE_B;

                /* use the specified name instead of "." */
                if (strlen(a_fn) > ISO9660_MAXNAMLEN_STD) {
                    tsk_error_reset();
                    tsk_errno = TSK_ERR_FS_ARG;
                    snprintf(tsk_errstr, TSK_ERRSTR_L,
                        "iso9660_load_inodes_dir: Name argument specified is too long");
                    return -1;
                }
                strncpy(in_node->inode.fn, a_fn,
                    ISO9660_MAXNAMLEN_STD + 1);

                if (sizeof(iso9660_dentry) % 2)
                    b_offs++;
            }
            else {
                char *file_ver;

                // the entry has a UTF-16 name
                if (ctype == ISO9660_CTYPE_UTF16) {
                    UTF16 *name16;
                    UTF8 *name8;
                    int retVal;

                    name16 = (UTF16 *) & buf[b_offs];
                    // the name is in UTF-16 BE -- convert to LE if needed
                    if (fs->endian & TSK_LIT_ENDIAN) {
                        int a;

                        for (a = 0; a < dentry->fi_len / 2; a++) {
                            name16[i] = ((name16[i] & 0xff) << 8) +
                                ((name16[i] & 0xff00) >> 8);
                        }
                    }
                    name8 = (UTF8 *) in_node->inode.fn;

                    retVal =
                        tsk_UTF16toUTF8(fs->endian,
                        (const UTF16 **) &name16,
                        (UTF16 *) & buf[b_offs + dentry->fi_len], &name8,
                        (UTF8 *) ((uintptr_t) & in_node->inode.
                            fn[ISO9660_MAXNAMLEN_STD]),
                        TSKlenientConversion);
                    if (retVal != TSKconversionOK) {
                        if (tsk_verbose)
                            tsk_fprintf(stderr,
                                "iso9660_load_inodes_dir: Error converting Joliet name to UTF8: %d",
                                retVal);
                        in_node->inode.fn[0] = '\0';
                    }
                    *name8 = '\0';
                }

                else if (ctype == ISO9660_CTYPE_ASCII) {
                    int readlen;

                    readlen = dentry->fi_len;
                    if (readlen > ISO9660_MAXNAMLEN_STD)
                        readlen = ISO9660_MAXNAMLEN_STD;

                    memcpy(in_node->inode.fn, &buf[b_offs], readlen);
                    in_node->inode.fn[readlen] = '\0';
                }
                else {
                    tsk_error_reset();
                    tsk_errno = TSK_ERR_FS_ARG;
                    snprintf(tsk_errstr, TSK_ERRSTR_L,
                        "Invalid ctype in iso9660_load_inodes_dir");
                    return -1;
                }

                // the version is embedded in the name
                file_ver = strchr(in_node->inode.fn, ';');
                if (file_ver) {
                    in_node->inode.version = atoi(file_ver + 1);
                    *file_ver = '\0';
                    file_ver = NULL;
                }

                // if no extension, remove the final '.'
                if (in_node->inode.fn[strlen(in_node->inode.fn) - 1] ==
                    '.')
                    in_node->inode.fn[strlen(in_node->inode.fn) - 1] =
                        '\0';

                /* skip past padding byte */
                b_offs += dentry->fi_len;
                if (!(dentry->fi_len % 2)) {
                    b_offs++;
                }
            }

            // copy the raw dentry data into the node
            memcpy(&(in_node->inode.dr), dentry, sizeof(iso9660_dentry));

            in_node->inode.ea = NULL;
            in_node->offset =
                tsk_getu32(fs->endian, dentry->ext_loc_m) * fs->block_size;
            in_node->ea_size = dentry->ext_len;

            /* record size to make sure fifos show up as unique files */
            in_node->size =
                tsk_getu32(fs->endian, in_node->inode.dr.data_len_m);
            in_node->inum = count++;

            /* RockRidge data is located after the name.  See if it is there.  */
            if ((int) (dentry->entry_len - sizeof(iso9660_dentry) -
                    dentry->fi_len) > 1) {
                int extra_bytes =
                    dentry->entry_len - sizeof(iso9660_dentry) -
                    dentry->fi_len;
                // this takes care of the length adjustment that we already did
                // on offs
                if (extra_bytes % 2)
                    extra_bytes--;

                in_node->inode.rr =
                    parse_susp(in_node, fs, &buf[b_offs], extra_bytes, NULL);
                in_node->inode.susp_off = b_offs + s_offs;
                in_node->inode.susp_len = extra_bytes;

                if (in_node->inode.rr == NULL) {
                    // return -1;
                    // @@@ Verbose error
                }
                b_offs += extra_bytes;
            }
            else {
                in_node->inode.susp_off = 0;
                in_node->inode.susp_len = 0;
            }


            /* add inode to the list */
            /* list not empty */
            if (iso->in_list) {
                iso9660_inode_node *tmp;
                tmp = iso->in_list;
                while ((tmp->next)
                    && ((in_node->offset != tmp->offset)
                        || (!in_node->size)
                        || (!tmp->size)))
                    tmp = tmp->next;

                /* see if the file is already in list */
                if ((in_node->offset == tmp->offset) && (in_node->size)
                    && (tmp->size)) {
                    if ((in_node->inode.rr) && (!tmp->inode.rr)) {
                        tmp->inode.rr = in_node->inode.rr;
                        in_node->inode.rr = NULL;
                    }
                    if (in_node->inode.rr)
                        talloc_free(in_node->inode.rr);

                    talloc_free(in_node);
                    count--;

                }
                /* file wasn't in list, add it */
                else {
                    tmp->next = in_node;
                    in_node->next = NULL;
                }

                /* list is empty */
            }
            else {
                iso->in_list = in_node;
                in_node->next = NULL;
            }
        }
        s_offs += cnt1;
    }

    return count;
}


/**
 * Process the path table for a joliet secondary volume descriptor.
 * This will load each
 * of the directories in the table pointed to by he SVD.
 *
 * @param fs File system to process
 * @param svd Pointer to the secondary volume descriptor
 * @param count Current count of inodes
 * @returns updated count of inodes or -1 on error
 */
static int
iso9660_load_inodes_pt_joliet(TSK_FS_INFO * fs, iso9660_svd * svd,
    int count)
{
    TSK_OFF_T pt_offs;              /* offset of where we are in path table */
    size_t pt_len;             /* bytes left in path table */

    // get the location of the path table
    pt_offs =
        (TSK_OFF_T) (tsk_getu32(fs->endian, svd->pt_loc_m) * fs->block_size);
    pt_len = tsk_getu32(fs->endian, svd->pt_size_m);

    while (pt_len > 0) {
        char utf16_buf[ISO9660_MAXNAMLEN_JOL + 1];      // UTF-16 name from img
        char utf8buf[2 * ISO9660_MAXNAMLEN_JOL + 1];    // UTF-8 version of name
        int readlen;
        TSK_OFF_T extent;           /* offset of extent for current directory */
        path_table_rec dir;
        int retVal;
        ssize_t cnt;

        UTF16 *name16;
        UTF8 *name8;

        // read the next entry
        cnt =
            tsk_fs_read_random(fs, (char *) &dir, (int) sizeof(dir),
            pt_offs);
        if (cnt != sizeof(dir)) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_errno = TSK_ERR_FS_READ;
            }
            snprintf(tsk_errstr2, TSK_ERRSTR_L, "iso9660_load_inodes_pt");
            return -1;
        }
        pt_len -= cnt;
        pt_offs += (TSK_OFF_T) cnt;

        readlen = dir.len_di;
        if (dir.len_di > ISO9660_MAXNAMLEN_JOL)
            readlen = ISO9660_MAXNAMLEN_JOL;

        /* get UCS-2 filename for the entry */
        cnt = tsk_fs_read_random(fs, (char *) utf16_buf, readlen, pt_offs);
        if (cnt != dir.len_di) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_errno = TSK_ERR_FS_READ;
            }
            snprintf(tsk_errstr2, TSK_ERRSTR_L, "iso_find_inodes");
            return -1;
        }
        pt_len -= cnt;
        pt_offs += (TSK_OFF_T) cnt;

        // ISO stores UTF-16 in BE -- convert to local if we need to
        if (fs->endian & TSK_LIT_ENDIAN) {
            int i;
            for (i = 0; i < cnt; i += 2) {
                char t = utf16_buf[i];
                utf16_buf[i] = utf16_buf[i + 1];
                utf16_buf[i] = t;
            }
        }

        name16 = (UTF16 *) utf16_buf;
        name8 = (UTF8 *) utf8buf;

        retVal = tsk_UTF16toUTF8(fs->endian, (const UTF16 **) &name16,
            (UTF16 *) ((uintptr_t) & utf16_buf[cnt + 1]), &name8,
            (UTF8 *) ((uintptr_t) & utf8buf[2 * ISO9660_MAXNAMLEN_JOL]),
            TSKlenientConversion);
        if (retVal != TSKconversionOK) {
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "fsstat: Error converting Joliet name to UTF8: %d",
                    retVal);
            utf8buf[0] = '\0';
        }
        *name8 = '\0';

        /* padding byte is there if strlen(file name) is odd */
        if (dir.len_di % 2) {
            pt_len--;
            pt_offs++;
        }

        extent =
            (TSK_OFF_T) (tsk_getu32(fs->endian, dir.ext_loc) * fs->block_size);

        count =
            iso9660_load_inodes_dir(fs, extent, count,
            ISO9660_CTYPE_UTF16, utf8buf);

        if (count == -1) {
            return -1;
        }
    }
    return count;
}

/**
 * Proces the path table and identify the directories that are listed.  The contents of each directory will also
 * be processed.  The result will be that the list of inodes in the image will be loaded in ISO_INFO.
 *
 * @param iso File system to analyze and store results in
 * @returns -1 on error or count of inodes found.
 */
static int
iso9660_load_inodes_pt(ISO_INFO * iso)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & iso->fs_info;
    int count = 0;
    iso9660_svd_node *s;
    iso9660_pvd_node *p;
    char fn[ISO9660_MAXNAMLEN_STD + 1]; /* store current directory name */
    path_table_rec dir;
    TSK_OFF_T pt_offs;              /* offset of where we are in path table */
    size_t pt_len;             /* bytes left in path table */
    TSK_OFF_T extent;               /* offset of extent for current directory */
    ssize_t cnt;

    if (tsk_verbose)
        tsk_fprintf(stderr, "iso9660_load_inodes_pt: iso: %lu\n",
            (uintptr_t) iso);

    /* initialize in case repeatedly called */
    iso9660_inode_list_free(fs);
    iso->in_list = NULL;

    /* The secondary volume descriptor table will contain the
     * longer / unicode files, so we process it first to give them
     * a higher priority */
    for (s = iso->svd; s != NULL; s = s->next) {

        /* Check if this is Joliet -- there are three possible signatures */
        if ((s->svd.esc_seq[0] == 0x25) && (s->svd.esc_seq[1] == 0x2F) &&
            ((s->svd.esc_seq[2] == 0x40) || (s->svd.esc_seq[2] == 0x43)
                || (s->svd.esc_seq[2] == 0x45))) {
            count = iso9660_load_inodes_pt_joliet(fs, &(s->svd), count);
            if (count == -1) {
                return -1;
            }
        }
    }


    /* Now look for unique files in the primary descriptors */
    for (p = iso->pvd; p != NULL; p = p->next) {

        pt_offs =
            (TSK_OFF_T) (tsk_getu32(fs->endian,
                p->pvd.pt_loc_m) * fs->block_size);
        pt_len = tsk_getu32(fs->endian, p->pvd.pt_size_m);

        while (pt_len > 0) {
            int readlen;

            /* get next dir... */
            cnt =
                tsk_fs_read_random(fs, (char *) &dir, sizeof(dir),
                pt_offs);
            if (cnt != sizeof(dir)) {
                if (cnt >= 0) {
                    tsk_error_reset();
                    tsk_errno = TSK_ERR_FS_READ;
                }
                snprintf(tsk_errstr2, TSK_ERRSTR_L, "iso_find_inodes");
                return -1;
            }
            pt_len -= cnt;
            pt_offs += (TSK_OFF_T) cnt;

            readlen = dir.len_di;
            if (readlen > ISO9660_MAXNAMLEN_STD)
                readlen = ISO9660_MAXNAMLEN_STD;

            /* get directory name, this is the only chance */
            cnt = tsk_fs_read_random(fs, fn, readlen, pt_offs);
            if (cnt != readlen) {
                if (cnt >= 0) {
                    tsk_error_reset();
                    tsk_errno = TSK_ERR_FS_READ;
                }
                snprintf(tsk_errstr2, TSK_ERRSTR_L, "iso_find_inodes");
                return -1;
            }
            fn[cnt] = '\0';

            pt_len -= cnt;
            pt_offs += (TSK_OFF_T) cnt;

            /* padding byte is there if strlen(file name) is odd */
            if (dir.len_di % 2) {
                pt_len--;
                pt_offs++;
            }

            extent =
                (TSK_OFF_T) (tsk_getu32(fs->endian,
                    dir.ext_loc) * fs->block_size);

            count =
                iso9660_load_inodes_dir(fs, extent, count,
                ISO9660_CTYPE_ASCII, fn);

            if (count == -1) {
                return -1;
            }
        }
    }
    return count;
}

/** 
 * Load the raw "inode" into the cached buffer (iso->dinode)
 *
 * dinode_load (for now) does not check for extended attribute records...
 * my issue is I dont have an iso9660 image with extended attr recs, so I
 * can't test/debug, etc
 *
 * @returns 1 if not found and 0 on succuss
 */
uint8_t
iso9660_dinode_load(ISO_INFO * iso, TSK_INUM_T inum)
{
    iso9660_inode_node *n;

    if (tsk_verbose)
        tsk_fprintf(stderr, "iso9660_dinode_load: iso: %lu"
            " inum: %" PRIuINUM "\n", (uintptr_t) iso, inum);

    n = iso->in_list;
    while (n && (n->inum != inum))
        n = n->next;

    if (n) {
        memcpy(iso->dinode, &n->inode, sizeof(iso9660_inode));
        iso->dinum = inum;
        return 0;
    }
    else {
        return 1;
    }
}

/**
 * Copies cached disk inode into generic structure. 
 *
 */
static void
iso9660_dinode_copy(ISO_INFO * iso, TSK_FS_INODE * fs_inode)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & iso->fs_info;
    struct tm t;
    memset(&t, 0, sizeof(t));

    if (tsk_verbose)
        tsk_fprintf(stderr, "iso9660_dinode_copy: iso: %lu"
            " inode: %lu\n", (uintptr_t) iso, (uintptr_t) fs_inode);

    fs_inode->addr = iso->dinum;
    fs_inode->size = tsk_getu32(fs->endian, iso->dinode->dr.data_len_m);

    t.tm_sec = iso->dinode->dr.rec_time.sec;
    t.tm_min = iso->dinode->dr.rec_time.min;
    t.tm_hour = iso->dinode->dr.rec_time.hour;
    t.tm_mday = iso->dinode->dr.rec_time.day;
    t.tm_mon = iso->dinode->dr.rec_time.month - 1;
    t.tm_year = iso->dinode->dr.rec_time.year;

    fs_inode->mtime = fs_inode->atime = fs_inode->ctime = mktime(&t);

    if (iso->dinode->ea) {
        fs_inode->uid = tsk_getu32(fs->endian, iso->dinode->ea->uid);
        fs_inode->gid = tsk_getu32(fs->endian, iso->dinode->ea->gid);
        fs_inode->mode = tsk_getu16(fs->endian, iso->dinode->ea->mode);
        fs_inode->nlink = 1;
    }
    else {
        if (iso->dinode->dr.flags & ISO9660_FLAG_DIR)
            fs_inode->mode = TSK_FS_INODE_MODE_DIR;
        else
            fs_inode->mode = TSK_FS_INODE_MODE_REG;

        fs_inode->nlink = 1;
        fs_inode->uid = 0;
        fs_inode->gid = 0;
    }


    fs_inode->direct_addr[0] =
        (TSK_DADDR_T) tsk_getu32(fs->endian, iso->dinode->dr.ext_loc_m);

    fs_inode->flags = TSK_FS_INODE_FLAG_ALLOC;
}

static TSK_FS_INODE *
iso9660_inode_lookup(TSK_FS_INFO * fs, TSK_INUM_T inum)
{
    ISO_INFO *iso = (ISO_INFO *) fs;
    TSK_FS_INODE *fs_inode;

    // clean up any error messages that are lying around
    tsk_error_reset();

    if ((fs_inode =
            tsk_fs_inode_alloc(ISO9660_NDADDR, ISO9660_NIADDR)) == NULL)
        return NULL;

    if (tsk_verbose)
        tsk_fprintf(stderr, "iso9660_inode_lookup: iso: %lu"
            " inum: %" PRIuINUM "\n", (uintptr_t) iso, inum);

    if (iso9660_dinode_load(iso, inum)) {
        tsk_fs_inode_free(fs_inode);
        return NULL;
    }

    iso9660_dinode_copy(iso, fs_inode);

    return fs_inode;
}

uint8_t
iso9660_inode_walk(TSK_FS_INFO * fs, TSK_INUM_T start, TSK_INUM_T last,
    TSK_FS_INODE_FLAG_ENUM flags, TSK_FS_INODE_WALK_CB action, void *ptr)
{
    char *myname = "iso9660_inode_walk";
    ISO_INFO *iso = (ISO_INFO *) fs;
    TSK_INUM_T inum;
    TSK_FS_INODE *fs_inode;
    int myflags;

    // clean up any error messages that are lying around
    tsk_error_reset();

    if ((fs_inode =
            tsk_fs_inode_alloc(ISO9660_NDADDR, ISO9660_NIADDR)) == NULL)
        return 1;

    if (tsk_verbose)
        tsk_fprintf(stderr, "iso9660_inode_walk: iso: %lu"
            " start: %" PRIuINUM " last: %" PRIuINUM " flags: %d"
            " action: %lu ptr: %lu\n",
            (uintptr_t) fs, start, last, flags, (uintptr_t) action,
            (uintptr_t) ptr);

    myflags = TSK_FS_INODE_FLAG_ALLOC;

    /*
     * Sanity checks.
     */
    if (start < fs->first_inum || start > fs->last_inum) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_WALK_RNG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "%s: Start inode:  %" PRIuINUM "", myname, start);
        return 1;
    }
    if (last < fs->first_inum || last > fs->last_inum || last < start) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_WALK_RNG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "%s: End inode: %" PRIuINUM "", myname, last);
        return 1;
    }

    if (flags & TSK_FS_INODE_FLAG_ORPHAN) {
        return 0;
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



    /*
     * Iterate.
     */
    for (inum = start; inum <= last; inum++) {
        int retval;
        if (iso9660_dinode_load(iso, inum)) {
            tsk_fs_inode_free(fs_inode);
            return 1;
        }

        if ((flags & myflags) != myflags)
            continue;

        iso9660_dinode_copy(iso, fs_inode);

        retval = action(fs, fs_inode, ptr);
        if (retval == TSK_WALK_ERROR) {
            tsk_fs_inode_free(fs_inode);
            return 1;
        }
        else if (retval == TSK_WALK_STOP) {
            break;
        }
    }

    /*
     * Cleanup.
     */
    tsk_fs_inode_free(fs_inode);
    return 0;
}

// @@@ Doesn' thit seem to ignore interleave?
/* return 1 if block is allocated in a file's extent, return 0 otherwise */
static int
iso9660_is_block_alloc(TSK_FS_INFO * fs, TSK_DADDR_T blk_num)
{
    ISO_INFO *iso = (ISO_INFO *) fs;
    iso9660_inode_node *in_node;

    if (tsk_verbose)
        tsk_fprintf(stderr, "iso9660_is_block_alloc: fs: %lu"
            " blk_num: %" PRIuDADDR "\n", (uintptr_t) fs, blk_num);

    for (in_node = iso->in_list; in_node; in_node = in_node->next) {
        TSK_DADDR_T first_block = in_node->offset / fs->block_size;
        TSK_DADDR_T file_size =
            tsk_getu32(fs->endian, in_node->inode.dr.data_len_m);
        TSK_DADDR_T last_block = first_block + (file_size / fs->block_size);
        if (file_size % fs->block_size)
            last_block++;

        if ((blk_num >= first_block) && (blk_num <= last_block))
            return 1;
    }

    return 0;
}

/* flags: TSK_FS_BLOCK_FLAG_ALLOC and FS_FLAG_UNALLOC
 * ISO9660 has a LOT of very sparse meta, so in this function a block is only
 * checked to see if it is part of an inode's extent
 */
uint8_t
iso9660_block_walk(TSK_FS_INFO * fs, TSK_DADDR_T start, TSK_DADDR_T last,
    TSK_FS_BLOCK_FLAG_ENUM flags, TSK_FS_BLOCK_WALK_CB action, void *ptr)
{
    char *myname = "iso9660_block_walk";
    TSK_DATA_BUF *data_buf;
    TSK_DADDR_T addr;
    int myflags = 0;
    ssize_t cnt;

    // clean up any error messages that are lying around
    tsk_error_reset();

    if (tsk_verbose)
        tsk_fprintf(stderr, "iso9660_block_walk: fs: %lu"
            " start: %" PRIuDADDR " last: %" PRIuDADDR " flags: %d"
            " action: %lu ptr: %lu\n",
            (uintptr_t) fs, start, last, flags, (uintptr_t) action,
            (uintptr_t) ptr);

    /*
     * Sanity checks.
     */
    if (start < fs->first_block || start > fs->last_block) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_WALK_RNG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "%s: Start block: %" PRIuDADDR "", myname, start);
        return 1;
    }
    if (last < fs->first_block || last > fs->last_block) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_WALK_RNG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "%s: End block: %" PRIuDADDR "", myname, last);
        return 1;
    }

    /* Sanity check on flags -- make sure at least one ALLOC is set */
    if (((flags & TSK_FS_BLOCK_FLAG_ALLOC) == 0) &&
        ((flags & TSK_FS_BLOCK_FLAG_UNALLOC) == 0)) {
        flags |= (TSK_FS_BLOCK_FLAG_ALLOC | TSK_FS_BLOCK_FLAG_UNALLOC);
    }


    if ((data_buf = tsk_data_buf_alloc(fs, fs->block_size)) == NULL) {
        return 1;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "isofs_block_walk: Block Walking %"PRIuDADDR" to %"PRIuDADDR"\n",
            start, last);

    /* cycle through block addresses */
    for (addr = start; addr <= last; addr++) {
        myflags = (iso9660_is_block_alloc(fs, addr)) ?
            TSK_FS_BLOCK_FLAG_ALLOC : TSK_FS_BLOCK_FLAG_UNALLOC;

        if ((flags & myflags) == myflags) {
            int retval;
            cnt = tsk_fs_read_block(fs, data_buf, fs->block_size, addr);
            if (cnt != fs->block_size) {
                if (cnt >= 0) {
                    tsk_error_reset();
                    tsk_errno = TSK_ERR_FS_READ;
                }
                snprintf(tsk_errstr2, TSK_ERRSTR_L, "iso_block_walk");
                return 1;
            }

            retval = action(fs, addr, data_buf->data, myflags, ptr);
            if (retval == TSK_WALK_ERROR) {
                tsk_data_buf_free(data_buf);
                return 1;
            }
            else if (retval == TSK_WALK_STOP) {
                break;
            }
        }
    }

    tsk_data_buf_free(data_buf);
    return 0;
}

/**************************************************************************
 *
 * FILE WALKING
 *
 *************************************************************************/
/**
 * Calls a callback function with the contents of each block in a file. 
 * Note that if an extended attribute exists, the first block in the 
 * callback will not be a full size. 
 *
 * @param fs File system file is located in
 * @param inode File to read and analyze
 * @param type Attribute type to read and analyze (does not apply to ISO9660)
 * @param id Attribute id to read and analyze (does not apply to ISO9660)
 * @param flags Flags to use while reading
 * @param action Callback function that is called for each block
 * @param ptr Pointer to data that is passed to the callback
 * @returns 1 on error and 0 on success
 */
uint8_t
iso9660_file_walk(TSK_FS_INFO * fs, TSK_FS_INODE * inode, uint32_t type,
    uint16_t id, TSK_FS_FILE_FLAG_ENUM flags,
    TSK_FS_FILE_WALK_CB action, void *ptr)
{
    char *data_buf;
    size_t length, size;
    int myflags;
    TSK_OFF_T offs;
    size_t bytes_read;
    TSK_DADDR_T addr;
    ISO_INFO *iso = (ISO_INFO *) fs;
    iso9660_dentry dd;

    // clean up any error messages that are lying around
    tsk_error_reset();

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "iso9660_file_walk: inode: %" PRIuINUM " type: %" PRIu32
            " id: %" PRIu16 " flags: %X\n", inode->addr, type, id, flags);


    if (iso9660_dinode_load(iso, inode->addr)) {
        snprintf(tsk_errstr2, TSK_ERRSTR_L, "iso9660_file_walk");
        return 1;
    }
    memcpy(&dd, &iso->dinode->dr, sizeof(iso9660_dentry));

    if (dd.gap_sz) {
        tsk_errno = TSK_ERR_FS_FUNC;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "file %" PRIuINUM " has an interleave gap -- not supported",
            inode->addr);
        return 1;
    }

    myflags = TSK_FS_BLOCK_FLAG_CONT;

    data_buf = talloc_size(inode, fs->block_size);
    if (data_buf == NULL) {
        return 1;
    };

    /* Determine how much data we need to copy */
    if (flags & TSK_FS_FILE_FLAG_SLACK)
        length = roundup((size_t) inode->size, fs->block_size);
    else
        // we do not return the extended attribute, but we do read it
        length = (size_t) inode->size + dd.ext_len;

    /* Get start of extent */
    addr = inode->direct_addr[0];
    offs = fs->block_size * addr;

    while (length > 0) {
        int retval;

        if (length >= fs->block_size)
            size = fs->block_size;
        else
            size = length;

        if ((flags & TSK_FS_FILE_FLAG_AONLY) == 0) {
            bytes_read = tsk_fs_read_random(fs, data_buf, size, offs);
            if (bytes_read != size) {
                if (bytes_read != -1) {
                    tsk_error_reset();
                    tsk_errno = TSK_ERR_FS_READ;
                }
                snprintf(tsk_errstr2, TSK_ERRSTR_L,
                    "iso9660_file_walk: Error reading block: %"
                    PRIuDADDR, offs);
                return 1;
            }
        }
        else {
            bytes_read = size;
        }
        offs += bytes_read;

        // for the first block in the file, skip the extended attribute 
        if (addr == inode->direct_addr[0])
            retval = action(fs, addr, &data_buf[dd.ext_len],
                size - dd.ext_len, myflags, ptr);
        else
            retval = action(fs, addr, data_buf, size, myflags, ptr);

        if (retval == TSK_WALK_ERROR) {
            talloc_free(data_buf);
            return 1;
        }
        else if (retval == TSK_WALK_STOP) {
            break;
        }
        addr++;
        length -= bytes_read;
    }
    talloc_free(data_buf);
    return 0;
}


static uint8_t
iso9660_fscheck(TSK_FS_INFO * fs, FILE * hFile)
{
    tsk_error_reset();
    tsk_errno = TSK_ERR_FS_FUNC;
    snprintf(tsk_errstr, TSK_ERRSTR_L,
        "fscheck not implemented for iso9660 yet");
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
iso9660_fsstat(TSK_FS_INFO * fs, FILE * hFile)
{
    char str[129];              /* store name of publisher/preparer/etc */
    ISO_INFO *iso = (ISO_INFO *) fs;
    char *cp;
    int i;

    iso9660_pvd_node *p = iso->pvd;
    iso9660_svd_node *s;

    // clean up any error messages that are lying around
    tsk_error_reset();

    if (tsk_verbose)
        tsk_fprintf(stderr, "iso9660_fsstat: fs: %lu \
			hFile: %lu\n", (uintptr_t) fs, (uintptr_t) hFile);

    i = 0;

    for (p = iso->pvd; p != NULL; p = p->next) {
        i++;
        tsk_fprintf(hFile, "\nPRIMARY VOLUME DESCRIPTOR %d\n", i);
        tsk_fprintf(hFile, "\nFILE SYSTEM INFORMATION\n");
        tsk_fprintf(hFile,
            "--------------------------------------------\n");
        tsk_fprintf(hFile, "Read from Primary Volume Descriptor\n");
        tsk_fprintf(hFile, "File System Type: ISO9660\n");
        tsk_fprintf(hFile, "Volume Name: %s\n", p->pvd.vol_id);
        tsk_fprintf(hFile, "Volume Set Size: %d\n",
            tsk_getu16(fs->endian, p->pvd.vol_set_m));
        tsk_fprintf(hFile, "Volume Set Sequence: %d\n",
            tsk_getu16(fs->endian, p->pvd.vol_seq_m));

        /* print publisher */
        if (p->pvd.pub_id[0] == 0x5f)
            /* publisher is in a file.  TODO: handle this properly */
            snprintf(str, 8, "In file\n");
        else
            snprintf(str, 128, "%s", p->pvd.pub_id);

        cp = &str[127];
        /* find last printable non space character */
        while ((!isprint(*cp) || isspace(*cp)) && (cp != str))
            cp--;
        *++cp = '\0';
        tsk_fprintf(hFile, "Publisher: %s\n", str);
        memset(str, ' ', 128);


        /* print data preparer */
        if (p->pvd.prep_id[0] == 0x5f)
            /* preparer is in a file.  TODO: handle this properly */
            snprintf(str, 8, "In file\n");
        else
            snprintf(str, 128, "%s", p->pvd.prep_id);

        cp = &str[127];
        while ((!isprint(*cp) || isspace(*cp)) && (cp != str))
            cp--;
        *++cp = '\0';
        tsk_fprintf(hFile, "Data Preparer: %s\n", str);
        memset(str, ' ', 128);


        /* print recording application */
        if (p->pvd.app_id[0] == 0x5f)
            /* application is in a file.  TODO: handle this properly */
            snprintf(str, 8, "In file\n");
        else
            snprintf(str, 128, "%s", p->pvd.app_id);
        cp = &str[127];
        while ((!isprint(*cp) || isspace(*cp)) && (cp != str))
            cp--;
        *++cp = '\0';
        tsk_fprintf(hFile, "Recording Application: %s\n", str);
        memset(str, ' ', 128);


        /* print copyright */
        if (p->pvd.copy_id[0] == 0x5f)
            /* copyright is in a file.  TODO: handle this properly */
            snprintf(str, 8, "In file\n");
        else
            snprintf(str, 37, "%s", p->pvd.copy_id);
        cp = &str[36];
        while ((!isprint(*cp) || isspace(*cp)) && (cp != str))
            cp--;
        *++cp = '\0';
        tsk_fprintf(hFile, "Copyright: %s\n", str);
        memset(str, ' ', 37);

        tsk_fprintf(hFile, "\nMETADATA INFORMATION\n");
        tsk_fprintf(hFile,
            "--------------------------------------------\n");
        tsk_fprintf(hFile,
            "Path Table Location: %" PRIu32 "-%" PRIu32 "\n",
            tsk_getu32(fs->endian, p->pvd.pt_loc_m), tsk_getu32(fs->endian,
                p->pvd.pt_loc_m) + tsk_getu32(fs->endian,
                p->pvd.pt_size_m) / fs->block_size);

        tsk_fprintf(hFile, "Inode Range: %" PRIuINUM " - %" PRIuINUM "\n",
            fs->first_inum, fs->last_inum);

        tsk_fprintf(hFile, "\nCONTENT INFORMATION\n");
        tsk_fprintf(hFile,
            "--------------------------------------------\n");
        tsk_fprintf(hFile, "Sector Size: %d\n", ISO9660_SSIZE_B);
        tsk_fprintf(hFile, "Block Size: %d\n", tsk_getu16(fs->endian,
                p->pvd.blk_sz_m));

        tsk_fprintf(hFile, "Total Sector Range: 0 - %d\n",
            (int) ((fs->block_size / ISO9660_SSIZE_B) *
                (fs->block_count - 1)));
        /* get image slack, ignore how big the image claims itself to be */
        tsk_fprintf(hFile, "Total Block Range: 0 - %d\n",
            (int) fs->block_count - 1);
    }

    i = 0;

    for (s = iso->svd; s != NULL; s = s->next) {
        i++;
        tsk_fprintf(hFile, "\nSUPPLEMENTARY VOLUME DESCRIPTOR %d\n", i);
        tsk_fprintf(hFile, "\nFILE SYSTEM INFORMATION\n");
        tsk_fprintf(hFile,
            "--------------------------------------------\n");
        tsk_fprintf(hFile, "Read from Supplementary Volume Descriptor\n");
        tsk_fprintf(hFile, "File System Type: ISO9660\n");
        tsk_fprintf(hFile, "Volume Name: %s\n", s->svd.vol_id);
        tsk_fprintf(hFile, "Volume Set Size: %d\n",
            tsk_getu16(fs->endian, s->svd.vol_set_m));
        tsk_fprintf(hFile, "Volume Set Sequence: %d\n",
            tsk_getu16(fs->endian, s->svd.vol_seq_m));



        /* print publisher */
        if (s->svd.pub_id[0] == 0x5f)
            /* publisher is in a file.  TODO: handle this properly */
            snprintf(str, 8, "In file\n");
        else
            snprintf(str, 128, "%s", s->svd.pub_id);

        cp = &str[127];
        /* find last printable non space character */
        while ((!isprint(*cp) || isspace(*cp)) && (cp != str))
            cp--;
        *++cp = '\0';
        tsk_fprintf(hFile, "Publisher: %s\n", str);
        memset(str, ' ', 128);


        /* print data preparer */
        if (s->svd.prep_id[0] == 0x5f)
            /* preparer is in a file.  TODO: handle this properly */
            snprintf(str, 8, "In file\n");
        else
            snprintf(str, 128, "%s", s->svd.prep_id);

        cp = &str[127];
        while ((!isprint(*cp) || isspace(*cp)) && (cp != str))
            cp--;
        *++cp = '\0';
        tsk_fprintf(hFile, "Data Preparer: %s\n", str);
        memset(str, ' ', 128);


        /* print recording application */
        if (s->svd.app_id[0] == 0x5f)
            /* application is in a file.  TODO: handle this properly */
            snprintf(str, 8, "In file\n");
        else
            snprintf(str, 128, "%s", s->svd.app_id);
        cp = &str[127];
        while ((!isprint(*cp) || isspace(*cp)) && (cp != str))
            cp--;
        *++cp = '\0';
        tsk_fprintf(hFile, "Recording Application: %s\n", str);
        memset(str, ' ', 128);


        /* print copyright */
        if (s->svd.copy_id[0] == 0x5f)
            /* copyright is in a file.  TODO: handle this properly */
            snprintf(str, 8, "In file\n");
        else
            snprintf(str, 37, "%s\n", s->svd.copy_id);
        cp = &str[36];
        while ((!isprint(*cp) || isspace(*cp)) && (cp != str))
            cp--;
        *++cp = '\0';
        tsk_fprintf(hFile, "Copyright: %s\n", str);
        memset(str, ' ', 37);

        tsk_fprintf(hFile, "\nMETADATA INFORMATION\n");
        tsk_fprintf(hFile,
            "--------------------------------------------\n");
        tsk_fprintf(hFile,
            "Path Table Location: %" PRIu32 "-%" PRIu32 "\n",
            tsk_getu32(fs->endian, s->svd.pt_loc_m), tsk_getu32(fs->endian,
                s->svd.pt_loc_m) + tsk_getu32(fs->endian,
                s->svd.pt_size_m) / fs->block_size);

        /* learn joliet level (1-3) */
        if (!strncmp((char *) s->svd.esc_seq, "%/E", 3))
            tsk_fprintf(hFile, "Joliet Name Encoding: UCS-2 Level 3\n");
        if (!strncmp((char *) s->svd.esc_seq, "%/C", 3))
            tsk_fprintf(hFile, "Joliet Name Encoding: UCS-2 Level 2\n");
        if (!strncmp((char *) s->svd.esc_seq, "%/@", 3))
            tsk_fprintf(hFile, "Joliet Name Encoding: UCS-2 Level 1\n");
        if (iso->rr_found)
            tsk_fprintf(hFile, "RockRidge Extensions present\n");


        tsk_fprintf(hFile, "\nCONTENT INFORMATION\n");
        tsk_fprintf(hFile,
            "--------------------------------------------\n");
        tsk_fprintf(hFile, "Sector Size: %d\n", ISO9660_SSIZE_B);
        tsk_fprintf(hFile, "Block Size: %d\n", fs->block_size);

        tsk_fprintf(hFile, "Total Sector Range: 0 - %d\n",
            (int) ((fs->block_size / ISO9660_SSIZE_B) *
                (fs->block_count - 1)));
        /* get image slack, ignore how big the image claims itself to be */
        tsk_fprintf(hFile, "Total Block Range: 0 - %d\n",
            (int) fs->block_count - 1);
    }

    return 0;
}


/**
 * Make a unix-style permissions string based the flags in dentry
 * and the cached inode in fs
 */
char *
make_unix_perm(TSK_FS_INFO * fs, iso9660_dentry * dd)
{
    static char perm[11];
    ISO_INFO *iso = (ISO_INFO *) fs;

    if (tsk_verbose)
        tsk_fprintf(stderr, "make_unix_perm: fs: %lu"
            " dd: %lu\n", (uintptr_t) fs, (uintptr_t) dd);

    perm[10] = '\0';

    memset(perm, '-', 11);

    if (dd->flags & ISO9660_FLAG_DIR)
        perm[0] = 'd';

    if (iso->dinode->ea) {
        if (tsk_getu16(fs->endian, iso->dinode->ea->mode) & ISO9660_BIT_UR)
            perm[1] = 'r';

        if (tsk_getu16(fs->endian, iso->dinode->ea->mode) & ISO9660_BIT_UX)
            perm[3] = 'x';

        if (tsk_getu16(fs->endian, iso->dinode->ea->mode) & ISO9660_BIT_GR)
            perm[4] = 'r';

        if (tsk_getu16(fs->endian, iso->dinode->ea->mode) & ISO9660_BIT_GX)
            perm[6] = 'x';

        if (tsk_getu16(fs->endian, iso->dinode->ea->mode) & ISO9660_BIT_AR)
            perm[7] = 'r';

        if (tsk_getu16(fs->endian, iso->dinode->ea->mode) & ISO9660_BIT_AX)
            perm[9] = 'x';
    }
    else {
        strcpy(&perm[1], "r-xr-xr-x");
    }

    return perm;
}

# if 0
static void
iso9660_print_rockridge(FILE * hFile, rockridge_ext * rr)
{
    char mode_buf[11];

    tsk_fprintf(hFile, "\nROCKRIDGE EXTENSIONS\n");

    tsk_fprintf(hFile, "Owner-ID: ");
    tsk_fprintf(hFile, "%d\t", (int) rr->uid);

    tsk_fprintf(hFile, "Group-ID: ");
    tsk_fprintf(hFile, "%d\n", (int) rr->gid);

    tsk_fprintf(hFile, "Mode: ");
    memset(mode_buf, '-', 11);
    mode_buf[10] = '\0';

    /* file type */
    /* note: socket and symbolic link are multi bit fields */
    if ((rr->mode & MODE_IFSOCK) == MODE_IFSOCK)
        mode_buf[0] = 's';
    else if ((rr->mode & MODE_IFLNK) == MODE_IFLNK)
        mode_buf[0] = 'l';
    else if (rr->mode & MODE_IFDIR)
        mode_buf[0] = 'd';
    else if (rr->mode & MODE_IFIFO)
        mode_buf[0] = 'p';
    else if (rr->mode & MODE_IFBLK)
        mode_buf[0] = 'b';
    else if (rr->mode & MODE_IFCHR)
        mode_buf[0] = 'c';

    /* owner permissions */
    if (rr->mode & TSK_FS_INODE_MODE_IRUSR)
        mode_buf[1] = 'r';
    if (rr->mode & TSK_FS_INODE_MODE_IWUSR)
        mode_buf[2] = 'w';

    if ((rr->mode & TSK_FS_INODE_MODE_IXUSR)
        && (rr->mode & TSK_FS_INODE_MODE_ISUID))
        mode_buf[3] = 's';
    else if (rr->mode & TSK_FS_INODE_MODE_IXUSR)
        mode_buf[3] = 'x';
    else if (rr->mode & TSK_FS_INODE_MODE_ISUID)
        mode_buf[3] = 'S';

    /* group permissions */
    if (rr->mode & TSK_FS_INODE_MODE_IRGRP)
        mode_buf[4] = 'r';
    if (rr->mode & TSK_FS_INODE_MODE_IWGRP)
        mode_buf[5] = 'w';

    if ((rr->mode & TSK_FS_INODE_MODE_IXGRP)
        && (rr->mode & TSK_FS_INODE_MODE_ISGID))
        mode_buf[6] = 's';
    else if (rr->mode & TSK_FS_INODE_MODE_IXGRP)
        mode_buf[6] = 'x';
    else if (rr->mode & TSK_FS_INODE_MODE_ISGID)
        mode_buf[6] = 'S';

    /* other permissions */
    if (rr->mode & TSK_FS_INODE_MODE_IROTH)
        mode_buf[7] = 'r';
    if (rr->mode & TSK_FS_INODE_MODE_IWOTH)
        mode_buf[8] = 'w';

    if ((rr->mode & TSK_FS_INODE_MODE_IXOTH)
        && (rr->mode & TSK_FS_INODE_MODE_ISVTX))
        mode_buf[9] = 't';
    else if (rr->mode & TSK_FS_INODE_MODE_IXOTH)
        mode_buf[9] = 'x';
    else if (rr->mode & TSK_FS_INODE_MODE_ISVTX)
        mode_buf[9] = 'T';

    tsk_fprintf(hFile, "%s\n", mode_buf);
    tsk_fprintf(hFile, "Number links: %" PRIu32 "\n", rr->nlink);

    tsk_fprintf(hFile, "Alternate name: %s\n", rr->fn);
    tsk_fprintf(hFile, "\n");
}
#endif

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
iso9660_istat(TSK_FS_INFO * fs, FILE * hFile, TSK_INUM_T inum,
    TSK_DADDR_T numblock, int32_t sec_skew)
{
    ISO_INFO *iso = (ISO_INFO *) fs;
    TSK_FS_INODE *fs_inode;
    iso9660_dentry dd;

    // clean up any error messages that are lying around
    tsk_error_reset();

    fs_inode = iso9660_inode_lookup(fs, inum);
    if(fs_inode == NULL)
    	return 1;

    tsk_fprintf(hFile, "Entry: %"PRIuINUM"\n", inum);

    if (iso9660_dinode_load(iso, inum)) {
        snprintf(tsk_errstr2, TSK_ERRSTR_L, "iso9660_istat");
        tsk_fs_inode_free(fs_inode);
        return 1;
    }
    memcpy(&dd, &iso->dinode->dr, sizeof(iso9660_dentry));

    tsk_fprintf(hFile, "Type: ");
    if (dd.flags & ISO9660_FLAG_DIR)
        tsk_fprintf(hFile, "Directory\n");
    else
        tsk_fprintf(hFile, "File\n");

    tsk_fprintf(hFile, "Links: %d\n", fs_inode->nlink);

    if (dd.gap_sz > 0) {
        tsk_fprintf(hFile, "Interleave Gap Size: %d\n", dd.gap_sz);
        tsk_fprintf(hFile, "Interleave File Unit Size: %d\n", dd.unit_sz);
    }

    tsk_fprintf(hFile, "Flags: ");

    if (dd.flags & ISO9660_FLAG_HIDE)
        tsk_fprintf(hFile, "Hidden, ");

    if (dd.flags & ISO9660_FLAG_ASSOC)
        tsk_fprintf(hFile, "Associated, ");

    if (dd.flags & ISO9660_FLAG_RECORD)
        tsk_fprintf(hFile, "Record Format, ");

    if (dd.flags & ISO9660_FLAG_PROT)
        tsk_fprintf(hFile, "Protected,  ");

    /* check if reserved bits are set, be suspicious */
    if (dd.flags & ISO9660_FLAG_RES1)
        tsk_fprintf(hFile, "Reserved1, ");

    if (dd.flags & ISO9660_FLAG_RES2)
        tsk_fprintf(hFile, "Reserved2, ");

    if (dd.flags & ISO9660_FLAG_MULT)
        tsk_fprintf(hFile, "Non-final multi-extent entry");
    putchar('\n');

    tsk_fprintf(hFile, "Name: %s\n", iso->dinode->fn);
    tsk_fprintf(hFile, "Size: %" PRIu32 "\n", tsk_getu32(fs->endian,
            iso->dinode->dr.data_len_m));

    if (iso->dinode->ea) {
        tsk_fprintf(hFile, "\nEXTENDED ATTRIBUTE INFO\n");
        tsk_fprintf(hFile, "Owner-ID: %" PRIu32 "\n",
            tsk_getu32(fs->endian, iso->dinode->ea->uid));
        tsk_fprintf(hFile, "Group-ID: %" PRIu32 "\n",
            tsk_getu32(fs->endian, iso->dinode->ea->gid));
        tsk_fprintf(hFile, "Mode: %s\n", make_unix_perm(fs, &dd));
    }
    else if (iso->dinode->susp_off) {
        char *buf2 = (char *) talloc_size(fs_inode, (size_t) iso->dinode->susp_len);
        if (buf2 != NULL) {
            ssize_t cnt;
            fprintf(hFile, "\nRock Ridge Extension Data\n");
            cnt =
                tsk_fs_read_random(fs, buf2,
                (size_t)iso->dinode->susp_len, iso->dinode->susp_off);
            if (cnt == iso->dinode->susp_len) {
                parse_susp(fs_inode, fs, buf2, (int) cnt, hFile);
            }
            else {
                fprintf(hFile, "Error reading Rock Ridge Location\n");
                if (tsk_verbose) {
                    fprintf(stderr,
                        "istat: error reading rock ridge entry\n");
                    tsk_error_print(stderr);
                }
                tsk_error_reset();
            }
            talloc_free(buf2);
        }
        else {
            if (tsk_verbose)
                fprintf(stderr,
                    "istat: error allocating memory to process rock ridge entry\n");
            tsk_error_reset();
        }
    }
    //else if (iso->dinode->rr) {
    //    iso9660_print_rockridge(hFile, iso->dinode->rr);
    //}
    else {
        tsk_fprintf(hFile, "Owner-ID: 0\n");
        tsk_fprintf(hFile, "Group-ID: 0\n");
        tsk_fprintf(hFile, "Mode: %s\n", make_unix_perm(fs, &dd));
    }

    if (sec_skew != 0) {
        tsk_fprintf(hFile, "\nAdjusted File Times:\n");
        fs_inode->mtime -= sec_skew;
        fs_inode->atime -= sec_skew;
        fs_inode->ctime -= sec_skew;

        tsk_fprintf(hFile, "Written:\t%s", ctime(&fs_inode->mtime));
        tsk_fprintf(hFile, "Accessed:\t%s", ctime(&fs_inode->atime));
        tsk_fprintf(hFile, "Created:\t%s", ctime(&fs_inode->ctime));

        fs_inode->mtime += sec_skew;
        fs_inode->atime += sec_skew;
        fs_inode->ctime += sec_skew;

        tsk_fprintf(hFile, "\nOriginal File Times:\n");
    }
    else {
        tsk_fprintf(hFile, "\nFile Times:\n");
    }

    tsk_fprintf(hFile, "Created:\t%s", ctime(&fs_inode->ctime));
    tsk_fprintf(hFile, "File Modified:\t%s", ctime(&fs_inode->mtime));
    tsk_fprintf(hFile, "Accessed:\t%s", ctime(&fs_inode->atime));


    tsk_fprintf(hFile, "\nSectors:\n");
    /* since blocks are all contiguous, print them here to simplify file_walk */
    {
        int block = tsk_getu32(fs->endian, iso->dinode->dr.ext_loc_m);
        TSK_OFF_T size = fs_inode->size;
        int rowcount = 0;

        while ((int64_t) size > 0) {
            tsk_fprintf(hFile, "%d ", block++);
            size -= fs->block_size;
            rowcount++;
            if (rowcount == 8) {
                rowcount = 0;
                tsk_fprintf(hFile, "\n");
            }
        }
        tsk_fprintf(hFile, "\n");
    }
    tsk_fs_inode_free(fs_inode);
    return 0;
}




uint8_t
iso9660_jopen(TSK_FS_INFO * fs, TSK_INUM_T inum)
{
    tsk_error_reset();
    tsk_errno = TSK_ERR_FS_FUNC;
    snprintf(tsk_errstr, TSK_ERRSTR_L, "ISO9660 does not have a journal");
    return 1;
}

uint8_t
iso9660_jentry_walk(TSK_FS_INFO * fs, int flags,
    TSK_FS_JENTRY_WALK_CB action, void *ptr)
{
    tsk_error_reset();
    tsk_errno = TSK_ERR_FS_FUNC;
    snprintf(tsk_errstr, TSK_ERRSTR_L, "ISO9660 does not have a journal");
    return 1;
}

uint8_t
iso9660_jblk_walk(TSK_FS_INFO * fs, TSK_DADDR_T start, TSK_DADDR_T end, int flags,
    TSK_FS_JBLK_WALK_CB action, void *ptr)
{
    tsk_error_reset();
    tsk_errno = TSK_ERR_FS_FUNC;
    snprintf(tsk_errstr, TSK_ERRSTR_L, "ISO9660 does not have a journal");
    return 1;
}

static void
iso9660_close(TSK_FS_INFO * fs)
{
	talloc_free(fs);
	return;
}

/** Load the volume descriptors into save the raw data structures in
 * the file system state structure (fs).  Also determines the block size.
 *
 * This is useful for discs which may have 2 volumes on them (no, not
 * multisession CD-R/CD-RW).
 * Design note: If path table address is the same, then you have the same image.
 * Only store unique image info.
 * Uses a linked list even though Ecma-119 says there is only 1 primary vol
 * desc, consider possibility of more.
 *
 * Returns -1 on error and 0 on success
 */
static int
load_vol_desc(TSK_FS_INFO * fs)
{
    int count = 0;
    ISO_INFO *iso = (ISO_INFO *) fs;
    TSK_OFF_T offs;
    char *myname = "iso_load_vol_desc";
    ssize_t cnt;
    iso9660_pvd_node *p;
    iso9660_svd_node *s;

    iso->pvd = NULL;
    iso->svd = NULL;
    fs->block_size = 0;
    fs->dev_bsize = 512;

#if 0
    b = (iso_bootrec *) tsk_malloc(sizeof(iso_bootrec));
    if (b == NULL) {
        return -1;
    }
#endif

    // @@@ Technically, we should seek ahea 16 * sector size
    for (offs = ISO9660_SBOFF;; offs += sizeof(iso9660_gvd)) {
        iso9660_gvd *vd;

        // allocate a buffer the size of the nodes in the linked list
        if ((vd = (iso9660_gvd *) talloc_size(iso, sizeof(iso9660_pvd_node))) ==
            NULL) {
            return -1;
        }

        // read the full descriptor
        cnt =
            tsk_fs_read_random(fs, (char *) vd, sizeof(iso9660_gvd), offs);
        if (cnt != sizeof(iso9660_gvd)) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_errno = TSK_ERR_FS_READ;
            }
            snprintf(tsk_errstr2, TSK_ERRSTR_L,
                "iso_load_vol_desc: Error reading");
            return -1;
        }

        // verify the magic value
        if (strncmp(vd->magic, ISO9660_MAGIC, 5)) {
            if (tsk_verbose)
                tsk_fprintf(stderr, "%s: Bad volume descriptor: \
                         Magic number is not CD001\n", myname);
            return -1;
        }

        // see if we are done
        if (vd->type == ISO9660_VOL_DESC_SET_TERM)
            break;

        switch (vd->type) {

        case ISO9660_PRIM_VOL_DESC:
            p = (iso9660_pvd_node *) vd;

            /* list not empty */
            if (iso->pvd) {
                iso9660_pvd_node *ptmp = iso->pvd;
                /* append to list if path table address not found in list */
                while ((p->pvd.pt_loc_l != ptmp->pvd.pt_loc_l)
                    && (ptmp->next))
                    ptmp = ptmp->next;

                if (p->pvd.pt_loc_l == ptmp->pvd.pt_loc_l) {
                    talloc_free(p);
                    p = NULL;
                }
                else {
                    ptmp->next = p;
                    p->next = NULL;
                    count++;
                }
            }

            /* list empty, insert */
            else {
                iso->pvd = p;
                p->next = NULL;
                count++;
            }

            break;

        case ISO9660_SUPP_VOL_DESC:
            s = (iso9660_svd_node *) vd;

            /* list not empty */
            if (iso->svd) {
                iso9660_svd_node *stmp = iso->svd;
                /* append to list if path table address not found in list */
                while ((s->svd.pt_loc_l != stmp->svd.pt_loc_l)
                    && (stmp->next))
                    stmp = stmp->next;

                if (s->svd.pt_loc_l == stmp->svd.pt_loc_l) {
                    talloc_free(s);
                    s = NULL;
                }
                else {
                    stmp->next = s;
                    s->next = NULL;
                    count++;
                }
            }

            /* list empty, insert */
            else {
                iso->svd = s;
                s->next = NULL;
                count++;
            }

            break;

            /* boot records are just read and discarded for now... */
        case ISO9660_BOOT_RECORD:
#if 0
            cnt =
                tsk_fs_read_random(fs, (char *) b, sizeof(iso_bootrec),
                offs);
            if (cnt != sizeof(iso_bootrec)) {
                if (cnt >= 0) {
                    tsk_error_reset();
                    tsk_errno = TSK_ERR_FS_READ;
                }
                snprintf(tsk_errstr2, TSK_ERRSTR_L,
                    "iso_load_vol_desc: Error reading");
                return -1;
            }
            offs += sizeof(iso_bootrec);
#endif
            break;
        }
    }


    /* now that we have all primary and supplementary volume descs, we should cull the list of */
    /* primary that match up with supplems, since supplem has all info primary has plus more. */
    /* this will make jobs such as searching all volumes easier later */
    for (s = iso->svd; s != NULL; s = s->next) {
        for (p = iso->pvd; p != NULL; p = p->next) {
            // see if they have the same starting address
            if (tsk_getu32(fs->endian,
                    p->pvd.pt_loc_m) == tsk_getu32(fs->endian,
                    s->svd.pt_loc_m)) {
                // see if it is the head of the list
                if (p == iso->pvd) {
                    iso->pvd = p->next;
                }
                else {
                    iso9660_pvd_node *ptmp = iso->pvd;
                    while (ptmp->next != p)
                        ptmp = ptmp->next;
                    ptmp->next = p->next;
                }
                p->next = NULL;
                talloc_free(p);
                p = NULL;
                count--;
                break;
            }
        }
    }

    if ((iso->pvd == NULL) && (iso->svd == NULL)) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_MAGIC;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "load_vol_desc: primary and secondary volume descriptors null");
        return -1;
    }


    return 0;
}


/* iso9660_open -
 * opens an iso9660 filesystem.
 * Design note: This function doesn't read a superblock, since iso9660 doesnt
 * really have one.  Volume info is read in with a call to load_vol_descs().
 */
TSK_FS_INFO *
iso9660_open(TSK_IMG_INFO * img_info, TSK_OFF_T offset,
    TSK_FS_INFO_TYPE_ENUM ftype, uint8_t test)
{
    ISO_INFO *iso;
    TSK_FS_INFO *fs;

    int len;

    if ((ftype & TSK_FS_INFO_TYPE_FS_MASK) !=
        TSK_FS_INFO_TYPE_ISO9660_TYPE) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_ARG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "Invalid FS type in iso9660_open");
        return NULL;
    }

    if (tsk_verbose) {
        tsk_fprintf(stderr, "iso9660_open img_info: %lu"
            " ftype: %" PRIu8 " test: %" PRIu8 "\n", (uintptr_t) img_info,
            ftype, test);
    }

    if ((iso = talloc(NULL, ISO_INFO)) == NULL) {
        return NULL;
    }
    fs = &(iso->fs_info);

    iso->rr_found = 0;
    iso->in_list = NULL;

    fs->ftype = ftype;
    fs->duname = "Block";
    fs->flags = 0;
    fs->img_info = img_info;
    fs->offset = offset;


    /* following two lines use setup TSK memory manger for local byte ordering
     * since we never check magic as a number, because it is not a number
     * and ISO9660 has no concept of byte order.
     */
    len = 1;
    tsk_fs_guessu32(fs, (uint8_t *) & len, 1);
    fs->endian = TSK_BIG_ENDIAN;

    /* load_vol_descs checks magic value */
    if (load_vol_desc(fs) == -1) {
        talloc_free(iso);
        if (test)
            return NULL;
        else {
            tsk_error_reset();
            tsk_errno = TSK_ERR_FS_MAGIC;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "Invalid FS type in iso9660_open");
            return NULL;
        }
    }

    fs->endian = TSK_BIG_ENDIAN;
    if (iso->pvd) {
        fs->block_size = tsk_getu16(fs->endian, iso->pvd->pvd.blk_sz_m);
        fs->block_count = tsk_getu32(fs->endian, iso->pvd->pvd.vs_sz_m);
    }
    else {
        fs->block_size = tsk_getu16(fs->endian, iso->svd->svd.blk_sz_m);
        fs->block_count = tsk_getu32(fs->endian, iso->svd->svd.vs_sz_m);
    }

    fs->first_block = 0;
    fs->last_block = fs->last_block_act = fs->block_count - 1;

    // determine the last block we have in this image
    if ((TSK_DADDR_T)((img_info->size - offset) / fs->block_size) < fs->last_block)
        fs->last_block_act =
            (img_info->size - offset) / fs->block_size - 1;

    fs->inum_count = iso9660_load_inodes_pt(iso);
    if ((int) fs->inum_count == -1) {
    	talloc_free(iso);
        return NULL;
    }

    fs->last_inum = fs->inum_count - 1;
    fs->first_inum = ISO9660_FIRSTINO;
    fs->root_inum = ISO9660_ROOTINO;


    fs->inode_walk = iso9660_inode_walk;
    fs->block_walk = iso9660_block_walk;
    fs->file_walk = iso9660_file_walk;
    fs->inode_lookup = iso9660_inode_lookup;
    fs->dent_walk = iso9660_dent_walk;
    fs->fsstat = iso9660_fsstat;
    fs->fscheck = iso9660_fscheck;
    fs->istat = iso9660_istat;
    fs->close = iso9660_close;

    fs->jblk_walk = iso9660_jblk_walk;
    fs->jentry_walk = iso9660_jentry_walk;
    fs->jopen = iso9660_jopen;


    /* allocate buffers */
    /* dinode */
    iso->dinode = talloc(iso, iso9660_inode);
    if (iso->dinode == NULL) {
    	talloc_free(iso);
        return NULL;
    }
    iso->dinum = -1;

    fs->list_inum_named = NULL;

    return fs;
}
