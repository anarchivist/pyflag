/*
** The Sleuth Kit
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

#include "fs_tools_i.h"
#include "hfs.h"


/**********************************************************************
 *
 *  MISC FUNCS
 *
 **********************************************************************/

/* convert the HFS Time (seconds from 1/1/1904)
 * to UNIX (UTC seconds from 1/1/1970)
 * The number is borrowed from linux HFS driver source
 */
uint32_t
hfs2unixtime(uint32_t hfsdate)
{
    return (uint32_t) (hfsdate - NSEC_BTWN_1904_1970);
}


/**********************************************************************
 *
 * Lookup Functions
 *
 **********************************************************************/

/* hfs_is_block_alloc - return 1 if bit 'b' is allocated.
 * block - number of bit to be checked for allocation
 * alloc_file - the bitmap to be checked
 * adapted from IsAllocationBlockUsed from:
 * http://developer.apple.com/technotes/tn/tn1150.html
 */
int
hfs_is_bit_b_alloc(uint32_t b, uint8_t * alloc_file)
{
    uint8_t this_byte;

    this_byte = alloc_file[b / 8];
    return (this_byte & (1 << (7 - (b % 8)))) != 0;
}

#define hfs_is_leaf(b, c) \
        hfs_is_bit_b_alloc(b, c)

#define hfs_is_block_alloc(b, c) \
        hfs_is_bit_b_alloc(b, c)

#define hfs_is_deleted_leaf(b, c) \
        hfs_is_bit_b_alloc(b, c)


/* return the offset into the image that btree node 'node' is at */
DADDR_T
hfs_cat_find_node_offset(HFS_INFO * hfs, int nodenum)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & (hfs->fs_info);
    uint16_t nodesize;          /* size of each node */
    int i;
    uint64_t bytes;             /* bytes left this extent */
    OFF_T r_offs;               /* offset we are reading from */
    OFF_T f_offs;               /* offset into the catalog file */
    OFF_T n_offs;               /* offset of the node we are looking for */
    hfs_sb *sb = hfs->fs;

    if (tsk_verbose)
        tsk_fprintf(stderr, "hfs_cat_find_node_offset: finding offset of "
            "btree node: %" PRIu32 "\n", nodenum);

    /* find first extent with data in it */
    i = 0;
    while (!(tsk_getu32(fs->endian, sb->cat_file.extents[i].blk_cnt)))
        i++;

    if (i > 7)
        tsk_fprintf(stderr,
            "hfs_cat_find_node_offset: No data found in catalog file extents\n");

    bytes =
        tsk_getu32(fs->endian,
        sb->cat_file.extents[i].blk_cnt) * fs->block_size;
    r_offs =
        tsk_getu32(fs->endian,
        sb->cat_file.extents[i].start_blk) * fs->block_size;
    f_offs = 0;

    nodesize = tsk_getu16(fs->endian, hfs->hdr->size);

    /* calculate where we will find the 'nodenum' node */
    n_offs = nodesize * nodenum;

    while (f_offs < n_offs) {

        if (n_offs <= (f_offs + bytes)) {

            r_offs += n_offs - f_offs;
            f_offs = n_offs;

        }
        else {

            i++;

            if (i > 7)
                tsk_fprintf(stderr,
                    "hfs_cat_find_node_offset: File seek error while searching for node %"
                    PRIu32 "\n", nodenum);

            r_offs =
                tsk_getu32(fs->endian,
                sb->cat_file.extents[i].start_blk) * fs->block_size;
            f_offs += bytes;
            bytes =
                tsk_getu64(fs->endian,
                sb->cat_file.extents[i].blk_cnt) * fs->block_size;

        }
    }

    return r_offs;
}


/* used to set fs->last_inum. */
static INUM_T
hfs_find_highest_inum(HFS_INFO * hfs)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & (hfs->fs_info);
    INUM_T highest = 0;
    int nodes;
    int i, j;
    OFF_T n_offs;               /* offset of the node */
    OFF_T addr_offs;            /* offset of next record address */
    hfs_btree_node node;
    int num_rec;                /* number of records this node */
    uint8_t r_offs[2];          /* offset of the record in the node */
    OFF_T read_offs;            /* read offset into node */
    uint8_t keylen[2];          /* length of this record's key */
    uint8_t rec_type[2];        /* record type */
    uint16_t filetype;
    uint8_t cnid[4];

    if (tsk_verbose)
        tsk_fprintf(stderr, "hfs_find_highest_inum: called\n");

    nodes = tsk_getu32(fs->endian, hfs->hdr->total);

    for (i = 0; i < nodes; i++) {

        if (hfs_is_leaf(i, hfs->leaf_map)) {

            n_offs = hfs_cat_find_node_offset(hfs, i);

            addr_offs =
                n_offs + tsk_getu16(fs->endian, hfs->hdr->size) - 2;

            tsk_fs_read_random(fs, (char *) &node, sizeof(node), n_offs);

            num_rec = tsk_getu16(fs->endian, node.num_rec);

            for (j = 1; j <= num_rec; j++) {

                /* get offset of next record */
                tsk_fs_read_random(fs, (char *) &r_offs, 2, addr_offs);

                read_offs = n_offs + tsk_getu16(fs->endian, r_offs);

                tsk_fs_read_random(fs, (char *) &keylen, 2, read_offs);
                read_offs += 2;

                read_offs += tsk_getu16(fs->endian, keylen);

                tsk_fs_read_random(fs, (char *) rec_type, 2, read_offs);

                filetype = tsk_getu16(fs->endian, rec_type);

                if ((filetype == HFS_FILE_RECORD)
                    || (filetype == HFS_FOLDER_RECORD))
                    tsk_fs_read_random(fs, (char *) &cnid, 4,
                        read_offs + 8);

                if ((filetype == HFS_FILE_RECORD) ||
                    (filetype == HFS_FOLDER_RECORD)) {

                    if (tsk_getu32(fs->endian, cnid) > highest)
                        highest = tsk_getu32(fs->endian, cnid);
                }

                addr_offs -= 2;
            }
        }
    }

    return highest;
}


/* this function adds an abstraction layer above the btree for searching files
 * easily. one issue I ran into a lot was not being able to build the entire 
 * search key for the btree and thus not being able to find all the files that
 * are on disk, or even find a specific file knowing a little bit about it.
 */
static void
hfs_load_inode_list(HFS_INFO * hfs)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & (hfs->fs_info);
    int i, j, nodes;
    DADDR_T n_offs;             /* offset of the node */
    DADDR_T addr_offs;          /* offset of next record address */
    hfs_btree_node node;
    int num_rec;                /* number of records this node */
    uint8_t r_offs[2];          /* offset of the record in the node */
    DADDR_T read_offs;          /* read offset into node */
    uint8_t keylen[2];          /* length of this record's key */
    uint8_t rec_type[2];        /* record type */
    uint16_t filetype;
    uint8_t cnid[4];
    htsk_fs_inode_mode_struct *in;
    uint8_t parent[4];
    DADDR_T key_offs;

    nodes = tsk_getu32(fs->endian, hfs->hdr->total);

    for (i = 0; i < nodes; i++) {

        if (hfs_is_leaf(i, hfs->leaf_map)) {

            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "hfs_load_inode_list: node %i is a leaf\n", i);

            n_offs = hfs_cat_find_node_offset(hfs, i);

            addr_offs =
                n_offs + tsk_getu16(fs->endian, hfs->hdr->size) - 2;

            tsk_fs_read_random(fs, (char *) &node, sizeof(node), n_offs);

            num_rec = tsk_getu16(fs->endian, node.num_rec);

            for (j = 1; j <= num_rec; j++) {

                /* get offset of next record */
                tsk_fs_read_random(fs, (char *) &r_offs, 2, addr_offs);

                read_offs = n_offs + tsk_getu16(fs->endian, r_offs);

                key_offs = read_offs;

                tsk_fs_read_random(fs, (char *) &keylen, 2, read_offs);
                read_offs += 2;

                tsk_fs_read_random(fs, (char *) &parent, 4, read_offs);

                read_offs += tsk_getu16(fs->endian, keylen);

                tsk_fs_read_random(fs, (char *) rec_type, 2, read_offs);

                filetype = tsk_getu16(fs->endian, rec_type);

                if ((filetype == HFS_FILE_RECORD)
                    || (filetype == HFS_FOLDER_RECORD)) {
                    tsk_fs_read_random(fs, (char *) &cnid, 4,
                        read_offs + 8);
                    in = hfs->inodes + tsk_getu32(fs->endian, cnid);
                    in->inum = tsk_getu32(fs->endian, cnid);
                    in->parent = tsk_getu32(fs->endian, parent);
                    in->offs = key_offs;
                    in->node = i;
                }

                addr_offs -= 2;
            }
        }
    }
}

/* lookup inode inum in the catalog file btree
 *
 * note: one thing that the Apple spec does not tell us
 * is how it deletes files.  The specification is open but
 * the algorithms are proprietary so finding deleted files
 * is difficult.  So far this searches leaf nodes of the 
 * catalog btree that are not in the allocated leaf node
 * list and finds files in them.  This may actually produce
 * no results but its the best we have so far.
 */

static void
hfs_catalog_lookup(HFS_INFO * hfs, hfs_file * cat, INUM_T inum)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & (hfs->fs_info);
    htsk_fs_inode_mode_struct *in;
    uint8_t key_len[2];
    DADDR_T read_offs;
    uint8_t rec_type[2];        /* record type */
    uint32_t filetype;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_catalog_lookup: Processing CAT %" PRIuINUM "\n", inum);

    /* sanity checks */
    if (!cat)
        tsk_fprintf(stderr, "catalog_lookup: null cat buffer");

    if (inum < fs->first_inum)
        tsk_fprintf(stderr, "inode number is too small (%" PRIuINUM ")",
            inum);
    if (inum > fs->last_inum)
        tsk_fprintf(stderr, "inode number is too large (%" PRIuINUM ")",
            inum);

    in = hfs->inodes + (int) inum;

    if (in->node == 0)
        tsk_fprintf(stderr,
            "Error finding catalog entry %" PRIuINUM " in catalog", inum);

    hfs->key = in->offs;

//    if (hfs_is_deleted_leaf(in->node, hfs->leaf_map))
//      hfs->flags |= FS_FLAG_META_UNLINK;
//    else
//      hfs->flags |= FS_FLAG_META_LINK;

    read_offs = in->offs;

    tsk_fs_read_random(fs, (char *) &key_len, 2, read_offs);
    read_offs += tsk_getu16(fs->endian, key_len) + 2;

    tsk_fs_read_random(fs, (char *) rec_type, 2, read_offs);

    filetype = tsk_getu16(fs->endian, rec_type);

    if (filetype == HFS_FILE_RECORD)
        tsk_fs_read_random(fs, (char *) hfs->cat, sizeof(hfs_file),
            read_offs);
    else
        tsk_fs_read_random(fs, (char *) hfs->cat, sizeof(hfs_folder),
            read_offs);
}


/* get the catalog file header node and cache it.  This will be useful for 
 * searching later 
 */
static int
hfs_catalog_get_header(HFS_INFO * hfs)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & (hfs->fs_info);
    int i;
    hfs_btree_node node;
    hfs_sb *sb = hfs->fs;
    DADDR_T r_offs;
    hfs_ext_desc *h;

    if (tsk_verbose)
        tsk_fprintf(stderr, "hfs_catalog_get_header: called\n");

    /* already got it */
    if (hfs->hdr)
        return 0;

    hfs->hdr = (hfs_btree_header_record *)
        tsk_malloc(sizeof(hfs_btree_header_record));

    /* find first extent with data in it */
    i = 0;
    h = sb->cat_file.extents;
    while (!(tsk_getu32(fs->endian, h[i].blk_cnt)))
        i++;

    r_offs = tsk_getu32(fs->endian, h[i].start_blk) * fs->block_size;
    tsk_fs_read_random(fs, (char *) &node, sizeof(node), r_offs);

    if (node.kind != HFS_BTREE_HEADER_NODE)
        tsk_fprintf(stderr,
            "hfs_catalog_get_header: Header node not found\n");

    r_offs += sizeof(node);

    /* get header node of btree */
    tsk_fs_read_random(fs, (char *) hfs->hdr,
        sizeof(hfs_btree_header_record), r_offs);

    return 0;
}


/* hfs_blockmap_build - This function will allocate a bitmap of blocks which
 * are allocated.
 */
static int
hfs_blockmap_build(HFS_INFO * hfs)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & (hfs->fs_info);
    int i;
    hfs_ext_desc *h;
    uint32_t block_count;
    size_t bitmap_size;
    size_t size;
    DADDR_T offs;

    if (tsk_verbose)
        tsk_fprintf(stderr, "hfs_blockmap_build: called\n");

    bitmap_size = roundup(fs->block_count / 8, fs->block_size);
    hfs->block_map = (uint8_t *) tsk_malloc(bitmap_size);

    h = hfs->fs->alloc_file.extents;

    size = fs->block_size;

    for (i = 0; i < 8; i++) {
        block_count = tsk_getu32(fs->endian, h[i].blk_cnt);
        offs = tsk_getu32(fs->endian, h[i].start_blk) * fs->block_size;
        if (block_count > 0) {
            tsk_fs_read_random(fs, (char *) hfs->block_map,
                size * block_count, offs);
        }
    }

    return 0;
}


/* hfs_leafmap_build - This function will allocate a bitmap of nodes which
 * show up as leaf nodes.  The allocation status of the node is ignored to
 * allow recovery of deleted inodes as well as allowing utilities such as
 * ils to see all inodes, regardless if they are deleted.
 */
static int
hfs_leafmap_build(HFS_INFO * hfs)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & (hfs->fs_info);
    size_t nodes;
    int i;
    OFF_T addr;
    hfs_btree_node n;
    int this_byte;
    int leafmap_size;

    if (tsk_verbose)
        tsk_fprintf(stderr, "hfs_leafmap_build: called\n");

    nodes = tsk_getu32(fs->endian, hfs->hdr->total);

    leafmap_size = roundup(nodes / 8, 8);

    hfs->leaf_map = (uint8_t *) tsk_malloc(leafmap_size);

    for (i = 0; i < nodes; i++) {
        addr = hfs_cat_find_node_offset(hfs, i);
        tsk_fs_read_random(fs, (char *) &n, sizeof(hfs_btree_node), addr);

        this_byte = i / 8;
        /* check node type.  a leaf node's height is always 1 */
        if ((n.kind == HFS_BTREE_LEAF_NODE) && (n.height == 1))
            hfs->leaf_map[this_byte] |= 1 << (7 - (i % 8));
        else
            hfs->leaf_map[this_byte] &= (0xff ^ (1 << (7 - (i % 8))));
    }

    return 0;

}

/* create a bitmap of deleted leaf nodes based on the original leaf node map.
 * this will help search for deleted files since they are no longer in the
 * btree search paths.
 */
static int
hfs_deleted_map_build(HFS_INFO * hfs)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & (hfs->fs_info);
    int deleted_size;
    size_t nodes;
    int leaf;
    OFF_T addr;
    hfs_btree_node node;
    int this_byte;

    if (tsk_verbose)
        tsk_fprintf(stderr, "hfs_deleted_map_build: called\n");

    leaf = tsk_getu32(fs->endian, hfs->hdr->firstleaf);

    nodes = tsk_getu32(fs->endian, hfs->hdr->total);

    deleted_size = roundup(nodes / 8, 8);

    hfs->del_map = (uint8_t *) tsk_malloc(deleted_size);

    /* get initial bitmap of what are leaf nodes */
    memcpy(hfs->del_map, hfs->leaf_map, deleted_size);

    while (leaf != 0) {
        /* clear the bit for this node */
        this_byte = leaf / 8;
        hfs->del_map[this_byte] ^= 1 << (7 - (leaf % 8));

        addr = hfs_cat_find_node_offset(hfs, leaf);
        tsk_fs_read_random(fs, (char *) &node, sizeof(node), addr);
        leaf = tsk_getu32(fs->endian, node.flink);
    }

    return 0;
}


/*
 * Copy the inode into the generic structure 
 */
static void
hfs_copy_inode(HFS_INFO * hfs, TSK_FS_INODE * fs_inode)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & hfs->fs_info;

    if (tsk_verbose)
        tsk_fprintf(stderr, "hfs_copy_inode: called\n");

    fs_inode->mode = tsk_getu16(fs->endian, hfs->cat->perm.mode);
    fs_inode->nlink = tsk_getu32(fs->endian, hfs->cat->perm.special.nlink);

    /* for now report directory size as 0 */
    if (tsk_getu16(fs->endian, hfs->cat->rec_type) == HFS_FOLDER_RECORD)
        fs_inode->size = 0;
    else
        fs_inode->size = tsk_getu64(fs->endian, hfs->cat->data.logic_sz);

    fs_inode->uid = tsk_getu32(fs->endian, hfs->cat->perm.owner);
    fs_inode->gid = tsk_getu32(fs->endian, hfs->cat->perm.group);
    fs_inode->mtime =
        hfs2unixtime(tsk_getu32(fs->endian, hfs->cat->cmtime));
    fs_inode->atime =
        hfs2unixtime(tsk_getu32(fs->endian, hfs->cat->atime));
    fs_inode->ctime =
        hfs2unixtime(tsk_getu32(fs->endian, hfs->cat->ctime));
    fs_inode->direct_count = 0;
    fs_inode->indir_count = 0;
    fs_inode->addr = hfs->inum;

    fs_inode->flags = 0;

    return;
}


/* 
 * Read the cat entry and put it into the hfs->cat structure
 * Also sets the hfs->inum value
 */
uint8_t
hfs_dinode_lookup(HFS_INFO * hfs, INUM_T inum)
{
    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_dinode_lookup: looking up %" PRIuINUM "\n", inum);

    /* cat_lookup does a sanity check, so we can skip it here */
    hfs_catalog_lookup(hfs, hfs->cat, inum);
    hfs->inum = inum;

    return 0;
}


/*
 * return the cat entry in the generic TSK_FS_INODE format
 */
static TSK_FS_INODE *
hfs_inode_lookup(TSK_FS_INFO * fs, INUM_T inum)
{
    HFS_INFO *hfs = (HFS_INFO *) fs;
    TSK_FS_INODE *fs_inode = tsk_fs_inode_alloc(HFS_NDADDR, HFS_NIADDR);

    if (tsk_verbose)
        tsk_fprintf(stderr, "hfs_inode_lookup: looking up %" PRIuINUM "\n",
            inum);

    /* Lookup inode and store it in the HFS structure */
    hfs_dinode_lookup(hfs, inum);

    /* Copy the structure in hfs to generic fs_inode */
    hfs_copy_inode(hfs, fs_inode);

    return (fs_inode);
}


uint8_t
hfs_file_walk(TSK_FS_INFO * fs, TSK_FS_INODE * inode, uint32_t type,
    uint16_t id, TSK_FS_FILE_FLAG_ENUM flags,
    TSK_FS_FILE_WALK_CB action, void *ptr)
{
    HFS_INFO *hfs = (HFS_INFO *) fs;
    char *data_buf;
    int myflags;
    size_t length, size;
    OFF_T offs;
    int i;
    int bytes_read;             /* bytes read using tsk_fs_read_random */
    DADDR_T addr;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_file_walk: inode: %" PRIuINUM " type: %" PRIu32
            " id: %" PRIu16 " flags: %X\n", inode->addr, type, id, flags);

    myflags = TSK_FS_BLOCK_FLAG_CONT;

    if (tsk_getu16(fs->endian, hfs->cat->rec_type) != HFS_FILE_RECORD)
        return 0;

    data_buf = tsk_malloc(fs->block_size);

    length = inode->size;

    /* examine data at end of last file sector */
    if (flags & TSK_FS_FILE_FLAG_SLACK)
        length = roundup(length, fs->block_size);
    else
        length = inode->size;

    for (i = 0; i < 7; i++) {

        addr = tsk_getu32(fs->endian, hfs->cat->data.extents[i].start_blk);

        while (length > 0) {

            offs = fs->block_size * addr;

            if (length > fs->block_size)
                size = fs->block_size;
            else
                size = length;

            if ((flags & TSK_FS_FILE_FLAG_AONLY) == 0) {
                bytes_read = tsk_fs_read_random(fs, data_buf, size, offs);
                if (bytes_read != size) {
                    tsk_fprintf(stderr,
                        "hfs_file_walk: Error reading block %" PRIuDADDR
                        " %m", addr);
                }
            }
            else {
                bytes_read = size;
            }
            offs += bytes_read;

            if (TSK_WALK_STOP ==
                action(fs, addr, data_buf, size, myflags, ptr)) {

                free(data_buf);
                return 0;
            }
            addr++;
            length -= bytes_read;
        }
    }

    free(data_buf);
    return 0;
}


uint8_t
hfs_block_walk(TSK_FS_INFO * fs, DADDR_T start_blk, DADDR_T end_blk,
    TSK_FS_BLOCK_FLAG_ENUM flags, TSK_FS_BLOCK_WALK_CB action, void *ptr)
{
    char *myname = "hfs_block_walk";
    HFS_INFO *hfs = (HFS_INFO *) fs;
    TSK_DATA_BUF *data_buf = tsk_data_buf_alloc(fs->block_size);
    DADDR_T addr;
    int myflags = 0;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_block_walk: start_blk: %" PRIuDADDR " end_blk: %"
            PRIuDADDR " flags: %" PRIu32 "\n", start_blk, end_blk, flags);

    /*
     * Sanity checks.
     */
    if (start_blk < fs->first_block || start_blk > fs->last_block)
        tsk_fprintf(stderr,
            "%s: invalid start block number: %" PRIuDADDR "", myname,
            start_blk);
    if (end_blk < fs->first_block || end_blk > fs->last_block)
        tsk_fprintf(stderr,
            "%s: invalid last block number: %" PRIuDADDR "", myname,
            end_blk);

    /*
     * Iterate
     */
    for (addr = start_blk; addr <= end_blk; addr++) {

        /* identify if the cluster is allocated or not */
        myflags = hfs_is_block_alloc(addr, hfs->block_map) ?
            TSK_FS_BLOCK_FLAG_ALLOC : TSK_FS_BLOCK_FLAG_UNALLOC;

        if ((flags & myflags) == myflags) {
            if (tsk_fs_read_block(fs, data_buf, fs->block_size, addr) !=
                fs->block_size) {
                tsk_fprintf(stderr,
                    "hfs_block_walk: Error reading block %" PRIuDADDR
                    ": %m", addr);
            }
            if (TSK_WALK_STOP ==
                action(fs, addr, data_buf->data, myflags, ptr)) {
                tsk_data_buf_free(data_buf);
                return 0;
            }
        }
    }

    tsk_data_buf_free(data_buf);
    return 0;
}


uint8_t
hfs_inode_walk(TSK_FS_INFO * fs, INUM_T start_inum, INUM_T end_inum,
    TSK_FS_INODE_FLAG_ENUM flags, TSK_FS_INODE_WALK_CB action, void *ptr)
{
    HFS_INFO *hfs = (HFS_INFO *) fs;
    INUM_T inum;
    TSK_FS_INODE *fs_inode = tsk_fs_inode_alloc(HFS_NDADDR, HFS_NIADDR);

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_inode_walk: start_inum: %" PRIuINUM " end_inum: %"
            PRIuINUM " flags: %" PRIu32 "\n", start_inum, end_inum, flags);

    /*
     * Sanity checks.
     */
    if (start_inum < fs->first_inum)
        tsk_fprintf(stderr,
            "Starting inode number is too small (%" PRIuINUM ")",
            start_inum);
    if (start_inum > fs->last_inum)
        tsk_fprintf(stderr,
            "Starting inode number is too large (%" PRIuINUM ")",
            start_inum);

    if (end_inum < fs->first_inum)
        tsk_fprintf(stderr,
            "Ending inode number is too small (%" PRIuINUM ")", end_inum);
    if (end_inum > fs->last_inum)
        tsk_fprintf(stderr,
            "Ending inode number is too large (%" PRIuINUM ")", end_inum);

    for (inum = start_inum; inum <= end_inum; inum++) {
        int retval;

        /* read catalog file entry in to HFS_INFO */
        hfs_dinode_lookup(hfs, inum);

        fs_inode->flags = hfs->flags;

        /* copy into generic format */
        hfs_copy_inode(hfs, fs_inode);

        /* call action */
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
     * Cleamup.
     */
    tsk_fs_inode_free(fs_inode);

    return 0;
}


static uint8_t
hfs_fscheck(TSK_FS_INFO * fs, FILE * hFile)
{
    tsk_fprintf(stderr, "fscheck not implemented for HFS yet");
    return 0;
}


static uint8_t
hfs_fsstat(TSK_FS_INFO * fs, FILE * hFile)
{
    char *myname = "hfs_fsstat";
    HFS_INFO *hfs = (HFS_INFO *) fs;
    hfs_sb *sb = hfs->fs;
    time_t mac_time;

    if (tsk_verbose)
        tsk_fprintf(stderr, "hfs_fstat: called\n");

    tsk_fprintf(hFile, "FILE SYSTEM INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    tsk_fprintf(hFile, "File System Type: ");

    switch (tsk_getu16(fs->endian, hfs->fs->version)) {
    case 4:
        tsk_fprintf(hFile, "HFS+\n");
        break;
    case 5:
        tsk_fprintf(hFile, "HFSX\n");
        break;
    default:
        tsk_fprintf(stderr,
            "%s: HFS Version field incorrect in superblock\n", myname);
        break;
    }


    tsk_fprintf(hFile, "Number of files: %" PRIu32 "\n",
        tsk_getu32(fs->endian, sb->file_cnt));

    tsk_fprintf(hFile, "Number of folders: %" PRIu32 "\n",
        tsk_getu32(fs->endian, sb->fldr_cnt));

    mac_time = hfs2unixtime(tsk_getu32(fs->endian, hfs->fs->c_date));
    tsk_fprintf(hFile, "Created: %s", ctime(&mac_time));

    mac_time = hfs2unixtime(tsk_getu32(fs->endian, hfs->fs->m_date));
    tsk_fprintf(hFile, "Last Written at: %s", ctime(&mac_time));

    mac_time = hfs2unixtime(tsk_getu32(fs->endian, hfs->fs->chk_date));
    tsk_fprintf(hFile, "Last Checked at: %s", ctime(&mac_time));

    /* State of the file system */
    if (tsk_getu32(fs->endian, hfs->fs->attr) & HFS_BIT_VOLUME_UNMOUNTED)
        tsk_fprintf(hFile, "Volume Unmounted properly\n");
    else
        tsk_fprintf(hFile, "Volume Unmounted Improperly\n");

    /* Print journal information */
    if (tsk_getu32(fs->endian, sb->attr) & HFS_BIT_VOLUME_JOURNALED) {
        tsk_fprintf(hFile, "\nJournal Info Block: %" PRIu32 "\n",
            tsk_getu32(fs->endian, sb->jinfo_blk));
    }

    tsk_fprintf(hFile, "\nMETADATA INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    tsk_fprintf(hFile, "First Block of Catalog File: %" PRIu32 "\n",
        tsk_getu32(fs->endian, hfs->fs->cat_file.extents[0].start_blk));

    tsk_fprintf(hFile, "Range: %" PRIuINUM " - %" PRIuINUM "\n",
        fs->first_inum, fs->last_inum);


    tsk_fprintf(hFile, "\nCONTENT INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    tsk_fprintf(hFile, "Block Range: %" PRIuDADDR " - %" PRIuDADDR "\n",
        fs->first_block, fs->last_block);

    tsk_fprintf(hFile, "Allocation Block Size: %u\n", fs->block_size);

    tsk_fprintf(hFile, "Free Blocks: %" PRIu32 "\n",
        tsk_getu32(fs->endian, sb->free_blks));
    return 0;
}


/************************* istat *******************************/

#define HFS_PRINT_WIDTH 8
typedef struct {
    FILE *hFile;
    int idx;
} HFS_PRINT_ADDR;

static uint8_t
print_addr_act(TSK_FS_INFO * fs, DADDR_T addr, char *buf,
    size_t size, TSK_FS_BLOCK_FLAG_ENUM flags, void *ptr)
{
    HFS_PRINT_ADDR *print = (HFS_PRINT_ADDR *) ptr;
    tsk_fprintf(print->hFile, "%" PRIuDADDR " ", addr);

    if (++(print->idx) == HFS_PRINT_WIDTH) {
        tsk_fprintf(print->hFile, "\n");
        print->idx = 0;
    }

    return TSK_WALK_CONT;
}

uint8_t
hfs_istat(TSK_FS_INFO * fs, FILE * hFile, INUM_T inum, DADDR_T numblock,
    int32_t sec_skew)
{
    HFS_INFO *hfs = (HFS_INFO *) fs;
    TSK_FS_INODE *fs_inode;
    time_t mac_time;
    char hfs_mode[11];
    HFS_PRINT_ADDR print;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_istat: inum: %" PRIuINUM " numblock: %" PRIu32 "\n",
            inum, numblock);

    fs_inode = hfs_inode_lookup(fs, inum);

    tsk_fprintf(hFile, "\nINODE INFORMATION\n");
    tsk_fprintf(hFile, "Entry: %lu\n", (ULONG) inum);

    tsk_fprintf(hFile, "Type: ");

    if (tsk_getu16(fs->endian, hfs->cat->rec_type) == HFS_FILE_RECORD)
        tsk_fprintf(hFile, "File\n");

    if (tsk_getu16(fs->endian, hfs->cat->rec_type) == HFS_FOLDER_RECORD)
        tsk_fprintf(hFile, "Folder\n");

    tsk_fprintf(hFile, "Owner-ID: %d\n", tsk_getu32(fs->endian,
            hfs->cat->perm.owner));
    tsk_fprintf(hFile, "Group-ID: %d\n", tsk_getu32(fs->endian,
            hfs->cat->perm.group));

    tsk_fs_make_ls((mode_t) tsk_getu16(fs->endian, hfs->cat->perm.mode),
        hfs_mode);
    tsk_fprintf(hFile, "Mode: %s\n", hfs_mode);

    mac_time = hfs2unixtime(tsk_getu32(fs->endian, hfs->cat->ctime));
    tsk_fprintf(hFile, "\nCreated:             %s", ctime(&mac_time));

    mac_time = hfs2unixtime(tsk_getu32(fs->endian, hfs->cat->cmtime));
    tsk_fprintf(hFile, "Content Modified:    %s", ctime(&mac_time));

    mac_time = hfs2unixtime(tsk_getu32(fs->endian, hfs->cat->attr_mtime));
    tsk_fprintf(hFile, "Attributes Modified: %s", ctime(&mac_time));

    mac_time = hfs2unixtime(tsk_getu32(fs->endian, hfs->cat->atime));
    tsk_fprintf(hFile, "Accessed:            %s", ctime(&mac_time));

    mac_time = hfs2unixtime(tsk_getu32(fs->endian, hfs->cat->bkup_date));
    tsk_fprintf(hFile, "Backed up:           %s\n", ctime(&mac_time));

    print.idx = 0;
    print.hFile = hFile;

    fs->file_walk(fs, fs_inode, 0, 0,
        (TSK_FS_FILE_FLAG_AONLY | TSK_FS_FILE_FLAG_META |
            TSK_FS_FILE_FLAG_NOID), print_addr_act, (void *) &print);

    if (print.idx != 0)
        tsk_fprintf(hFile, "\n");

    return 0;
}


static void
hfs_close(TSK_FS_INFO * fs)
{
    HFS_INFO *hfs = (HFS_INFO *) fs;

    free((char *) hfs->cat);
    free((char *) hfs->fs);
    free((char *) hfs->inodes);
    free(hfs);
}

/* hfs_open - open an hfs file system 
 *
 * Return NULL on error (or not an HFS or HFS+ file system)
 * */

TSK_FS_INFO *
hfs_open(TSK_IMG_INFO * img_info, SSIZE_T offset,
    TSK_FS_INFO_TYPE_ENUM ftype, uint8_t test)
{
    HFS_INFO *hfs;
    unsigned int len;
    TSK_FS_INFO *fs;
    SSIZE_T cnt;

    if ((ftype & TSK_FS_INFO_TYPE_FS_MASK) != TSK_FS_INFO_TYPE_HFS_TYPE) {
        tsk_errno = TSK_ERR_FS_ARG;
        snprintf(tsk_errstr, TSK_ERRSTR_L, "Invalid FS Type in hfs_open");
        tsk_errstr2[0] = '\0';
        return NULL;
    }

    if ((hfs = (HFS_INFO *) tsk_malloc(sizeof(HFS_INFO))) == NULL)
        return NULL;

    fs = &(hfs->fs_info);

    fs->ftype = ftype;
    fs->flags = 0;

    /*
     * Read the superblock.
     */
    fs->img_info = img_info;
    fs->offset = offset;
    len = sizeof(hfs_sb);
    if ((hfs->fs = (hfs_sb *) tsk_malloc(len)) == NULL) {
        free(hfs);
        return NULL;
    }

    cnt = tsk_fs_read_random(fs, (char *) hfs->fs, len, (OFF_T) HFS_SBOFF);
    if (cnt != len) {
        if (cnt != -1) {
            tsk_errno = TSK_ERR_FS_READ;
            tsk_errstr[0] = '\0';
        }
        snprintf(tsk_errstr2, TSK_ERRSTR_L, "hfs_open: superblock");
        free(hfs->fs);
        free(hfs);
        return NULL;
    }


    /*
     * Verify we are looking at an HFS+ image
     */
    if (tsk_fs_guessu16(fs, hfs->fs->signature, HFSPLUS_MAGIC)) {
        free(hfs->fs);
        free(hfs);
        tsk_errno = TSK_ERR_FS_MAGIC;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "not an HFS+ file system (magic)");
        tsk_errstr2[0] = '\0';
        return NULL;
    }

    fs->block_count = tsk_getu32(fs->endian, hfs->fs->blk_cnt);
    fs->first_block = 0;
    fs->last_block = fs->block_count - 1;

    fs->dev_bsize = fs->block_size =
        tsk_getu32(fs->endian, hfs->fs->blk_sz);

    /*
     * Other initialization: caches, callbacks.
     */
    fs->inode_walk = hfs_inode_walk;
    fs->block_walk = hfs_block_walk;
    fs->inode_lookup = hfs_inode_lookup;
    fs->dent_walk = hfs_dent_walk;
    fs->file_walk = hfs_file_walk;
    fs->fsstat = hfs_fsstat;
    fs->fscheck = hfs_fscheck;
    fs->istat = hfs_istat;
    fs->close = hfs_close;

    hfs_blockmap_build(hfs);
    hfs->hdr = (hfs_btree_header_record *) NULL;
    hfs_catalog_get_header(hfs);
    hfs_leafmap_build(hfs);
    hfs_deleted_map_build(hfs);

    fs->first_inum = HFS_ROOT_INUM;
    fs->root_inum = HFS_ROOT_INUM;
    fs->last_inum = hfs_find_highest_inum(hfs);
    hfs->inodes = (htsk_fs_inode_mode_struct *)
        tsk_malloc((fs->last_inum +
            1) * sizeof(htsk_fs_inode_mode_struct));
    memset(hfs->inodes, 0,
        (fs->last_inum + 1) * sizeof(htsk_fs_inode_mode_struct));
    hfs_load_inode_list(hfs);

    /*
     * Inode
     */


    /* journal */
    fs->jblk_walk = hfs_jblk_walk;
    fs->jentry_walk = hfs_jentry_walk;
    fs->jopen = hfs_jopen;

    /* allocate buffers */

    /* dinode */

    /* allocate the buffer to hold catalog file entries */
    hfs->cat = (hfs_file *) tsk_malloc(sizeof(hfs_file));
    hfs->inum = -1;

    return fs;
}
