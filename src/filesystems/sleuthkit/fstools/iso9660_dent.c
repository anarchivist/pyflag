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

#include "fs_tools.h"
#include "iso9660.h"
#include "mymalloc.h"
#include "error.h"

static unsigned int depth = 0;

#define DIR_STRSZ	2048
static char dirs[DIR_STRSZ];
#define MAX_DEPTH	64
static char *didx[MAX_DEPTH];

/* iso9660_dent_walk - walk directory entries starting with inode 'inum'.
 *	flags - FS_FLAG_NAME_RECURSE
 */
void
iso9660_dent_walk(FS_INFO * fs, INUM_T inum, int flags,
		  FS_DENT_WALK_FN action, void *ptr)
{
    ISO_INFO *iso = (ISO_INFO *) fs;
    FS_DENT *fs_dent = fs_dent_alloc(ISO9660_MAXNAMLEN, 0);
    int myflags = FS_FLAG_META_LINK;
    char *buf;			/* temp storage for directory extent */
    int length = 0;		/* size of directory extent */
    iso9660_dentry *dd;		/* directory descriptor */
    in_node *in;
    off_t offs;			/* where we are reading in the file */

    if (inum < fs->first_inum || inum > fs->last_inum)
	error("invalid inode value: %i\n", inum);

    if (verbose)
	fprintf(stderr, "iso9660_dent_walk: Processing directory %lu\n",
		(ULONG) inum);
    iso9660_dinode_load(iso, inum);

    /* walking a directory */
    if ((iso->dinode->dr.flags & ISO9660_FLAG_DIR) == ISO9660_FLAG_DIR) {
	/* calculate directory extent location */
	offs =
	    (off_t) (fs->block_size *
		     parseu32(fs, iso->dinode->dr.ext_loc));

	/* read directory extent into memory */
	length = parseu32(fs, iso->dinode->dr.data_len);

	buf = mymalloc(length);
	fs_read_random(fs, buf, length, offs);
	dd = (iso9660_dentry *) buf;

	/* handle "." entry */
	fs_dent->inode = inum;
	strcpy(fs_dent->name, ".");

	fs_dent->path = dirs;
	fs_dent->pathdepth = depth;
	fs_dent->fsi = fs->inode_lookup(fs, fs_dent->inode);
	fs_dent->ent_type = FS_DENT_DIR;

	if (WALK_STOP == action(fs, fs_dent, myflags, ptr)) {
	    fs_dent_free(fs_dent);
	    return;
	}

	length -= dd->length;

	dd = (iso9660_dentry *) ((char *) dd + dd->length);

	/* handle ".." entry */
	in = iso->in;

	while (in
	       && (parseu32(fs, in->inode.dr.ext_loc) !=
		   parseu32(fs, dd->ext_loc)))
	    in = in->next;

	fs_dent->inode = in->inum;
	strcpy(fs_dent->name, "..");

	fs_dent->path = dirs;
	fs_dent->pathdepth = depth;
	fs_dent->fsi = fs->inode_lookup(fs, fs_dent->inode);
	fs_dent->ent_type = FS_DENT_DIR;

	if (WALK_STOP == action(fs, fs_dent, myflags, ptr)) {
	    fs_dent_free(fs_dent);
	    return;
	}


	length -= dd->length;

	dd = (iso9660_dentry *) ((char *) dd + dd->length);

	/* for each directory descriptor in it: */
	while (length > sizeof(iso9660_dentry)) {
	    if (dd->length) {
		/* print out info on what was in extent */
		in = iso->in;
		while (parseu32(fs, in->inode.dr.ext_loc) !=
		       parseu32(fs, dd->ext_loc))
		    in = in->next;

		fs_dent->inode = in->inum;
		strcpy(fs_dent->name, in->inode.fn);

		fs_dent->path = dirs;
		fs_dent->pathdepth = depth;
		fs_dent->fsi = fs->inode_lookup(fs, fs_dent->inode);
		if (dd->flags & ISO9660_FLAG_DIR)
		    fs_dent->ent_type = FS_DENT_DIR;
		else
		    fs_dent->ent_type = FS_DENT_REG;

		if (WALK_STOP == action(fs, fs_dent, myflags, ptr)) {
		    fs_dent_free(fs_dent);
		    return;
		}

		if ((dd->flags & ISO9660_FLAG_DIR)
		    && (flags & FS_FLAG_NAME_RECURSE)) {
		    if (depth < MAX_DEPTH) {
			didx[depth] = &dirs[strlen(dirs)];
			strncpy(didx[depth], fs_dent->name,
				DIR_STRSZ - strlen(dirs));
			strncat(dirs, "/", DIR_STRSZ);
		    }
		    depth++;
		    iso9660_dent_walk(fs, in->inum, flags, action, ptr);
		    depth--;
		    if (depth < MAX_DEPTH)
			*didx[depth] = '\0';
		}

		length -= dd->length;

		dd = (iso9660_dentry *) ((char *) dd + dd->length);
		/* we need to look for files past the next NULL we discover, in case
		 * directory has a hole in it (this is common) */
	    }
	    else {
		char *a, *b;
		length -= sizeof(iso9660_dentry);

		/* find next non-zero byte and we'll start over there */

		a = (char *) dd;
		b = a + sizeof(iso9660_dentry);

		while ((*a == 0) && (a != b))
		    a++;

		if (a != b) {
		    length += (int) (b - a);
		    dd = (iso9660_dentry *) ((char *) dd +
					     (sizeof(iso9660_dentry) -
					      (int) (b - a)));
		}
	    }
	}

	free(buf);
	/* regular file */
    }
    else {
	fs_dent->inode = inum;
	iso9660_dinode_load(iso, inum);
	strcpy(fs_dent->name, iso->dinode->fn);

	fs_dent->path = dirs;
	fs_dent->pathdepth = depth;
	fs_dent->fsi = fs->inode_lookup(fs, fs_dent->inode);
	fs_dent->ent_type = FS_DENT_REG;

	if (WALK_STOP == action(fs, fs_dent, myflags, ptr)) {
	    fs_dent_free(fs_dent);
	    return;
	}
    }
}
