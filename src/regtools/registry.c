/*
 * This file is part of PyFlag $Version: 0.84RC1 Date: Fri Feb  9 08:22:13 EST 2007$
 * registry.c - registry access routines for regedit (regutils package)
 * Copyright (C) 1998 Memorial University of Newfoundland
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "registry.h"
#include "regformat.h"
#include "misc.h"

extern char *progname;
extern int warnings;

struct key_section {
    struct rgdb_header header;
    struct key_entry key[255];
};

static struct key_section *load_section(Registry *r, int n);
static char *load_string(char *buf, int buf_i, int buf_n, int len);
static int registry_write(Registry *);
static void registry_delete(Registry *r);
static void section_delete(struct key_section *sect);
static u_int checksum(void *area, u_int length);

#define kn_header(r) ((struct rgkn_header *) (r)->rgkn)
#define kn_entry(r, offset) ((struct rgkn_key *) ((r)->rgkn + (offset)))
/* Can't check if offset is multiple of struct size - doesn't have to be */
#define kn_is_valid_offset(r, offset) \
			((offset) >= sizeof(struct rgkn_header) \
			 && (offset) <= (r)->last_rgkn_offset)
#define db_entry(r, kn) (&((r)->rgdb[(kn)->rgdb]->key[(kn)->id]))


Registry *
registry_open(const char *filename, int verbose)
{
    Registry *r;
    struct rgkn_header kn_header;
    int i, nfree;
    int nread;
    int bleft;

    r = (Registry *) xmalloc(sizeof(Registry));
    memset(r, 0, sizeof *r);
    r->verbose = verbose;

    if (strcmp(filename, "-") == 0)
	r->fp = stdin;
    else if ((r->fp = fopen(filename, "r")) == NULL) {
	fprintf(stderr, "%s: can't open %s - %s\n",
		progname, filename, strerror(errno));
	registry_delete(r);
	return NULL;
    }
    r->modified = 0;
    r->name = xstrdup(filename);
    r->header = (struct reg_header *) xmalloc(sizeof *r->header);
    nread = fread(r->header, sizeof *r->header, 1, r->fp);
    if (nread != 1 || r->header->magic != REG_HEADER_MAGIC) {
	fprintf(stderr, "%s: %s: not in registry format\n", progname, filename);
	registry_delete(r);
	return NULL;
    }
    if (verbose) {
	fprintf(stderr, "loading CREG section:\n");
	fprintf(stderr, "\tflags=0x%x, nrgdb=%d, rgdb offset=0x%x, csum=0x%x\n",
	    r->header->flags,
	    r->header->nrgdb,
	    r->header->rgdb_offset,
	    r->header->csum);
	fprintf(stderr, "\tuk4l=0x%x, uk20l=0x%x, uk24l=0x%x, uk28l=0x%x\n",
	    r->header->uk4l,
	    r->header->uk20l,
	    r->header->uk24l,
	    r->header->uk28l);
    }
    if (warnings
        && (r->header->uk4l != 0x10000
	    || (r->header->flags != 0x5 && r->header->flags != 0x4
		&& r->header->flags != 0x0 && r->header->flags != 0x1)
	    || (r->header->uk20l != 0x10000
		&& r->header->uk20l != 0x800000)
	    || r->header->uk24l != 0
	    || r->header->uk28l != 0))
    {
	fprintf(stderr, "%s: %s: Warning: unexpected values in CREG header\n",
		progname, filename);
	if (r->header->uk4l != 0x10000)
	    fprintf(stderr, "\tat offset 4 long: 0x%x\n", r->header->uk4l);
	if (r->header->flags != 0x5 && r->header->flags != 0x4
	    && r->header->flags != 0x0 && r->header->flags != 0x1)
	    fprintf(stderr, "\tat offset 18 short: 0x%x (flags)\n",
		r->header->flags);
	if (r->header->uk20l != 0x10000
	    && r->header->uk20l != 0x800000)
	    fprintf(stderr, "\tat offset 20 long: 0x%x\n", r->header->uk20l);
	if (r->header->uk24l != 0)
	    fprintf(stderr, "\tat offset 24 long: 0x%x\n", r->header->uk24l);
	if (r->header->uk28l != 0)
	    fprintf(stderr, "\tat offset 28 long: 0x%x\n", r->header->uk28l);
    }
    if (warnings
	&& ((r->header->flags & REG_FLAG_CSUMVALID)
	    && checksum(r->header, sizeof *r->header) != 0))
    {
	fprintf(stderr, "%s: %s: Warning: bad checksum in CREG header (%x)\n",
		progname, filename, r->header->csum);
    }


    /*
     * Read RGKN section (key index table)
     */
    nread = fread(&kn_header, sizeof kn_header, 1, r->fp);
    if (nread != 1 || kn_header.magic != RGKN_HEADER_MAGIC) {
	fprintf(stderr, "%s: %s: bad RGKN section\n", progname, filename);
	registry_delete(r);
	return NULL;
    }
    r->rgkn = (char *) xmalloc(kn_header.size);
    memcpy(r->rgkn, &kn_header, sizeof kn_header);
    nread = fread(&r->rgkn[sizeof kn_header],
		  kn_header.size - sizeof kn_header, 1, r->fp);
    if (nread != 1) {
	fprintf(stderr, "%s: %s: couldn't read RGKN data\n",
	    progname, filename);
	registry_delete(r);
	return NULL;
    }
    if (verbose) {
	fprintf(stderr, "loading RGKN section:\n");
	fprintf(stderr,
	    "\tflags=0x%x, size=0x%x, root offset=0x%x, free offset=0x%x\n",
	    kn_header.flags,
	    kn_header.size,
	    kn_header.root_offset,
	    kn_header.free_offset);
	fprintf(stderr, "\tcsum=0x%x, uk24l=0x%x, uk28l=0x%x\n",
	    kn_header.csum,
	    kn_header.uk24l,
	    kn_header.uk28l);
    }
    if (warnings
	&& (kn_header.root_offset < sizeof kn_header
	    || kn_header.root_offset >= kn_header.size
	    || kn_header.free_offset < sizeof kn_header
	    || kn_header.free_offset >= kn_header.size
	    || (kn_header.flags != 0xd && kn_header.flags != 0x9
		&& kn_header.flags != 0xc && kn_header.flags != 0xf)
	    || kn_header.uk24l != 0
	    || kn_header.uk28l != 0))
    {
	fprintf(stderr, "%s: %s: Warning: unexpected values in RGKN header\n",
		progname, filename);
	if (kn_header.root_offset < sizeof kn_header
	    || kn_header.root_offset >= kn_header.size)
	    fprintf(stderr, "\tat offset 8 long: 0x%x (root offset)\n",
		kn_header.root_offset);
	if (kn_header.free_offset < sizeof kn_header
	    || kn_header.free_offset >= kn_header.size)
	    fprintf(stderr, "\tat offset 12 long: 0x%x (free offset)\n",
		kn_header.free_offset);
	if (kn_header.flags != 0xd && kn_header.flags != 0x9
	    && kn_header.flags != 0xc && kn_header.flags != 0xf)
	    fprintf(stderr, "\tat offset 16 long: 0x%x (flags)\n",
		kn_header.flags);
	if (kn_header.uk24l != 0)
	    fprintf(stderr, "\tat offset 24 long: 0x%x\n", kn_header.uk24l);
	if (kn_header.uk28l != 0)
	    fprintf(stderr, "\tat offset 28 long: 0x%x\n", kn_header.uk28l);
    }
    if (warnings
	&& ((kn_header.flags & REG_FLAG_CSUMVALID)
	    && checksum(r->rgkn, kn_header.size) != 0))
    {
	fprintf(stderr, "%s: %s: Warning: bad checksum in RGKN header (%x)\n",
		progname, filename, kn_header.csum);
    }

    r->last_rgkn_offset = kn_header.size
		- (kn_header.size - sizeof kn_header) % sizeof(struct rgkn_key)
		- sizeof(struct rgkn_key);
    nfree = 0;
    bleft = RGKN_INIT_SIZE - sizeof kn_header;
    for (i = sizeof kn_header; i <= r->last_rgkn_offset;) {
	struct rgkn_key *kn = kn_entry(r, i);

	if (nfree > 0) {
	    --nfree;
	} else if (kn->inuse == 0) {
	    if (warnings
		&& ((kn->parent != 0xffffffff && !kn_is_valid_offset(r, kn->parent))
		    || (kn->child != 0xffffffff && !kn_is_valid_offset(r, kn->child))
		    || (kn->next != 0xffffffff && !kn_is_valid_offset(r, kn->next))
		    || kn->id > 254
		    || kn->rgdb > r->header->nrgdb))
	    {
		fprintf(stderr,
			"%s: %s: Warning: bad inuse key in RGKN at offset %x\n",
			progname, filename, i);
		if (kn->parent != 0xffffffff
		    && !kn_is_valid_offset(r, kn->parent))
		    fprintf(stderr, "\tat offset 12 long: 0x%x (parent)\n",
			kn->parent);
		if (kn->child != 0xffffffff
		    && !kn_is_valid_offset(r, kn->child))
		    fprintf(stderr, "\tat offset 16 long: 0x%x (child)\n",
			kn->child);
		if (kn->next != 0xffffffff
		    && !kn_is_valid_offset(r, kn->next))
		    fprintf(stderr, "\tat offset 20 long: 0x%x (next)\n",
			kn->next);
		if (kn->id > 254)
		    fprintf(stderr, "\tat offset 24 short: 0x%x (id)\n",
			kn->id);
		if (kn->rgdb > r->header->nrgdb)
		    fprintf(stderr, "\tat offset 26 short: 0x%x (rgdb section, nrgdb %d)\n",
			kn->rgdb, r->header->nrgdb);
	    }
	} else if (kn->inuse == FREE_SLOT) {
	    if (warnings
		&& ((kn->next_free != 0xffffffff
		     && !kn_is_valid_offset(r, kn->next_free))
		    || kn->hash < sizeof *kn || kn->hash + i > kn_header.size))
	    {
		fprintf(stderr,
			"%s: %s: Warning: bad free key in RGKN at offset %x\n",
			progname, filename, i);
		if (kn->next_free != 0xffffffff
		    && !kn_is_valid_offset(r, kn->next_free))
		    fprintf(stderr, "\tat offset 8 long: 0x%x (next free)\n",
			kn->next_free);
		if (kn->hash < sizeof *kn || kn->hash + i > kn_header.size)
		    fprintf(stderr, "\tat offset 4 long: 0x%x (hash/free size)\n",
			kn->hash);
	    }
	    nfree = kn->hash / sizeof *kn - 1;
	} else {
	    if (warnings) {
		fprintf(stderr,
			"%s: %s: Warning: bad key in RGKN at offset %x\n",
			progname, filename, i);
		fprintf(stderr, "\tat offset 0 long: 0x%x (flags)\n",
			kn->inuse);
	    }
	}
	bleft -= sizeof(struct rgkn_key);
	if (bleft < sizeof(struct rgkn_key)) {
	    i += bleft;
	    bleft = RGKN_INCR_SIZE;
	}
	i += sizeof(struct rgkn_key);
    }
    /*
     * XXX Not checked
     *	- offsets to key table don't overlap
     *	- id within rgdb section are valid
     *	- child/parent relationship matches
     */


    /*
     * Read RGDB sections
     */
    r->avail_db = r->header->nrgdb;
    r->rgdb = (struct key_section **)
	xmalloc(sizeof(*r->rgdb) * r->header->nrgdb);
    memset(r->rgdb, 0, sizeof(*r->rgdb) * r->header->nrgdb);
    for (i = 0; i < r->header->nrgdb; i++) {
	struct key_section *sect = load_section(r, i);
	if (sect == NULL) {
	    registry_delete(r);
	    return NULL;
	}
	if (sect->header.first_free_id < 255)
	    r->avail_db = sect->header.section;
	r->rgdb[sect->header.section] = sect;
    }
    return r;
}

void
registry_rename(Registry *r, const char *filename)
{
    free(r->name);
    r->name = xstrdup(filename);
}

static void
free_entry(struct key_entry *entry)
{
    int i;

    free(entry->name);
    entry->name = NULL;
    if (entry->nvalues != 0) {
	for (i = 0; i < entry->nvalues; i++) {
	    RegistryValue *v = &entry->value[i];
	    if (v->name != NULL) {
		free(v->name);
		if (v->data)
		    free(v->data);
	    }
	}
	free(entry->value);
    }
}

int
registry_close(Registry *r)
{
    int ret = 1;
    fclose(r->fp);
    r->fp = 0;
    if (r->modified)
	ret = registry_write(r);
    registry_delete(r);
    return ret;
}

static void
registry_delete(Registry *r)
{
    if (r == 0)
	return;

    if (r->fp)
	fclose(r->fp);
    if (r->name)
	free(r->name);
    if (r->rgkn)
	free(r->rgkn);

    if (r->rgdb != 0) {
	int i;

	for (i = 0; i < r->header->nrgdb; i++)
	    section_delete(r->rgdb[i]);
	free(r->rgdb);
    }

    if (r->header)
	free(r->header);

    free(r);
}

static void
section_delete(struct key_section *sect)
{
    if (sect) {
	int j;

	for (j = 0; j < 255; j++) {
	    struct key_entry *entry = &sect->key[j];
	    if (entry->name != NULL)
		free_entry(entry);
	}
	free(sect);
    }
}

static struct key_section *
load_section(Registry *r, int n)
{
    FILE *fp = r->fp;
    struct key_section *sect;
    char *buf;
    int buf_i, buf_n;
    int offset;
    int usedsize;
    int nread;
    long xxx_unused = 0;

    sect = (struct key_section *) xmalloc(sizeof *sect);
    memset(sect, 0, sizeof *sect);
    nread = fread(&sect->header, sizeof sect->header, 1, fp);
    if (nread != 1 || sect->header.magic != RGDB_HEADER_MAGIC) {
	fprintf(stderr, "%s: %s: unable to read RGDB section %d\n",
		progname, r->name, n);
	free(sect);
	return 0;
    }
    if (warnings
	&& (sect->header.unused_size > sect->header.size
	    || (sect->header.flags != 0x9
		&& sect->header.flags != 0xb && sect->header.flags != 0xc
		&& sect->header.flags != 0xd && sect->header.flags != 0xf)
	    || (sect->header.free_offset != 0xffffffff
		&& (sect->header.free_offset < sizeof sect->header
		    || sect->header.free_offset > sect->header.size))
	    || sect->header.section != n
	    || sect->header.max_id > 255
	    || sect->header.first_free_id > 255))
    {
	fprintf(stderr, "%s: %s: Warning: unexpected values in RGDB header %d\n",
		progname, r->name, n);
	if (sect->header.unused_size > sect->header.size)
	    fprintf(stderr, "\tat offset 8 long: 0x%x (unused size)\n",
		sect->header.unused_size);
	if (sect->header.flags != 0x9
	    && sect->header.flags != 0xb && sect->header.flags != 0xc
	    && sect->header.flags != 0xd && sect->header.flags != 0xf)
	    fprintf(stderr, "\tat offset 12 short: 0x%x (flags)\n",
		sect->header.flags);
	if (sect->header.free_offset != 0xffffffff
	    && (sect->header.free_offset < sizeof sect->header
		|| sect->header.free_offset > sect->header.size))
	    fprintf(stderr, "\tat offset 16 long: 0x%x (free offset)\n",
		sect->header.free_offset);
	if (sect->header.section != n)
	    fprintf(stderr, "\tat offset 14 short: 0x%x (section, expected %d)\n",
		sect->header.section, n);
	if (sect->header.max_id > 255)
	    fprintf(stderr, "\tat offset 20 short: 0x%x (max id)\n",
		sect->header.max_id);
	if (sect->header.first_free_id > 255)
	    fprintf(stderr, "\tat offset 22 short: 0x%x (first free id)\n",
		sect->header.first_free_id);
    }
    buf = (char *) xmalloc(buf_n = sect->header.size);
    buf_i = sizeof sect->header;
    memcpy(buf, &sect->header, sizeof sect->header);
    nread = fread(buf + sizeof sect->header, 1,
		  sect->header.size - sizeof sect->header, r->fp);
    if (nread != sect->header.size - sizeof sect->header) {
	fprintf(stderr, "%s: %s: unable to read data in RGDB section %d\n",
		progname, r->name, n);
	free(buf);
	free(sect);
	return 0;
    }
    if (warnings
	&& ((sect->header.flags & REG_FLAG_CSUMVALID)
	    && checksum(buf, sect->header.size) != 0))
    {
	fprintf(stderr,
	    "%s: %s: Warning: bad checksum in RGDB header %d (%x)\n",
	    progname, r->name, n, sect->header.csum);
    }

    offset = sizeof sect->header;
    /*
     * For win95, either
     *    size - unused_size == free_offset
     * or
     *    free_offset == -1 && unused_size == 0
     * For win98, unused_size is smaller than it should be.
     * (haven't looked at win98 much yet, so don't know how variable it is)
     * From  Jeff Muizelaar (muizelaar at rogers.com):
     *    It appears that free_offset can point to any place in the 
     *    RGDB section where there is free space instead of the end
     *    of the used area.
     */
    usedsize = sect->header.size - sect->header.unused_size;
    if ((sect->header.free_offset == 0xffffffff
	 && sect->header.unused_size != 0)
	|| (sect->header.free_offset != 0xffffffff
	    && sect->header.free_offset > sect->header.size))
    {
	fprintf(stderr,
	    "%s: %s: RGDB section %d bad: size %x, unused %x, free_offset %x\n",
		progname, r->name, n,
		sect->header.size, sect->header.unused_size,
		sect->header.free_offset);
	free(buf);
	free(sect);
	return 0;
    }
    if (r->verbose) {
	fprintf(stderr, "loading RGDB section %d:\n",
	    sect->header.section);
	fprintf(stderr,
	    "\tflags=0x%x, csum=0x%x, size=0x%x, unused size=0x%x\n",
	    sect->header.flags,
	    sect->header.csum,
	    sect->header.size,
	    sect->header.unused_size);
	fprintf(stderr,
	    "\tfree offset=0x%x, max id=%d, first free id=%d, uk24l=0x%x\n",
	    sect->header.free_offset,
	    sect->header.max_id,
	    sect->header.first_free_id,
	    sect->header.uk24l);
    }
    /* "+ xxx_unused" from Jeff Muizelaar. */
    while (offset < usedsize + xxx_unused) {
	struct rgdb_key rk;
	struct rgdb_value rv;
	struct key_entry *k;
	RegistryValue *v;
	int i;

	if (buf_i + sizeof rk > buf_n) {
	    fprintf(stderr, "%s: %s: RGDB section %d bad: can't read key\n",
		progname, r->name, n);
	    free(buf);
	    section_delete(sect);
	    return 0;
	}
	memcpy(&rk, buf + buf_i, sizeof rk);
	if (warnings
	    && (rk.size < sizeof rk || rk.size > buf_n - buf_i
		|| (rk.rgdb != n && (rk.rgdb != 0xffff || rk.id != 0xffff))
		|| rk.used_size < sizeof rk || rk.used_size > rk.size
		|| rk.name_len > rk.used_size
		|| rk.uk16l != 0))
	{
	    fprintf(stderr,
	"%s: %s: Warning: unexpected values in key header of RGDB section %d\n",
		    progname, r->name, n);
	    if (rk.size < sizeof rk || rk.size > buf_n - buf_i)
		fprintf(stderr, "\tat offset 0 long: 0x%x (record size)\n",
		    rk.size);
	    if (rk.rgdb != n && (rk.rgdb != 0xffff || rk.id != 0xffff))
		fprintf(stderr,
		    "\tat offset 6 short: 0x%x (section, expected %d)\n",
		    rk.rgdb, n);
	    if (rk.used_size < sizeof rk || rk.used_size > rk.size)
		fprintf(stderr, "\tat offset 8 long: 0x%x (used size)\n",
		    rk.used_size);
	    if (rk.name_len > rk.used_size)
		fprintf(stderr, "\tat offset 12 short: 0x%x (id)\n", rk.name_len);
	    if (rk.uk16l != 0)
		fprintf(stderr, "\tat offset 16 long: 0x%x\n", rk.uk16l);
	}

	/* This key is not used (win98ism) - just skip it. */
	if (rk.id == 0xffff && rk.rgdb == 0xffff) {
	    if (r->verbose) {
		fprintf(stderr,
		    "  %06x: skipping empty entry, size %d (uk16l %x)\n",
		    offset, rk.size, rk.uk16l);
	    }
	    buf_i += rk.size;
	    offset += rk.size;
	    xxx_unused += rk.size;
	    continue;
	}

	buf_i += sizeof rk;

	if (rk.id > 254) {
	    fprintf(stderr, "%s: %s: RGDB section %d bad: key id too big: %d\n",
		progname, r->name, n, rk.id);
	    free(buf);
	    section_delete(sect);
	    return 0;
	}
	k = &sect->key[rk.id];
	if (k->name) {
	    fprintf(stderr,
		"%s: %s: RGDB section %d bad: key id %d already in use\n",
		progname, r->name, n, rk.id);
	    free(buf);
	    section_delete(sect);
	    return 0;
	}

	k->name = load_string(buf, buf_i, buf_n, rk.name_len);
	if (!k->name) {
	    fprintf(stderr,
		"%s: %s: RGDB section %d bad: can't read key name\n",
		progname, r->name, n);
	    free(buf);
	    section_delete(sect);
	    return 0;
	}
	buf_i += rk.name_len;
	k->namelen = rk.name_len;
	k->nvalues = rk.nvalues;
	if (r->verbose) {
	    fprintf(stderr,
		"  %06x: loading key %d [%s], %d values (uses %d/%d) uk16l %x\n",
		offset, rk.id, k->name, k->nvalues, rk.used_size, rk.size,
		rk.uk16l);
	}
	if (rk.nvalues != 0)
	    k->value = (RegistryValue *)
			    xmalloc(sizeof(RegistryValue) * rk.nvalues);
	for (i = 0; i < rk.nvalues; i++) {
	    v = &k->value[i];
	    if (buf_i + sizeof rv > buf_n) {
		fprintf(stderr,
		    "%s: %s: RGDB section %d bad: can't read entry\n",
		    progname, r->name, n);
		free(buf);
		section_delete(sect);
		return 0;
	    }
	    memcpy(&rv, buf + buf_i, sizeof rv);
	    buf_i += sizeof(rv);
	    if (warnings
		&& ((rv.type != STRING_VALUE
		     && rv.type != HEX_VALUE
		     && rv.type != DWORD_VALUE
		     && rv.type != STRINGZ_VALUE
		     && rv.type != USTRINGZ_VALUE
		     /* Other values that have been seen */
		     && rv.type != 0x0		/* corel8, msoffice8 */
		     && rv.type != 0x80000001	/* corel8 */
		     && rv.type != 0x80000002	/* corel8 */
		     && rv.type != 0x80000007	/* corel8 */
		     && rv.type != 0x80000009	/* corel8 */
		     && rv.type != 0x8000000b	/* corel8 */
		     && rv.type != 0x7		/* corel8 */
			)
		    || (rv.type == DWORD_VALUE && rv.data_len != 4)
		       /* win95: uk4l == 0; win98: uk4l == 0, -1, anything? */
		    || (rv.uk4l != 0 && rv.uk4l != 0xffffffff)
		    || rv.name_len > buf_n - buf_i
		    || rv.data_len > buf_n - buf_i))
	    {
		fprintf(stderr,
    "%s: %s: Warning: unexpected values in entry header of RGDB section %d\n",
			progname, r->name, n);
		if (rv.type != STRING_VALUE
		    && rv.type != HEX_VALUE
		    && rv.type != DWORD_VALUE
		    && rv.type != STRINGZ_VALUE
		    && rv.type != USTRINGZ_VALUE
		    /* Other values that have been seen */
		    && rv.type != 0x0		/* corel8, ms office8 */
		    && rv.type != 0x80000001	/* corel8 */
		    && rv.type != 0x80000002	/* corel8 */
		    && rv.type != 0x80000007	/* corel8 */
		    && rv.type != 0x80000009	/* corel8 */
		    && rv.type != 0x8000000b	/* corel8 */
		    && rv.type != 0x7		/* corel8 */
		    )
		    fprintf(stderr, "\tat offset 0 short: 0x%x (entry type)\n",
			rv.type);
		if (rv.type == DWORD_VALUE && rv.data_len != 4)
		    fprintf(stderr,
			"\tdword type, but data len not 4 (is %d)\n",
			rv.data_len);
		if (rv.uk4l != 0 && rv.uk4l != 0xffffffff)
		    fprintf(stderr, "\tat offset 4 long: 0x%x\n", rv.uk4l);
		if (rv.name_len > buf_n - buf_i)
		    fprintf(stderr, "\tat offset 8 short: 0x%x (name len)\n",
			rv.name_len);
		if (rv.data_len > buf_n - buf_i)
		    fprintf(stderr, "\tat offset 10 short: 0x%x (value len)\n",
			rv.data_len);
	    }
	    v->type = rv.type;
	    v->namelen = rv.name_len;
	    v->name = load_string(buf, buf_i, buf_n, rv.name_len);
	    if (!v->name) {
		fprintf(stderr,
		    "%s: %s: RGDB section %d bad: can't read entry name\n",
		    progname, r->name, n);
		free(buf);
		section_delete(sect);
		return 0;
	    }
	    buf_i += rv.name_len;
	    v->datalen = rv.data_len;
	    v->data = load_string(buf, buf_i, buf_n, rv.data_len);
	    if (!v->data) {
		fprintf(stderr,
		    "%s: %s: RGDB section %d bad: can't read entry data\n",
		    progname, r->name, n);
		free(buf);
		section_delete(sect);
		return 0;
	    }
	    buf_i += rv.data_len;
	    if (r->verbose) {
		fprintf(stderr, "    loading value \"%s\"=", v->name);
		if (v->type == STRING_VALUE)
		    fprintf(stderr, "\"%s\"\n", v->data);
		else if (v->type == DWORD_VALUE) {
		    int l;
		    memcpy(&l, v->data, sizeof(int));
		    fprintf(stderr, "dword:%08x\n", l);
		} else if (v->type == HEX_VALUE)
		    fprintf(stderr, "... (len %d)\n", v->datalen);
		else
		    fprintf(stderr, "??? (len %d)\n", v->datalen);
	    }
	}
	offset += rk.size;
	if (buf_i + rk.size - rk.used_size > buf_n) {
	    fprintf(stderr,
		"%s: %s: RGDB section %d bad: unused area too big\n",
		progname, r->name, n);
	    free(buf);
	    section_delete(sect);
	    return 0;
	}
	buf_i += rk.size - rk.used_size;
    }

    /* looking at w96 registries...
    if (xxx_unused || sect->header.size - sect->header.free_offset
			!= sect->header.unused_size)
	fprintf(stderr, "XXX section %d: flags %x, size %d, unused %d, free %d   xxx %ld  sens %c\n",
	    sect->header.section, 
	    sect->header.flags, 
	    sect->header.size,
	    sect->header.unused_size,
	    sect->header.free_offset,
	    xxx_unused,
	    sect->header.size - sect->header.free_offset + xxx_unused
	    == sect->header.unused_size ? 'y' : 'n'
	    );
    */

    free(buf);
    /* "+ xxx_unused" from Jeff Muizelaar. */
    if (offset != usedsize + xxx_unused) {
	fprintf(stderr,
	    "%s: %s: RGDB section %d bad: overran used section area: %d > %d\n",
		progname, r->name, n, offset, usedsize);
	section_delete(sect);
	return 0;
    }
    return sect;
}

static char *
load_string(char *buf, int buf_i, int buf_n, int len)
{
    char *s;

    if (len > buf_n - buf_i)
	return 0;

    s = (char *) xmalloc(len + 1);
    memcpy(s, buf + buf_i, len);
    s[len] = '\0';

    return s;
}

RegistryKey
registry_key(Registry *r, const char *path, int create)
{
    RegistryKey rk;
    struct rgkn_key *kn;

    if (path != NULL && strncmp(path, "HKEY_", 5) == 0)
	path = strchr(path, '\\');
    rk.offset = kn_header(r)->root_offset;
    kn = kn_entry(r, kn_header(r)->root_offset);
    rk.r = r;
    if (kn->id == NO_ID)
	rk.entry = NULL;
    else
	rk.entry = db_entry(r, kn);
    while (path != NULL) {
	if (*path == '\\')
	    path++;
	rk = registry_subkey(rk, path, create);
	if (rk.offset == NO_KEY)
	    break;
	path = strchr(path, '\\');
    }
    return rk;
}

static u_int
allocate_rgkn_slot(Registry *r)
{
    u_int offset = kn_header(r)->free_offset;
    struct rgkn_key *kn = kn_entry(r, offset);

    if (kn->hash > sizeof(struct rgkn_key) || kn->next_free == NO_KEY) {
	u_int size = kn->hash - sizeof(struct rgkn_key);
	struct rgkn_key *nk = kn + 1;
	if (size < sizeof(struct rgkn_key)) {
	    char *new_rgkn = (char *) xmalloc(kn_header(r)->size + RGKN_INCR_SIZE);
	    memcpy(new_rgkn, r->rgkn, kn_header(r)->size);
	    memset(new_rgkn + kn_header(r)->size, 0, RGKN_INCR_SIZE);
	    free(r->rgkn);
	    r->rgkn = new_rgkn;
	    nk = kn_entry(r, kn_header(r)->size);
	    kn_header(r)->size += RGKN_INCR_SIZE;
	    r->header->rgdb_offset += RGKN_INCR_SIZE;
	    size = RGKN_INCR_SIZE;
	}
	nk->inuse = FREE_SLOT;
	nk->hash = size;
	nk->next_free = NO_KEY;
	kn_header(r)->free_offset = (char *) nk - r->rgkn;
    } else
	kn_header(r)->free_offset = kn->next_free;
    return offset;
}

static int
get_available_rgdb(Registry *r)
{
    struct key_section **new_rgdb;

    while (r->avail_db < r->header->nrgdb) {
	if (r->rgdb[r->avail_db]->header.first_free_id < 255)
	    return r->avail_db;
	r->avail_db++;
    }
    new_rgdb = (struct key_section **)
	xmalloc(sizeof(*new_rgdb) * (r->avail_db + 1));
    memcpy(new_rgdb, r->rgdb, sizeof(*new_rgdb) * r->avail_db);
    free(r->rgdb);
    r->rgdb = new_rgdb;
    new_rgdb[r->avail_db] = (struct key_section *)
	xmalloc(sizeof(struct key_section));
    memset(new_rgdb[r->avail_db], 0, sizeof(struct key_section));
    new_rgdb[r->avail_db]->header.magic = RGDB_HEADER_MAGIC;
    new_rgdb[r->avail_db]->header.section = r->avail_db;
    new_rgdb[r->avail_db]->header.flags = NEW_RGDB_FLAG_VALUE;
    r->header->nrgdb++;
    return r->avail_db;
}

RegistryKey
registry_subkey(RegistryKey rk, const char *path, int create)
{
    struct rgkn_key *kn;
    int len = 0;
    int hash = 0;
    u_int parent_offset = rk.offset, ref_offset = NO_KEY;

    while (path[len] && path[len] != '\\') {
	if (islower(path[len]))
	    hash += toupper(path[len]);
	else
	    hash += path[len];
	len++;
    }
    rk.offset = kn_entry(rk.r, parent_offset)->child;
    for (;; ref_offset = rk.offset, rk.offset = kn->next) {
	if (rk.offset == NO_KEY) {
	    if (create) {
		struct key_section *sect;

		rk.offset = allocate_rgkn_slot(rk.r);
		kn = kn_entry(rk.r, rk.offset);
		kn->rgdb = get_available_rgdb(rk.r);
		sect = rk.r->rgdb[kn->rgdb];
		kn->id = sect->header.first_free_id;
		if (kn->id > sect->header.max_id)
		    sect->header.max_id = kn->id;
		while (sect->header.first_free_id < 255 &&
			sect->key[++sect->header.first_free_id].name != NULL)
		    ;
		if (rk.r->verbose)
		    fprintf(stderr, "-- created new key %d:%d (free = %d, max = %d)\n",
			kn->rgdb, kn->id, sect->header.first_free_id, sect->header.max_id);
		rk.entry = &sect->key[kn->id];
		rk.entry->name = (char *) xmalloc(len + 1);
		memcpy(rk.entry->name, path, len);
		rk.entry->name[len] = '\0';
		rk.entry->namelen = len;
		rk.entry->nvalues = 0;
		rk.entry->value = NULL;
		kn->inuse = 0;
		kn->next_free = NO_KEY;
		kn->hash = hash;
		kn->child = NO_KEY;
		kn->next = NO_KEY;
		kn->parent = parent_offset;
		if (ref_offset == NO_KEY)
		    kn_entry(rk.r, parent_offset)->child = rk.offset;
		else
		    kn_entry(rk.r, ref_offset)->next = rk.offset;
		rk.r->modified++;
	    } else
		rk.entry = NULL;
	    break;
	}
	kn = kn_entry(rk.r, rk.offset);
	if (kn->hash != hash)
	    continue;
	rk.entry = db_entry(rk.r, kn);
	if (len == rk.entry->namelen &&
		strncasecmp(path, rk.entry->name, len) == 0)
	    break;
    }
    return rk;
}

RegistryKey
registry_first_subkey(RegistryKey rk)
{
    struct rgkn_key *kn = kn_entry(rk.r, rk.offset);
    rk.offset = kn->child;
    if (rk.offset == NO_KEY)
	rk.entry = NULL;
    else {
	kn = kn_entry(rk.r, rk.offset);
	rk.entry = db_entry(rk.r, kn);
	/* This to handle win98 registries */
	if (!rk.entry->name) {
	    /* delete when known to be correct thing to do */
	    if (warnings)
		fprintf(stderr,
		    "%s: warning: invalid registry key entry - empty db entry (sect %d, id %d, first)\n",
		    progname, kn->rgdb, kn->id);
	    rk.entry = NULL;
	    return registry_next_subkey(rk);
	}
    }
    return rk;
}

RegistryKey
registry_next_subkey(RegistryKey rk)
{
    struct rgkn_key *kn = kn_entry(rk.r, rk.offset);
    rk.offset = kn->next;
    if (rk.offset == NO_KEY)
	rk.entry = NULL;
    else {
	kn = kn_entry(rk.r, rk.offset);
	rk.entry = db_entry(rk.r, kn);
	/* This to handle win98 registries */
	if (!rk.entry->name) {
	    /* delete when known to be correct thing to do */
	    if (warnings)
		fprintf(stderr,
		    "%s: warning: invalid registry key entry - empty db entry (sect %d, id %d, next)\n",
		    progname, kn->rgdb, kn->id);
	    rk.entry = NULL;
	    return registry_next_subkey(rk);
	}
    }
    return rk;
}

void
registry_set(RegistryKey rk, const char *name, const char *data, int datalen, int type)
{
    int namelen = strlen(name);
    struct key_entry *db = rk.entry;
    int i;

    for (i = 0; i < db->nvalues; i++)
	if (namelen == db->value[i].namelen && strncasecmp(name, db->value[i].name, namelen) == 0)
	    break;
    if (i == db->nvalues) {
	RegistryValue *nval;

	db->nvalues++;
	nval = (RegistryValue *) xmalloc(sizeof(RegistryValue) * db->nvalues);
	memcpy(nval, db->value, sizeof(RegistryValue) * i);
	free(db->value);
	db->value = nval;
	db->value[i].name = NULL;
    }
    if (db->value[i].name == NULL) {
	db->value[i].name = xstrdup(name);
	db->value[i].namelen = namelen;
    } else if (db->value[i].data)
	free(db->value[i].data);
    db->value[i].type = type;
    db->value[i].datalen = datalen;
    if (datalen > 0) {
	db->value[i].data = (char *) xmalloc(datalen);
	memcpy(db->value[i].data, data, datalen);
    } else
	db->value[i].data = (char *) 0;
    rk.r->modified++;
}

void
registry_delete_value(RegistryKey rk, const char *name)
{
    int namelen = strlen(name);
    struct key_entry *db = rk.entry;
    int i;

    for (i = 0; i < db->nvalues; i++)
	if (namelen == db->value[i].namelen
	    && (namelen == 0
		|| strncasecmp(name, db->value[i].name, namelen) == 0))
	{
	    if (db->value[i].name)
		free(db->value[i].name);
	    if (db->value[i].data)
		free(db->value[i].data);
	    db->value[i].name = NULL;
	    db->value[i].namelen = 0;
	    db->value[i].data = NULL;
	    db->value[i].datalen = 0;
	    rk.r->modified++;
	}
}

static void
free_rgkn_slot(Registry *r, u_int offset)
{
    struct rgkn_key *kn = kn_entry(r, offset);

    kn->inuse = FREE_SLOT;
    kn->rgdb = kn->id = 0xffff;
    kn->hash = sizeof(struct rgkn_key);
    kn->next_free = kn_header(r)->free_offset;
    kn_header(r)->free_offset = offset;
}

static void
delete_key(Registry *r, u_int offset)
{
    struct rgkn_key *kn = kn_entry(r, offset);
    struct rgkn_key *ref;
    struct key_section *db;

    while (kn->child != NO_KEY)
	delete_key(r, kn->child);
    if (kn->parent != NO_KEY) {
	db = r->rgdb[kn->rgdb];
	if (db->header.max_id == kn->id) {
	    while (db->header.max_id > 0 &&
			db->key[--db->header.max_id].name == NULL)
		;
	}
	if (kn->id < db->header.first_free_id)
	    db->header.first_free_id = kn->id;
	if (r->verbose)
	    fprintf(stderr, "-- deleting key %d:%d [%s] (free = %d, max = %d)\n", kn->rgdb, kn->id, db->key[kn->id].name, db->header.first_free_id, db->header.max_id);
	free_entry(&db->key[kn->id]);
	ref = kn_entry(r, kn->parent);
	if (ref->child == offset)
	    ref->child = kn->next;
	else {
	    ref = kn_entry(r, ref->child);
	    while (ref->next != offset)
		ref = kn_entry(r, ref->next);
	    ref->next = kn->next;
	}
	free_rgkn_slot(r, offset);
    }
}

void
registry_delete_key(RegistryKey rk)
{
    delete_key(rk.r, rk.offset);
    rk.r->modified++;
}

static u_int
calc_section_size(struct key_section *sect)
{
    int i, j;
    u_int size;
    struct key_entry *entry;

    size = sizeof sect->header;
    for (i = 0; i < 255; i++) {
	entry = &sect->key[i];
	if (entry->name == NULL)
	    continue;
	size += sizeof(struct rgdb_key) + entry->namelen;
	for (j = 0; j < entry->nvalues; j++) {
	    if (entry->value[j].name != NULL)
		size += sizeof(struct rgdb_value) + entry->value[j].namelen +
		    entry->value[j].datalen;
	}
    }
    return size;
}

static u_int
checksum(void *area, u_int length)
{
    u_int *ap = area;
    u_int *end = (u_int *) ((char *) area + length);
    u_int sum = 0;

    while (ap < (u_int *) end)
	sum += *ap++;
    return sum;
}

static void
write_section(struct key_section *sect, int secnum, FILE *fp, int verbose)
{
    struct rgdb_header *head = &sect->header;
    struct rgdb_key rk;
    char *buf = (char *) xmalloc(head->size);
    char *ptr = buf + sizeof *head;
    char *fix = NULL;
    struct key_entry *entry;
    int i, j;
    int last_add;

    if (verbose)
	fprintf(stderr, "saving RGDB section %d, size = %d - %d\n",
	    head->section, head->size, head->unused_size);
    if (head->unused_size < sizeof(struct rgdb_key)) {
	last_add = head->unused_size;
	head->free_offset = 0xffffffff;
	head->unused_size = 0;
    } else
	last_add = 0;
    memcpy(buf, head, sizeof *head);
    head = (struct rgdb_header *) buf;
    for (i = 0; i <= head->max_id; i++) {
	entry = &sect->key[i];
	if (entry->name == NULL)
	    continue;
	fix = ptr;
	ptr += sizeof rk;
	memcpy(ptr, entry->name, entry->namelen);
	ptr += entry->namelen;
	rk.nvalues = 0;
	for (j = 0; j < entry->nvalues; j++) {
	    struct rgdb_value rv;
	    RegistryValue *v = &entry->value[j];

	    if (v->name == NULL)
		continue;
	    if (verbose)
		fprintf(stderr, "    saving value \"%s\"\n", v->name);
	    rv.type = v->type;
	    rv.uk4l = 0;
	    rv.name_len = v->namelen;
	    rv.data_len = v->datalen;
	    memcpy(ptr, &rv, sizeof rv);
	    ptr += sizeof rv;
	    memcpy(ptr, v->name, v->namelen);
	    ptr += v->namelen;
	    if (v->data)
		memcpy(ptr, v->data, v->datalen);
	    ptr += v->datalen;
	    rk.nvalues++;
	}
	rk.size = rk.used_size = ptr - fix;
	rk.id = i;
	rk.rgdb = secnum;
	rk.name_len = entry->namelen;
	rk.uk16l = 0;
	if (verbose)
	    fprintf(stderr, "  %06x: saving key [%s], %d values (uses %d/%d)\n",
		(int) (fix - buf), entry->name, rk.nvalues,
		rk.used_size, rk.size);
	memcpy(fix, &rk, sizeof rk);
    }
    if (fix != NULL) {
	rk.size += last_add;
	memcpy(fix, &rk, sizeof rk);
    }
    memset(ptr, 0, head->unused_size);
    if (head->unused_size >= sizeof(struct rgdb_key)) {
	struct rgdb_key rk;

	rk.size = head->unused_size;
	rk.id = 0xffff;
	rk.rgdb = 0xffff;
	rk.used_size = 0xffffffff;
	rk.name_len = 0;
	rk.nvalues = 0;
	rk.uk16l = 0;
	memcpy(ptr, &rk, sizeof(rk));
    }
    head->csum -= checksum(buf, head->size);
    fwrite(buf, head->size, 1, fp);
    free(buf);
}

static int
registry_write(Registry *r)
{
    FILE *fp;
    int i;
    char *tmpfile = 0;

    if (strcmp(r->name, "-") == 0)
	fp = stdout;
    else {
	if (!(tmpfile = malloc(strlen(r->name) + 5))) {
	    fprintf(stderr, "%s: malloc failed - %s\n",
		    progname, strerror(errno));
	    return 0;
	}
	sprintf(tmpfile, "%s.tmp", r->name);
	if ((fp = fopen(tmpfile, "w")) == NULL) {
	    fprintf(stderr, "%s: can't open %s for writing - %s\n",
		    progname, tmpfile, strerror(errno));
	    free(tmpfile);
	    return 0;
	}
    }
    r->header->csum -= checksum(r->header, sizeof *r->header);
    fwrite(r->header, sizeof *r->header, 1, fp);
    kn_header(r)->csum -= checksum(r->rgkn, kn_header(r)->size);
    fwrite(r->rgkn, kn_header(r)->size, 1, fp);
    for (i = 0; i < r->header->nrgdb; i++) {
	u_int size = calc_section_size(r->rgdb[i]);
	struct rgdb_header *head = &r->rgdb[i]->header;

	head->size = (size + 4096) & ~4095;
	head->free_offset = size < head->size ? size : 0xffffffff;
	head->unused_size = head->size - size;
	write_section(r->rgdb[i], i, fp, r->verbose);
    }
    fflush(fp);
	/* bit-wise or */
    if (ferror(fp) | (fclose(fp) == EOF)) {
	fprintf(stderr, "%s: error writing to %s - %s\n",
		progname, r->name, strerror(errno));
	unlink(tmpfile);
	free(tmpfile);
	return 0;
    }
    if (tmpfile) {
	struct stat statb;

	if (stat(r->name, &statb) >= 0) {
	    (void) chown(tmpfile, statb.st_uid, statb.st_gid);
	    (void) chmod(tmpfile, statb.st_mode & 07777);
	}
	if (rename(tmpfile, r->name) < 0) {
	    fprintf(stderr, "%s: error renaming %s to %s - %s\n",
		    progname, tmpfile, r->name, strerror(errno));
	    unlink(tmpfile);
	    free(tmpfile);
	    return 0;
	}
	free(tmpfile);
    }

    return 1;
}
