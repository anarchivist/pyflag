#ifndef REGISTRY_H
# define REGISTRY_H
/*
 * registry.h - internal data structures used by regedit (regutils package)
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

struct reg_header;
struct key_section;
struct key_entry;

typedef struct {
    char *name;
    FILE *fp;
    int modified;
    int verbose;
    int avail_db;
    struct reg_header *header;
    char *rgkn;
    u_int last_rgkn_offset;	/* last valid offset */
    struct key_section **rgdb;
} Registry;

typedef struct {
    int type;
    int namelen;
    char *name;
    int datalen;
    char *data;
} RegistryValue;

struct key_entry {
    int namelen;
    char *name;
    int nvalues;
    RegistryValue *value;
};

typedef struct {
    Registry *r;
    struct key_entry *entry;
    unsigned long offset;
} RegistryKey;

#define registry_key_name(rk)	((rk).entry->name)
#define registry_nvalues(rk)	((rk).entry == NULL ? 0 : (rk).entry->nvalues)
#define registry_value(rk, n)	(&(rk).entry->value[n])

extern Registry *registry_open(const char *filename, int verbose);
extern void registry_rename(Registry *, const char *);
extern int registry_close(Registry *);

extern RegistryKey registry_key(Registry *, const char *, int);
extern RegistryKey registry_subkey(RegistryKey, const char *, int);
extern RegistryKey registry_first_subkey(RegistryKey);
extern RegistryKey registry_next_subkey(RegistryKey);

extern void registry_set(RegistryKey, const char *, const char *,
    int, int);
extern void registry_delete_value(RegistryKey, const char *);
extern void registry_delete_key(RegistryKey);
#endif /* REGISTRY_H */
