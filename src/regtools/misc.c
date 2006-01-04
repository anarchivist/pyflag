/*
 * misc.c - miscellaneous support routines for regedit (regutils package)
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
#include <stdlib.h>
#include "misc.h"

extern char *progname;

void *
xmalloc(unsigned int size)
{
    void *mem = (void *) malloc(size);

    if (mem == 0) {
	fprintf(stderr, "%s: Out of memory (size=%u)\n", progname, size);
	exit(1);
    }
    return mem;
}

char *
xstrdup(const char *s)
{
    char *n = strdup(s);

    if (n == 0) {
	fprintf(stderr, "%s: Out of memory (strdup)\n", progname);
	exit(1);
    }
    return n;
}
