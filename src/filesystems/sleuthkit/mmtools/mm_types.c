/*
 * The Sleuth Kit
 *
 * $Date: 2006/09/06 20:40:02 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
 *
 * mm_types - set the type value given a string of partition type
 *
 *
 * This software is distributed under the Common Public License 1.0
 *
 */

#include "mm_tools.h"

typedef struct {
    char *name;
    char code;
    char *comment;
} MM_TYPES;


MM_TYPES mm_open_table[] = {
    {"dos", MM_DOS, "DOS-based partitions [Windows, Linux, etc.]"},
    {"mac", MM_MAC, "MAC partitions"},
    {"bsd", MM_BSD, "BSD Disklabels [FreeBSD, OpenBSD, NetBSD]"},
    {"sun", MM_SUN, "Sun Volume Table of Contents (Solaris)"},
    {"gpt", MM_GPT, "GUID Partition Table (EFI)"},
    {0},
};

/* parse the string and return the value 
 *
 * Returns MM_UNSUPP if string cannot be parsed
 * */
char
mm_parse_type(const TSK_TCHAR * str)
{
    char tmp[16];
    int i;
    MM_TYPES *types;

    // convert to char
    for (i = 0; i < 15 && str[i] != '\0'; i++) {
	tmp[i] = (char) str[i];
    }
    tmp[i] = '\0';

    for (types = mm_open_table; types->name; types++) {
	if (strcmp(tmp, types->name) == 0) {
	    return types->code;
	}
    }
    return MM_UNSUPP;
}

void
mm_print_types(FILE * hFile)
{
    MM_TYPES *types;
    tsk_fprintf(hFile, "Supported partition types:\n");
    for (types = mm_open_table; types->name; types++)
	tsk_fprintf(hFile, "\t%s (%s)\n", types->name, types->comment);
}


/*
 * Return the string name of a partition type given its code
 *
 * Returns NULL if a match is not made
 * */
char *
mm_get_type(char mmtype)
{
    MM_TYPES *types;
    for (types = mm_open_table; types->name; types++)
	if (types->code == mmtype)
	    return types->name;

    return NULL;
}
