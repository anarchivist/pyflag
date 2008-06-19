/*
 * The Sleuth Kit
 *
 * $Date: 2007/12/20 20:32:39 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */

/** \file mm_types.c
 * Contains the code to parse and print the strings for the supported volume system types.
 */

#include "tsk_vs_i.h"

typedef struct {
    char *name;
    TSK_MM_INFO_TYPE_ENUM code;
    char *comment;
} MM_TYPES;


MM_TYPES mm_open_table[] = {
    {"dos", TSK_MM_INFO_TYPE_DOS,
        "DOS-based partitions [Windows, Linux, etc.]"},
    {"mac", TSK_MM_INFO_TYPE_MAC, "MAC partitions"},
    {"bsd", TSK_MM_INFO_TYPE_BSD,
        "BSD Disklabels [FreeBSD, OpenBSD, NetBSD]"},
    {"sun", TSK_MM_INFO_TYPE_SUN,
        "Sun Volume Table of Contents (Solaris)"},
    {"gpt", TSK_MM_INFO_TYPE_GPT, "GUID Partition Table (EFI)"},
    {0},
};

/* parse the string and return the value 
 *
 * Returns TSK_MM_INFO_TYPE_UNSUPP if string cannot be parsed
 * */
TSK_MM_INFO_TYPE_ENUM
tsk_mm_parse_type(const TSK_TCHAR * str)
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
    return TSK_MM_INFO_TYPE_UNSUPP;
}

void
tsk_mm_print_types(FILE * hFile)
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
const char *
tsk_mm_get_type(TSK_MM_INFO_TYPE_ENUM mmtype)
{
    MM_TYPES *types;
    for (types = mm_open_table; types->name; types++)
        if (types->code == mmtype)
            return types->name;

    return NULL;
}
