/*
** img_types
** The Sleuth Kit 
**
** $Date: 2007/12/20 20:32:39 $
**
** Identify the type of image file being used
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2006 Brian Carrier.  All rights reserved 
**
** This software is distributed under the Common Public License 1.0
*/

/** \file img_types.c
 * Contains basic functions to parse and print the names of the supported disk image types. 
 */
#include "tsk_img_i.h"

/** \internal
  * used to parse and print supported types
  */
typedef struct {
    char *name;
    uint8_t code;
    char *comment;
} IMG_TYPES;

/** \internal
 * The table used to parse input strings 
 * - in order of expected usage
 */
IMG_TYPES img_open_table[] = {
    {"raw", TSK_IMG_INFO_TYPE_RAW_SING, "raw (dd)"},
#if HAVE_LIBAFFLIB
    {"aff", TSK_IMG_INFO_TYPE_AFF_AFF, "Advanced Forensic Format"},
    {"afd", TSK_IMG_INFO_TYPE_AFF_AFD, "AFF Multiple File"},
    {"afm", TSK_IMG_INFO_TYPE_AFF_AFM, "AFF with external metadata"},
#endif
#if HAVE_LIBEWF
    {"ewf", TSK_IMG_INFO_TYPE_EWF_EWF, "Expert Witness format (encase)"},
#endif
    {"split", TSK_IMG_INFO_TYPE_RAW_SPLIT, "Split raw files"},
    {0},
};


/**
 * Parse a string and return the image type ID
 * @param str String of image type
 * @return ID of image type
 */
TSK_IMG_INFO_TYPE_ENUM
tsk_img_parse_type(const TSK_TCHAR * str)
{
    char tmp[16];
    IMG_TYPES *sp;
    int i;
    // convert to char
    for (i = 0; i < 15 && str[i] != '\0'; i++) {
        tmp[i] = (char) str[i];
    }
    tmp[i] = '\0';

    for (sp = img_open_table; sp->name; sp++) {
        if (strcmp(tmp, sp->name) == 0) {
            return sp->code;
        }
    }
    return TSK_IMG_INFO_TYPE_UNSUPP;
}


/**
 * Print the supported image types to a handle.
 * @param hFile Handle to print to.
 */
void
tsk_img_print_types(FILE * hFile)
{
    IMG_TYPES *sp;
    tsk_fprintf(hFile, "Supported image format types:\n");
    for (sp = img_open_table; sp->name; sp++)
        tsk_fprintf(hFile, "\t%s (%s)\n", sp->name, sp->comment);
}

/**
 * Get the name of an image type give its type ID.
 * @param type ID of image type
 * @returns Pointer to string of name.
 */
const char *
tsk_img_get_type(TSK_IMG_INFO_TYPE_ENUM type)
{
    IMG_TYPES *sp;
    for (sp = img_open_table; sp->name; sp++)
        if (sp->code == type)
            return sp->name;

    return NULL;
}
