/*
 * The Sleuth Kit
 * 
 * $Date: 2007/12/20 20:32:38 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2007 Brian Carrier.  All rights reserved 
 *
 * This software is distributed under the Common Public License 1.0
 */

/** \file  tsk_version.c
 * Contains functions to print and obtain the library version.
 */

#include "tsk_base_i.h"

/**
 * Print the version to a handle.
 * @param hFile Handle to print to
 */
void
tsk_print_version(FILE * hFile)
{
    char *str = "The Sleuth Kit";
#ifdef PACKAGE_VERSION
    tsk_fprintf(hFile, "%s ver %s\n", str, PACKAGE_VERSION);
#else
    tsk_fprintf(hFile, "%s\n", str);
#endif
    return;
}

/**
 * Return the library version as a string.
 * @returns String version of version (1.00 for example)
 */
const char *
tskGetVersion()
{
#ifdef PACKAGE_VERSION
    return PACKAGE_VERSION;
#else
    return "0.0";
#endif
}
