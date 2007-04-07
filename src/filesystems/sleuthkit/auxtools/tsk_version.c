/*
 * The Sleuth Kit
 * 
 * $Date: 2007/02/15 20:35:16 $
 */
#include <stdlib.h>
#include <stdio.h>
#include "aux_tools.h"

void
tsk_print_version(FILE * hFile)
{
    char *str = "The Sleuth Kit";
#ifdef VER
    tsk_fprintf(hFile, "%s ver %s\n", str, VER);
#else
    tsk_fprintf(hFile, "%s\n", str);
#endif
    return;
}

char *
tskGetVersion()
{
#ifdef VER
    return VER;
#else
    return "0.0";
#endif
}
