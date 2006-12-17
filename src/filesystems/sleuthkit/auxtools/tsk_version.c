/*
 * The Sleuth Kit
 * 
 * $Date: 2006/12/07 16:25:39 $
 */
#include <stdlib.h>
#include <stdio.h>
#include "aux_tools.h"

void
print_version(FILE * hFile)
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
