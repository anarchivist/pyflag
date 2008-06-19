/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2007 Brian Carrier.  All Rights reserved
 *
 * $Date: 2007/12/20 20:32:38 $
 *
 * This software is distributed under the Common Public License 1.0
 */
 
/** \file tsk_printf.c 
 * These are printf wrappers that are needed so that we can
 * easily print in both Unix and Windows.  For Unix, the 
 * internal UTF-8 representation is kept and a normal printf
 * is performed.  For Windows, the UTF-8 representation is first
 * converted to UTF-16 and then printed
 */
 
#include "tsk_base_i.h"
#include <stdarg.h>


// wlen is the max number of characters in buf
// return 1 on error and 0 on success
#ifdef TSK_WIN32
static int
tsk_printf_conv(WCHAR * wbuf, int wlen, const char *msg, va_list * args)
{
    char *cbuf;
    UTF8 *ptr8;
    UTF16 *ptr16;
    int retVal;
    size_t len, clen;

    wbuf[0] = '\0';

    clen = wlen * 3;
    if (NULL == (cbuf = (char *) tsk_malloc(clen))) {
        return 1;
    }
    memset(cbuf, 0, clen);

    vsnprintf_s(cbuf, clen - 1, _TRUNCATE, msg, *args);
    len = strlen(cbuf);

    //Convert to UTF-16
    ptr8 = (UTF8 *) cbuf;
    ptr16 = (UTF16 *) wbuf;
    retVal =
        tsk_UTF8toUTF16(&ptr8, &ptr8[len + 1], &ptr16, &ptr16[wlen],
        TSKlenientConversion);
    if (retVal != TSKconversionOK) {
        *ptr16 = '\0';
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "tsk_printf_conv: error converting string to UTF-16\n");
    }
    free(cbuf);

    return 0;
}
#endif

// wlen is the max number of characters in buf
#if 0
// after creating this, I"m not sure if it makes sense.  we keep
// all internal strings as UTF-8 and the result of this is an internal
// string...
void
tsk_snprintf(WCHAR * wbuf, int wlen, char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    tsk_printf_conv(wbuf, wlen, msg, &args);
    va_end(args);
}
#endif

void
tsk_fprintf(FILE * fd, const char *msg, ...)
{
    va_list args;
    va_start(args, msg);

#ifdef TSK_WIN32
    {
        WCHAR wbuf[2048];
        tsk_printf_conv(wbuf, 2048, msg, &args);
        fwprintf(fd, _TSK_T("%s"), wbuf);
    }
#else
    vfprintf(fd, msg, args);
#endif
    va_end(args);
}

void
tsk_printf(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);

#ifdef TSK_WIN32
    {
        WCHAR wbuf[2048];
        tsk_printf_conv(wbuf, 2048, msg, &args);
        wprintf(_TSK_T("%s"), wbuf);
    }
#else
    vprintf(msg, args);
#endif
    va_end(args);
}
