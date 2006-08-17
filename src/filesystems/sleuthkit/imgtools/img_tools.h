/*
 * The Sleuth Kit
 *
 * $Date: 2006/06/20 22:35:41 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2005 Brian Carrier.  All rights reserved 
 */
#ifndef _IMG_TOOLS_H
#define _IMG_TOOLS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#include "tsk_os.h"

#ifdef HAVE_UNISTD
#include <unistd.h>
#endif

#include "tsk_types.h"

#include "img_types.h"

#include "libauxtools.h"

    typedef struct IMG_INFO IMG_INFO;

    struct IMG_INFO {

	IMG_INFO *next;		// pointer to next layer

	/* Image specific function pointers */
	uint8_t itype;

	OFF_T size;		/* Size of image in bytes */

	/* Read random */
	 SSIZE_T(*read_random) (IMG_INFO *, OFF_T, char *, OFF_T, OFF_T);
	 OFF_T(*get_size) (IMG_INFO *);
	void (*close) (IMG_INFO *);
	void (*imgstat) (IMG_INFO *, FILE *);
    };


    extern IMG_INFO *img_open(const char *, const int, const char **);

#ifdef __cplusplus
}
#endif
#endif
