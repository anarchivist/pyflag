/*
 * The Sleuth Kit
 *
 * $Date: 2005/09/02 19:53:28 $
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
#include <unistd.h>
#include <fcntl.h>

#include "tsk_os.h"
#include "tsk_types.h"


#include "libauxtools.h"

    typedef struct IMG_INFO IMG_INFO;

    struct IMG_INFO {

	IMG_INFO *next;		// pointer to next layer

	/* Image specific function pointers */
	uint8_t itype;

	OFF_T offset;		/* Offset for reads (in bytes) */
	OFF_T size;		/* Size of image in bytes */

	/* Read random */
	 OFF_T(*read_random) (IMG_INFO *, char *, OFF_T, OFF_T);
	 OFF_T(*get_size) (IMG_INFO *);
	void (*close) (IMG_INFO *);
	void (*imgstat) (IMG_INFO *, FILE *);
    };

#define IMG_RAW		0x01
#define IMG_SPLIT	0x02


    extern IMG_INFO *img_open(const char *, const char *, const int,
			      const char **);

    extern void img_print_types(FILE *);
    extern char *img_get_type(uint8_t);

#ifdef __cplusplus
}
#endif
#endif
