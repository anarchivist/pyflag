/*
 * The Sleuth Kit
 *
 * $Date: 2006/12/07 16:38:18 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2005 Brian Carrier.  All rights reserved 
 */
#ifndef _IMG_TOOLS_H
#define _IMG_TOOLS_H



#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#include "aux_tools.h"


#ifdef HAVE_UNISTD
#include <unistd.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

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


    extern IMG_INFO *img_open(const TSK_TCHAR *, const int,
	const TSK_TCHAR **);


/********* TYPES *******/
    extern uint8_t img_parse_type(const TSK_TCHAR *);
    extern void img_print_types(FILE *);
    extern char *img_get_type(uint8_t);

/*
** the most-sig-nibble is the image type, which indicates which
** _open function to call.  The least-sig-nibble is the specific type
** of implementation.  
*/
#define IMGMASK			0xf0
#define OSMASK			0x0f

#define UNSUPP_IMG		0x00

/* RAW */
#define RAW_TYPE		0x10
#define RAW_SING		0x11
#define RAW_SPLIT		0x12

/* AFF */
#define AFF_TYPE		0x20
#define AFF_AFF			0x21
#define AFF_AFD			0x22
#define AFF_AFM			0x23

/* EWF */
#define EWF_TYPE		0x30
#define EWF_EWF			0x31

/* PYTHON */
#define PYFILE_TYPE     0x40

#ifdef __cplusplus
}
#endif
#endif
