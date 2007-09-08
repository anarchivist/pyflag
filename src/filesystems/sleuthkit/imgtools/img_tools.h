/*
 * The Sleuth Kit
 *
 * $Date: 2007/06/05 20:04:41 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2005 Brian Carrier.  All rights reserved 
 */
#ifndef _IMG_TOOLS_H
#define _IMG_TOOLS_H

#include "aux_tools.h"

#include <string.h>
#include <fcntl.h>
#include <errno.h>


/**
 * \file img_tools.h
 * Contains the definitions for the disk image functions.
 */

#ifdef HAVE_UNISTD
#include <unistd.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif


    /** 
     * Values for the disk image type.  The most-significant nibble is 
     * the high-level image type.  The least-sigificant nibble is the specific 
     * sub-type of implementation.  
     */
    enum TSK_IMG_INFO_TYPE_ENUM {
        TSK_IMG_INFO_TYPE_IMG_MASK = 0xf0,      ///< Mask to isolate high-level image type
        TSK_IMG_INFO_TYPE_SUB_MASK = 0x0f,      ///< Mask to isolte sub-type

        TSK_IMG_INFO_TYPE_UNSUPP = 0x00,        ///< Unsupported disk image type

        /* RAW */
        TSK_IMG_INFO_TYPE_RAW_TYPE = 0x10,      ///< Raw type (general)
        TSK_IMG_INFO_TYPE_RAW_SING = 0x11,      ///< Raw single disk image
        TSK_IMG_INFO_TYPE_RAW_SPLIT = 0x12,     ///< Raw split image

        /* AFF */
        TSK_IMG_INFO_TYPE_AFF_TYPE = 0x20,      ///< AFF Type (general)
        TSK_IMG_INFO_TYPE_AFF_AFF = 0x21,       ///< AFF version
        TSK_IMG_INFO_TYPE_AFF_AFD = 0x22,       ///< AFD Version
        TSK_IMG_INFO_TYPE_AFF_AFM = 0x23,       ///< AFM version

        /* EWF */
        TSK_IMG_INFO_TYPE_EWF_TYPE = 0x30,      ///< EWF/EnCase Type (General)
        TSK_IMG_INFO_TYPE_EWF_EWF = 0x31,       ///< EWF version

        /* PYTHON */
        TSK_IMG_INFO_TYPE_PYFILE_TYPE	=	0x40	///< PYTHON file type
    };
    typedef enum TSK_IMG_INFO_TYPE_ENUM TSK_IMG_INFO_TYPE_ENUM;

    typedef struct TSK_IMG_INFO TSK_IMG_INFO;

    /**
     * Generic structure used to store information about
     * disk image files
     */
    struct TSK_IMG_INFO {

        TSK_IMG_INFO *next;     ///< Pointer to next "layer"
        TSK_IMG_INFO_TYPE_ENUM itype;   ///< Type of disk image format
        OFF_T size;             ///< Total size of image in bytes

        /// file type-specific read function
         SSIZE_T(*read_random) (TSK_IMG_INFO *, OFF_T, char *, OFF_T,
            OFF_T);

         OFF_T(*get_size) (TSK_IMG_INFO *);
        void (*close) (TSK_IMG_INFO *);
        void (*imgstat) (TSK_IMG_INFO *, FILE *);
    };


    extern TSK_IMG_INFO *tsk_img_open(const TSK_TCHAR *, const int,
        const TSK_TCHAR **);


/********* TYPES *******/
    extern TSK_IMG_INFO_TYPE_ENUM tsk_img_parse_type(const TSK_TCHAR *);
    extern void tsk_img_print_types(FILE *);
    extern char *tsk_img_get_type(TSK_IMG_INFO_TYPE_ENUM);




#ifdef __cplusplus
}
#endif
#endif
