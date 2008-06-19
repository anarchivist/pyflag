/*
 * The Sleuth Kit
 *
 * $Date: 2007/12/20 20:32:39 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2005 Brian Carrier.  All rights reserved 
 */
#ifndef _TSK_IMG_H
#define _TSK_IMG_H


/**
 * \file tsk_img.h
 * Contains the external library definitions for the disk image functions.  
 * Note that this file is not meant to be directly included.  
 * It is included by both libtsk.h and tsk_img_i.h.
 */


#ifdef __cplusplus
extern "C" {
#endif


    /** 
     * Values for the disk image type.  The most-significant nibble is 
     * the high-level image type.  The least-sigificant nibble is the specific 
     * sub-type of implementation.  
     */
    typedef enum {
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
        TSK_IMG_INFO_TYPE_EWF_EWF = 0x31        ///< EWF version
    } TSK_IMG_INFO_TYPE_ENUM;

    typedef struct TSK_IMG_INFO TSK_IMG_INFO;

    /**
     * Generic structure used to store information about
     * disk image files
     */
    struct TSK_IMG_INFO {

        TSK_IMG_INFO *next;     ///< Pointer to next "layer"
        TSK_IMG_INFO_TYPE_ENUM itype;   ///< Type of disk image format
        TSK_OFF_T size;         ///< Total size of image in bytes

        /** Pointer to image type-specific read function
          * @param img Image to read from
          * @param vol_off Byte offset to start of 'volume' in image.
          * @param buf Buffer to read into
          * @param len Number of bytes to read
          * @param off Offset in volume to start reading from.
          * @returns number of bytes read or -1 on error.
          */
         ssize_t(*read_random) (TSK_IMG_INFO * img, TSK_OFF_T vol_off,
            char *buf, size_t len, TSK_OFF_T off);

         TSK_OFF_T(*get_size) (TSK_IMG_INFO *);
        void (*close) (TSK_IMG_INFO *);
        void (*imgstat) (TSK_IMG_INFO *, FILE *);
    };


    extern TSK_IMG_INFO *tsk_img_open(const TSK_TCHAR *, const int,
        const TSK_TCHAR **);


/********* TYPES *******/
    extern TSK_IMG_INFO_TYPE_ENUM tsk_img_parse_type(const TSK_TCHAR *);
    extern void tsk_img_print_types(FILE *);
    extern const char *tsk_img_get_type(TSK_IMG_INFO_TYPE_ENUM);


#ifdef __cplusplus
}
#endif
#endif
