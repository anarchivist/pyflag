/*
 * The Sleuth Kit
 *
 * $Date: 2007/04/04 18:48:46 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
 *
 * tsk_mm_open - wrapper function for specific partition type
 *
 *
 * This software is distributed under the Common Public License 1.0
 *
 */

#include "mm_tools.h"


/**
 * \file mm_open.c
 * Contains general code to open media management systems.
 */

/**
 * Open a disk image and process the media management system
 * data.  This calls MM specific code to determine the type and
 * collect data. 
 *
 * @param img_info The opened disk image.
 * @param offset Byte offset in the disk image to start analyzing from.
 * @param type String name of type specified by user (autodetect is used
 * if this is NULL).
 *
 * @return NULL on error. 
 */
TSK_MM_INFO *
tsk_mm_open(TSK_IMG_INFO * img_info, DADDR_T offset,
    const TSK_TCHAR * type)
{
    /* Autodetect mode 
     * We need to try all of them in case there are multiple 
     * installations
     *
     *
     * NOte that errors that are encountered during the testing process
     * will not be reported
     */
    if (type == NULL) {
        TSK_MM_INFO *mm_info, *mm_set = NULL;
        char *set = NULL;

        if ((mm_info = tsk_mm_dos_open(img_info, offset, 1)) != NULL) {
            set = "DOS";
            mm_set = mm_info;
        }
        else {
            tsk_error_reset();
        }
        if ((mm_info = tsk_mm_bsd_open(img_info, offset)) != NULL) {
            // if (set == NULL) {
            // In this case, BSD takes priority because BSD partitions start off with
            // the DOS magic value in the first sector with the boot code.
            set = "BSD";
            mm_set = mm_info;
            /*
               }
               else {
               mm_set->close(mm_set);
               mm_info->close(mm_info);
               tsk_error_reset();
               tsk_errno = TSK_ERR_MM_UNKTYPE;
               snprintf(tsk_errstr, TSK_ERRSTR_L,
               "BSD or %s at %" PRIuDADDR, set, offset);
               tsk_errstr2[0] = '\0';
               return NULL;
               }
             */
        }
        else {
            tsk_error_reset();
        }
        if ((mm_info = tsk_mm_gpt_open(img_info, offset)) != NULL) {
            if (set == NULL) {
                set = "GPT";
                mm_set = mm_info;
            }
            else {
                mm_set->close(mm_set);
                mm_info->close(mm_info);
                tsk_error_reset();
                tsk_errno = TSK_ERR_MM_UNKTYPE;
                snprintf(tsk_errstr, TSK_ERRSTR_L,
                    "GPT or %s at %" PRIuDADDR, set, offset);
                return NULL;
            }
        }
        else {
            tsk_error_reset();
        }

        if ((mm_info = tsk_mm_sun_open(img_info, offset)) != NULL) {
            if (set == NULL) {
                set = "Sun";
                mm_set = mm_info;
            }
            else {
                mm_set->close(mm_set);
                mm_info->close(mm_info);
                tsk_error_reset();
                tsk_errno = TSK_ERR_MM_UNKTYPE;
                snprintf(tsk_errstr, TSK_ERRSTR_L,
                    "Sun or %s at %" PRIuDADDR, set, offset);
                return NULL;
            }
        }
        else {
            tsk_error_reset();
        }

        if ((mm_info = tsk_mm_mac_open(img_info, offset)) != NULL) {
            if (set == NULL) {
                set = "Mac";
                mm_set = mm_info;
            }
            else {
                mm_set->close(mm_set);
                mm_info->close(mm_info);
                tsk_error_reset();
                tsk_errno = TSK_ERR_MM_UNKTYPE;
                snprintf(tsk_errstr, TSK_ERRSTR_L,
                    "Mac or %s at %" PRIuDADDR, set, offset);
                return NULL;
            }
        }
        else {
            tsk_error_reset();
        }

        if (mm_set == NULL) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_MM_UNKTYPE;
            return NULL;
        }

        return mm_set;
    }
    else {
        uint8_t mmtype;

        /* Transate the string into the number */
        mmtype = tsk_mm_parse_type(type);

        switch (mmtype) {
        case TSK_MM_INFO_TYPE_DOS:
            return tsk_mm_dos_open(img_info, offset, 0);
        case TSK_MM_INFO_TYPE_MAC:
            return tsk_mm_mac_open(img_info, offset);
        case TSK_MM_INFO_TYPE_BSD:
            return tsk_mm_bsd_open(img_info, offset);
        case TSK_MM_INFO_TYPE_SUN:
            return tsk_mm_sun_open(img_info, offset);
        case TSK_MM_INFO_TYPE_GPT:
            return tsk_mm_gpt_open(img_info, offset);
        case TSK_MM_INFO_TYPE_UNSUPP:
        default:
            tsk_error_reset();
            tsk_errno = TSK_ERR_MM_UNSUPTYPE;
            snprintf(tsk_errstr, TSK_ERRSTR_L, "%s", type);
            return NULL;
        }
    }
}
