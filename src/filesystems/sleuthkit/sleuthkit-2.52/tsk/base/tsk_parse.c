/*
 * The Sleuth Kit 
 *
 * $Date: 2008/02/25 16:31:40 $
 *
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2005-2007 Brian Carrier.  All Rights reserved
 */
#include "tsk_base_i.h"


/**
 * \file tsk_parse.c
 * Contains code to parse specific types of data from 
 * the command line
 */

/**
 * Parse a string in the cnt\@size or cnt format and
 * return the byte offset. 
 *
 * @param [in] a_offset_str The string version of the offset
 * @return -1 on error or byte offset on success
 */
TSK_OFF_T
tsk_parse_offset(const TSK_TCHAR * a_offset_str)
{
    TSK_TCHAR offset_lcl[64], *offset_lcl_p;
    TSK_DADDR_T num_blk;
    TSK_TCHAR *cp, *at;
    int bsize;
    TSK_OFF_T offset_b;

    if (a_offset_str == NULL) {
        return 0;
    }
    if (TSTRLEN(a_offset_str) > 63) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_IMG_OFFSET;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "tsk_parse: offset string is too long: %s", a_offset_str);
        return -1;
    }

    /* Make a local copy */
    TSTRNCPY(offset_lcl, a_offset_str, 64);
    offset_lcl_p = offset_lcl;

    /* Check for the x@y setup  and set
     * bsize if it exists
     */
    if ((at = TSTRCHR(offset_lcl_p, '@')) != NULL) {
        *at = '\0';
        at++;

        bsize = TSTRTOUL(at, &cp, 0);
        if (*cp || *cp == *at) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_IMG_OFFSET;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "tsk_parse: block size: %s", at);
            return -1;
        }
        else if (bsize % 512) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_IMG_OFFSET;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "tsk_parse: block size not multiple of 512");
            return -1;
        }
    }
    else {
        bsize = 512;
    }


    /* Now we address the sector offset */
    offset_lcl_p = offset_lcl;

    /* remove leading 0s */
    while ((offset_lcl_p[0] != '\0') && (offset_lcl_p[0] == '0'))
        offset_lcl_p++;

    if (offset_lcl_p[0] != '\0') {
        num_blk = TSTRTOULL(offset_lcl_p, &cp, 0);
        if (*cp || *cp == *offset_lcl_p) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_IMG_OFFSET;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "tsk_parse: invalid image offset: %s", offset_lcl_p);
            return -1;
        }
        offset_b = num_blk * bsize;
    }
    else {
        offset_b = 0;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "tsk_parse_offset: Offset set to %" PRIuOFF "\n", offset_b);

    return offset_b;
}

/**
 * Convert a string to an inode, type, and id pair.  This assumes
 * the string is either:
 * INUM, INUM-TYPE, or INUM-TYPE-ID
 *
 * @param [in] str Input string to parse
 * @param [out] inum Pointer to location where inode can be stored.
 * @param [out] type Pointer to location where type can be stored (or NULL)
 * @param [out] id Pointer to location where id can be stored (or NULL)
 * @param [out] id_used Pointer to location where the value can be set
 * to 1 if the id was set (to differentiate between meanings of 0) (or NULL).
 *
 * @return 1 on error or if not an inode and 0 on success
 */
int
tsk_parse_inum(const TSK_TCHAR * str, TSK_INUM_T * inum, uint32_t * type,
    uint16_t * id, int *id_used)
{
    TSK_TCHAR *cp;
    TSK_TCHAR *tdash = NULL;
    TSK_TCHAR *tmpstr;

    if (*str == 0)
        return 1;

    if (type)
        *type = 0;
    if (id)
        *id = 0;
    if (id_used)
        *id_used = 0;

    /* Make a copy of the input string */
    tmpstr =
        (TSK_TCHAR *) tsk_malloc((TSTRLEN(str) + 1) * sizeof(TSK_TCHAR));
    if (tmpstr == NULL)
        return 1;

    TSTRNCPY(tmpstr, str, TSTRLEN(str) + 1);

    if ((tdash = TSTRCHR(tmpstr, _TSK_T('-'))) != NULL) {
        *tdash = '\0';
        tdash++;
    }

    *inum = TSTRTOULL(tmpstr, &cp, 10);
    if (*cp || *cp == *tmpstr) {
        free(tmpstr);
        return 1;
    }

    // if there was a dash, verify what follows is numbers
    if (tdash) {
        TSK_TCHAR *idash = NULL;
        uint32_t ttmp;

        if ((idash = TSTRCHR(tdash, _TSK_T('-'))) != NULL) {
            *idash = '\0';
            idash++;
        }

        ttmp = (uint32_t) TSTRTOUL(tdash, &cp, 10);
        if (*cp || *cp == *tdash) {
            free(tmpstr);
            return 1;
        }

        if (type != NULL) 
            *type = ttmp;

        // if there was a dash after type, verify it is a number after it
        if (idash) {
            uint16_t itmp;

            itmp = (uint16_t) TSTRTOUL(idash, &cp, 0);
            if (*cp || *cp == *idash) {
                free(tmpstr);
                return 1;
            }

            if (id) 
                *id = itmp;
            if (id_used)
                *id_used = 1;

        }
    }

    free(tmpstr);
    return 0;
}


