/*
 * $Date: 2007/12/19 23:12:10 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2006-2007 Brian Carrier, Basis Technology.  All rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */

/**
 * \file aff.c
 * Code to interface with afflib to read and open AFF image files
 */

#include "tsk_img_i.h"

#if HAVE_LIBAFFLIB

typedef int bool;

#include "aff.h"

static ssize_t
aff_read_random(TSK_IMG_INFO * img_info, TSK_OFF_T vol_offset, char *buf,
    size_t len, TSK_OFF_T offset)
{
    ssize_t cnt;
    IMG_AFF_INFO *aff_info = (IMG_AFF_INFO *) img_info;
    TSK_OFF_T tot_offset = offset + vol_offset;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "aff_read_random: byte offset: %" PRIuOFF " len: %" PRIuOFF
            "\n", offset, len);

    if (tot_offset > img_info->size) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_IMG_READ_OFF;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "aff_read_random - %" PRIuOFF, tot_offset);
        return -1;
    }

    if (aff_info->seek_pos != tot_offset) {
        if (af_seek(aff_info->af_file, tot_offset, SEEK_SET) != tot_offset) {
            tsk_error_reset();
            // @@@ ADD more specific error messages
            tsk_errno = TSK_ERR_IMG_SEEK;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "aff_read_random - %" PRIuOFF " - %s", tot_offset,
                strerror(errno));
            return -1;

        }
        aff_info->seek_pos = tot_offset;
    }

    cnt = af_read(aff_info->af_file, (unsigned char *) buf, len);
    if (cnt < 0) {
        // @@@ Add more specific error message
        tsk_error_reset();
        tsk_errno = TSK_ERR_IMG_READ;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "aff_read_random - offset: %" PRIuOFF " - len: %"
            PRIuOFF " - %s", tot_offset, len, strerror(errno));
        return -1;
    }

    /* AFF will return 0 if the page does not exist -- fill the 
     * buffer with zeros in this case */
    if (cnt == 0) {
        // @@@ We could improve this if there is an AFF call
        // to see if the data exists or not
        if ((af_eof(aff_info->af_file) == 0) &&
            (tot_offset + len < img_info->size)) {
            memset(buf, 0, len);
            cnt = len;
        }
    }

    aff_info->seek_pos += cnt;
    return cnt;
}

TSK_OFF_T
aff_get_size(TSK_IMG_INFO * img_info)
{
    return img_info->size;
}

void
aff_imgstat(TSK_IMG_INFO * img_info, FILE * hFile)
{
    IMG_AFF_INFO *aff_info = (IMG_AFF_INFO *) img_info;
    unsigned char buf[512];
    size_t buf_len = 512;


    tsk_fprintf(hFile, "IMAGE FILE INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Image Type: ");
    switch (aff_info->type) {
    case AF_IDENTIFY_AFF:
        tsk_fprintf(hFile, "AFF\n");
        break;
    case AF_IDENTIFY_AFD:
        tsk_fprintf(hFile, "AFD\n");
        break;
    case AF_IDENTIFY_AFM:
        tsk_fprintf(hFile, "AFM\n");
        break;
    default:
        tsk_fprintf(hFile, "?\n");
        break;
    }

    tsk_fprintf(hFile, "\nSize in bytes: %" PRIuOFF "\n", img_info->size);

    tsk_fprintf(hFile, "\nMD5: ");
    if (af_get_seg(aff_info->af_file, AF_MD5, NULL, buf, &buf_len) == 0) {
        int i;
        for (i = 0; i < 16; i++) {
            tsk_fprintf(hFile, "%x", buf[i]);
        }
        tsk_fprintf(hFile, "\n");
    }
    else {
        tsk_fprintf(hFile, "Segment not found\n");
    }

    buf_len = 512;
    tsk_fprintf(hFile, "SHA1: ");
    if (af_get_seg(aff_info->af_file, AF_SHA1, NULL, buf, &buf_len) == 0) {
        int i;
        for (i = 0; i < 20; i++) {
            tsk_fprintf(hFile, "%x", buf[i]);
        }
        tsk_fprintf(hFile, "\n");
    }
    else {
        tsk_fprintf(hFile, "Segment not found\n");
    }

    /* Creator segment */
    buf_len = 512;
    if (af_get_seg(aff_info->af_file, AF_CREATOR, NULL, buf,
            &buf_len) == 0) {
        buf[buf_len] = '\0';
        tsk_fprintf(hFile, "Creator: %s\n", buf);
    }

    buf_len = 512;
    if (af_get_seg(aff_info->af_file, AF_CASE_NUM, NULL, buf,
            &buf_len) == 0) {
        buf[buf_len] = '\0';
        tsk_fprintf(hFile, "Case Number: %s\n", buf);
    }

    buf_len = 512;
    if (af_get_seg(aff_info->af_file, AF_IMAGE_GID, NULL, buf,
            &buf_len) == 0) {
        unsigned int i;
        tsk_fprintf(hFile, "Image GID: ");
        for (i = 0; i < buf_len; i++) {
            tsk_fprintf(hFile, "%X", buf[i]);
        }
        tsk_fprintf(hFile, "\n");
    }

    buf_len = 512;
    if (af_get_seg(aff_info->af_file, AF_ACQUISITION_DATE, NULL, buf,
            &buf_len) == 0) {
        buf[buf_len] = '\0';
        tsk_fprintf(hFile, "Acquisition Date: %s\n", buf);
    }

    buf_len = 512;
    if (af_get_seg(aff_info->af_file, AF_ACQUISITION_NOTES, NULL, buf,
            &buf_len) == 0) {
        buf[buf_len] = '\0';
        tsk_fprintf(hFile, "Acquisition Notes: %s\n", buf);
    }

    buf_len = 512;
    if (af_get_seg(aff_info->af_file, AF_ACQUISITION_DEVICE, NULL, buf,
            &buf_len) == 0) {
        buf[buf_len] = '\0';
        tsk_fprintf(hFile, "Acquisition Device: %s\n", buf);
    }

    buf_len = 512;
    if (af_get_seg(aff_info->af_file, AF_AFFLIB_VERSION, NULL, buf,
            &buf_len) == 0) {
        buf[buf_len] = '\0';
        tsk_fprintf(hFile, "AFFLib Version: %s\n", buf);
    }

    buf_len = 512;
    if (af_get_seg(aff_info->af_file, AF_DEVICE_MANUFACTURER, NULL, buf,
            &buf_len) == 0) {
        buf[buf_len] = '\0';
        tsk_fprintf(hFile, "Device Manufacturer: %s\n", buf);
    }

    buf_len = 512;
    if (af_get_seg(aff_info->af_file, AF_DEVICE_MODEL, NULL, buf,
            &buf_len) == 0) {
        buf[buf_len] = '\0';
        tsk_fprintf(hFile, "Device Model: %s\n", buf);
    }

    buf_len = 512;
    if (af_get_seg(aff_info->af_file, AF_DEVICE_SN, NULL, buf,
            &buf_len) == 0) {
        buf[buf_len] = '\0';
        tsk_fprintf(hFile, "Device SN: %s\n", buf);
    }

    return;
}

void
aff_close(TSK_IMG_INFO * img_info)
{
    IMG_AFF_INFO *aff_info = (IMG_AFF_INFO *) img_info;
    af_close(aff_info->af_file);
    talloc_free(aff_info);
}


TSK_IMG_INFO *
aff_open(const char **images, TSK_IMG_INFO * next)
{
    IMG_AFF_INFO *aff_info;
    TSK_IMG_INFO *img_info;
    int type;

    if (next != NULL) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_IMG_LAYERS;
        snprintf(tsk_errstr, TSK_ERRSTR_L, "AFF must be lowest layer");
        return NULL;
    }

    aff_info = talloc(NULL, IMG_AFF_INFO);
    if (aff_info == NULL) {
        return NULL;
    }
    memset((void *) aff_info, 0, sizeof(IMG_AFF_INFO));

    img_info = (TSK_IMG_INFO *) aff_info;

    img_info->read_random = aff_read_random;
    img_info->get_size = aff_get_size;
    img_info->close = aff_close;
    img_info->imgstat = aff_imgstat;


    type = af_identify_file_type(images[0], 1);
    if ((type == AF_IDENTIFY_ERR) || (type == AF_IDENTIFY_NOEXIST)) {
        if (tsk_verbose) {
            tsk_fprintf(stderr,
                "aff_open: Error determining type of file: %" PRIttocTSK
                "\n", images[0]);
            perror("aff_open");
        }
        tsk_error_reset();
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "aff_open file: %" PRIttocTSK ": Error checking type",
            images[0]);
        tsk_errstr2[0] = '\0';
        talloc_free(aff_info);
        return NULL;
    }
    else if (type == AF_IDENTIFY_AFF) {
        img_info->itype = TSK_IMG_INFO_TYPE_AFF_AFF;
    }
    else if (type == AF_IDENTIFY_AFD) {
        img_info->itype = TSK_IMG_INFO_TYPE_AFF_AFD;
    }
    else if (type == AF_IDENTIFY_AFM) {
        img_info->itype = TSK_IMG_INFO_TYPE_AFF_AFM;
    }
//    else if ((type == AF_IDENTIFY_EVF) || (type ==AF_IDENTIFY_EVD  )) {
//      img_info->itype = TSK_IMG_INFO_TYPE_AFF_AFF;
    //   }
    else {
        tsk_error_reset();
        tsk_errno = TSK_ERR_IMG_MAGIC;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "aff_open: Not an AFF, AFD, or AFM file");
        talloc_free(aff_info);
        if (tsk_verbose)
            tsk_fprintf(stderr, "Not an AFF/AFD/AFM file\n");

        return NULL;
    }

    aff_info->af_file = af_open(images[0], O_RDONLY, 0);
    if (!aff_info->af_file) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_IMG_OPEN;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "aff_open file: %" PRIttocTSK ": Error opening - %s",
            images[0], strerror(errno));
        talloc_free(aff_info);
        if (tsk_verbose) {
            tsk_fprintf(stderr, "Error opening AFF/AFD/AFM file\n");
            perror("aff_open");
        }
        return NULL;
    }
    aff_info->type = type;

    img_info->size = af_imagesize(aff_info->af_file);

    af_seek(aff_info->af_file, 0, SEEK_SET);
    aff_info->seek_pos = 0;

    return img_info;
}
#endif
