/*
 * $Date: 2007/12/20 20:32:38 $
 *
 * Joachim Metz <forensics@hoffmannbv.nl>, Hoffmann Investigations
 * Copyright (c) 2006 Joachim Metz.  All rights reserved 
 *
 * ewf
 *
 * This software is distributed under the Common Public License 1.0
 */

/** \file ewf.c
 * Contains the functions for TSK to interface with libewf.
 */

#include "tsk_img_i.h"

#if HAVE_LIBEWF
#include "ewf.h"

static ssize_t
ewf_image_read_random(TSK_IMG_INFO * img_info, TSK_OFF_T vol_offset,
    char *buf, size_t len, TSK_OFF_T offset)
{
    ssize_t cnt;
    IMG_EWF_INFO *ewf_info = (IMG_EWF_INFO *) img_info;
    TSK_OFF_T tot_offset = offset + vol_offset;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "ewf_read_random: byte offset: %" PRIuOFF " len: %" PRIuOFF
            "\n", offset, len);

    if (tot_offset > img_info->size) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_IMG_READ_OFF;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "split_read_random - %" PRIuOFF, tot_offset);
        return -1;
    }

    cnt = libewf_read_random(ewf_info->handle, buf, len, tot_offset);
    if (cnt < 0) {
        tsk_error_reset();
        // @@@ Add more specific error message
        tsk_error_reset();
        tsk_errno = TSK_ERR_IMG_READ;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "ewf_read_random - offset: %" PRIuOFF " - len: %"
            PRIuOFF " - %s", tot_offset, len, strerror(errno));
        return -1;
    }

    return cnt;
}

TSK_OFF_T
ewf_image_get_size(TSK_IMG_INFO * img_info)
{
    return img_info->size;
}

void
ewf_image_imgstat(TSK_IMG_INFO * img_info, FILE * hFile)
{
    IMG_EWF_INFO *ewf_info = (IMG_EWF_INFO *) img_info;

    tsk_fprintf(hFile, "IMAGE FILE INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Image Type:\t\tewf\n");
    tsk_fprintf(hFile, "\nSize of data in bytes:\t%" PRIuOFF "\n",
        img_info->size);

    if (ewf_info->md5hash_isset == 1) {
        tsk_fprintf(hFile, "MD5 hash of data:\t%s\n", ewf_info->md5hash);
    }
    return;
}

void
ewf_image_close(TSK_IMG_INFO * img_info)
{
    IMG_EWF_INFO *ewf_info = (IMG_EWF_INFO *) img_info;

    libewf_close(ewf_info->handle);
    free(img_info);
}

/* Tests if the image file header against the
 * header (magic) signature specified.
 * Returns a 0 on no match and a 1 on a match, and -1 on error.
 */
int
img_file_header_signature_ncmp(const char *filename,
    const char *file_header_signature, int size_of_signature)
{
    int match;
    ssize_t read_count = 0;
    char header[512];
    int fd;

    if ((filename == NULL) || (file_header_signature == NULL)) {
        return (0);
    }
    if (size_of_signature <= 0) {
        return (0);
    }

    if ((fd = open(filename, O_RDONLY)) < 0) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_IMG_OPEN;
        snprintf(tsk_errstr, TSK_ERRSTR_L, "ewf magic testing: %s",
            filename);
        return -1;
    }
    read_count = read(fd, header, 512);

    if (read_count != 512) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_IMG_READ;
        snprintf(tsk_errstr, TSK_ERRSTR_L, "ewf magic testing: %s",
            filename);
        return -1;
    }
    close(fd);

    match = strncmp(file_header_signature, header, size_of_signature) == 0;

    return (match);
}


TSK_IMG_INFO *
ewf_open(int num_img, const char **images, TSK_IMG_INFO * next)
{
    IMG_EWF_INFO *ewf_info;
    TSK_IMG_INFO *img_info;
#if !defined( LIBEWF_STRING_DIGEST_HASH_LENGTH_MD5 )
    uint8_t md5_hash[16];
#endif

    if (next != NULL) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_IMG_LAYERS;
        snprintf(tsk_errstr, TSK_ERRSTR_L, "EWF must be lowest layer");
        return NULL;
    }

    ewf_info = (IMG_EWF_INFO *) tsk_malloc(sizeof(IMG_EWF_INFO));
    if (ewf_info == NULL) {
        return NULL;
    }
    memset((void *) ewf_info, 0, sizeof(IMG_EWF_INFO));

    img_info = (TSK_IMG_INFO *) ewf_info;

    /* check the magic before we call the library open */
    if (img_file_header_signature_ncmp(images[0],
            "\x45\x56\x46\x09\x0d\x0a\xff\x00", 8) != 1) {
        //   if (libewf_check_file_signature(images[0]) == 0) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_IMG_MAGIC;
        snprintf(tsk_errstr, TSK_ERRSTR_L, "ewf_open: Not an EWF file");
        free(ewf_info);
        if (tsk_verbose)
            tsk_fprintf(stderr, "Not an EWF file\n");

        return NULL;
    }

    ewf_info->handle =
        libewf_open((char *const *) images, num_img, LIBEWF_OPEN_READ);
    if (ewf_info->handle == NULL) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_IMG_OPEN;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "ewf_open file: %" PRIttocTSK ": Error opening", images[0]);
        free(ewf_info);
        if (tsk_verbose) {
            tsk_fprintf(stderr, "Error opening EWF file\n");
        }
        return NULL;
    }

// 2007 version
#if defined( LIBEWF_STRING_DIGEST_HASH_LENGTH_MD5 )
    img_info->size = libewf_get_media_size(ewf_info->handle);
    ewf_info->md5hash_isset = libewf_get_stored_md5_hash(ewf_info->handle,
        ewf_info->md5hash, TSK_EWF_MD5_DIGEST_HASH_LENGTH);
// libewf-20080322 version
#else
    if (libewf_get_media_size(ewf_info->handle,
            (size64_t *) & (img_info->size))
        != 1) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_IMG_OPEN;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "ewf_open file: %" PRIttocTSK ": Error getting size", images[0]);
        free(ewf_info);
        if (tsk_verbose) {
            tsk_fprintf(stderr, "Error getting size of EWF file\n");
        }
        return NULL;
    }
    if (libewf_get_md5_hash(ewf_info->handle, md5_hash, 16) == 1) {
        int md5_string_iterator = 0;
        int md5_hash_iterator;
        for (md5_hash_iterator = 0; md5_hash_iterator < 16;
            md5_hash_iterator++) {
            int digit = md5_hash[md5_hash_iterator] / 16;
            if (digit <= 9)
                ewf_info->md5hash[md5_string_iterator++] = (char)
                    ('0' + digit);
            else
                ewf_info->md5hash[md5_string_iterator++] = (char) ('a' +
                    (digit - 10));
            digit = md5_hash[md5_hash_iterator] % 16;
            if (digit <= 9)
                ewf_info->md5hash[md5_string_iterator++] =
                    (char) ('0' + digit);
            else
                ewf_info->md5hash[md5_string_iterator++] = (char) ('a' +
                    (digit - 10));
        }
        ewf_info->md5hash_isset = 1;
    }
#endif

    img_info->itype = TSK_IMG_INFO_TYPE_EWF_EWF;
    img_info->read_random = ewf_image_read_random;
    img_info->get_size = ewf_image_get_size;
    img_info->close = ewf_image_close;
    img_info->imgstat = ewf_image_imgstat;

    return img_info;
}
#endif
