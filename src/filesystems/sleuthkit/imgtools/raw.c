/*
 * $Date: 2007/04/04 20:06:59 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2006 Brian Carrier, Basis Technology.  All rights reserved
 * Copyright (c) 2005 Brian Carrier.  All rights reserved
 *
 * raw
 *
 * This software is distributed under the Common Public License 1.0
 *
 */


#include <sys/stat.h>
#include "img_tools.h"
#include "raw.h"

#ifdef TSK_WIN32
#include "Winioctl.h"
#endif

/* Return the size read and -1 if error */
static SSIZE_T
raw_read_random(TSK_IMG_INFO * img_info, OFF_T vol_offset, char *buf,
    OFF_T len, OFF_T offset)
{
    SSIZE_T cnt;
    IMG_RAW_INFO *raw_info = (IMG_RAW_INFO *) img_info;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "raw_read_random: byte offset: %" PRIuOFF " len: %" PRIuOFF
            "\n", offset, len);

    // is there another layer?
    if (img_info->next) {
        return img_info->next->read_random(img_info->next, vol_offset, buf,
            len, offset);
    }

    // Read the data
    else {
        OFF_T tot_offset = offset + vol_offset;

#ifdef TSK_WIN32
        {
            DWORD nread;

            if (raw_info->seek_pos != tot_offset) {
                LONG lo, hi;
                OFF_T max = (OFF_T) MAXLONG + 1;

                hi = (LONG) (tot_offset / max);
                lo = (LONG) (tot_offset - max * hi);

                if (0xFFFFFFFF == SetFilePointer(raw_info->fd, lo, &hi,
                        FILE_BEGIN)) {
                    tsk_error_reset();
                    tsk_errno = TSK_ERR_IMG_SEEK;
                    snprintf(tsk_errstr, TSK_ERRSTR_L,
                        "raw_read_random - %" PRIuOFF, tot_offset);
                    return -1;
                }
                raw_info->seek_pos = tot_offset;
            }

            if (FALSE == ReadFile(raw_info->fd, buf, (DWORD) len,
                    &nread, NULL)) {
                tsk_error_reset();
                tsk_errno = TSK_ERR_IMG_READ;
                snprintf(tsk_errstr, TSK_ERRSTR_L,
                    "raw_read_random - offset: %" PRIuOFF " - len: %"
                    PRIuOFF, tot_offset, len);
                return -1;
            }
            cnt = (SSIZE_T) nread;
        }
#else
        if (raw_info->seek_pos != tot_offset) {
            if (lseek(raw_info->fd, tot_offset, SEEK_SET) != tot_offset) {
                tsk_error_reset();
                tsk_errno = TSK_ERR_IMG_SEEK;
                snprintf(tsk_errstr, TSK_ERRSTR_L,
                    "raw_read_random - %" PRIuOFF " - %s",
                    tot_offset, strerror(errno));
                return -1;
            }
            raw_info->seek_pos = tot_offset;
        }

        cnt = read(raw_info->fd, buf, len);
        if (cnt < 0) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_IMG_READ;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "raw_read_random - offset: %" PRIuOFF " - len: %"
                PRIuOFF " - %s", tot_offset, len, strerror(errno));
            return -1;
        }
#endif
        raw_info->seek_pos += cnt;
        return cnt;
    }
}

OFF_T
raw_get_size(TSK_IMG_INFO * img_info)
{
    return img_info->size;
}

void
raw_imgstat(TSK_IMG_INFO * img_info, FILE * hFile)
{
    tsk_fprintf(hFile, "IMAGE FILE INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Image Type: raw\n");
    tsk_fprintf(hFile, "\nSize in bytes: %" PRIuOFF "\n", img_info->size);
    return;
}

void
raw_close(TSK_IMG_INFO * img_info)
{
    IMG_RAW_INFO *raw_info = (IMG_RAW_INFO *) img_info;
#ifdef TSK_WIN32
    CloseHandle(raw_info->fd);
#else
    close(raw_info->fd);
#endif
    free(raw_info);
}


/*
 *  Open the file as a raw image.  Return the TSK_IMG_INFO structure
 *  or NULL if the file cannot be opened.  There are no magic values
 *  to test for a raw file
 */
TSK_IMG_INFO *
raw_open(const TSK_TCHAR ** images, TSK_IMG_INFO * next)
{
    IMG_RAW_INFO *raw_info;
    TSK_IMG_INFO *img_info;

    if ((raw_info =
            (IMG_RAW_INFO *) tsk_malloc(sizeof(IMG_RAW_INFO))) == NULL)
        return NULL;

    memset((void *) raw_info, 0, sizeof(IMG_RAW_INFO));

    img_info = (TSK_IMG_INFO *) raw_info;

    img_info->itype = TSK_IMG_INFO_TYPE_RAW_SING;
    img_info->read_random = raw_read_random;
    img_info->get_size = raw_get_size;
    img_info->close = raw_close;
    img_info->imgstat = raw_imgstat;

    if (next) {
        img_info->next = next;
        img_info->size = next->get_size(next);
    }

    /* Open the file */
    else {
        struct STAT_STR stat_buf;
        int is_winobj = 0;

#ifdef TSK_WIN32
        if ((images[0][0] == _TSK_T('\\'))
            && (images[0][1] == _TSK_T('\\'))
            && (images[0][2] == _TSK_T('.'))
            && (images[0][3] == _TSK_T('\\'))) {
            is_winobj = 1;
        }
#endif
        if (is_winobj == 0) {
            /* Exit if we are given a directory */
            if (TSTAT(images[0], &stat_buf) < 0) {
                tsk_error_reset();
                tsk_errno = TSK_ERR_IMG_STAT;
                snprintf(tsk_errstr, TSK_ERRSTR_L,
                    "raw_open directory check: %s", strerror(errno));
                return NULL;
            }
            else if ((stat_buf.st_mode & S_IFMT) == S_IFDIR) {
                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "raw_open: image %s is a directory\n", images[0]);

                tsk_error_reset();
                tsk_errno = TSK_ERR_IMG_MAGIC;
                snprintf(tsk_errstr, TSK_ERRSTR_L,
                    "raw_open: Image is a directory");
                return NULL;
            }
        }

#ifdef TSK_WIN32
        {
            DWORD dwHi, dwLo;

            if ((raw_info->fd = CreateFile(images[0], GENERIC_READ,
                        FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0)) ==
                INVALID_HANDLE_VALUE) {
                tsk_error_reset();
                tsk_errno = TSK_ERR_IMG_OPEN;
                snprintf(tsk_errstr, TSK_ERRSTR_L,
                    "raw_open file: %s msg: %d", images[0],
                    GetLastError());
                return NULL;
            }

            /* We need different techniques to determine the size of physical
             * devices versus normal files
             */
            if (is_winobj == 0) {
                dwLo = GetFileSize(raw_info->fd, &dwHi);
                if (dwLo == 0xffffffff) {
                    tsk_error_reset();
                    tsk_errno = TSK_ERR_IMG_OPEN;
                    snprintf(tsk_errstr, TSK_ERRSTR_L,
                        "raw_open file: %s GetFileSize: %d", images[0],
                        GetLastError());
                    return NULL;
                }
                img_info->size = dwLo | ((OFF_T) dwHi << 32);
            }
            else {
                DISK_GEOMETRY pdg;
                DWORD junk;

                if (FALSE == DeviceIoControl(raw_info->fd,      // device to be queried
                        IOCTL_DISK_GET_DRIVE_GEOMETRY,  // operation to perform
                        NULL, 0, &pdg, sizeof(pdg), &junk,
                        (LPOVERLAPPED) NULL)) {
                    tsk_error_reset();
                    tsk_errno = TSK_ERR_IMG_OPEN;
                    snprintf(tsk_errstr, TSK_ERRSTR_L,
                        "raw_open file: %s DeviceIoControl: %d", images[0],
                        GetLastError());
                    return NULL;
                }

                img_info->size =
                    pdg.Cylinders.QuadPart *
                    (ULONG) pdg.TracksPerCylinder *
                    (ULONG) pdg.SectorsPerTrack *
                    (ULONG) pdg.BytesPerSector;
            }
        }
#else
        if ((raw_info->fd = open(images[0], O_RDONLY)) < 0) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_IMG_OPEN;
            snprintf(tsk_errstr, TSK_ERRSTR_L, "raw_open file: %s msg: %s",
                images[0], strerror(errno));
            return NULL;
        }

        /* We don't use the stat output because it doesn't work on raw
         * devices and such */
        img_info->size = lseek(raw_info->fd, 0, SEEK_END);
        lseek(raw_info->fd, 0, SEEK_SET);
#endif
        raw_info->seek_pos = 0;
    }

    return img_info;
}
