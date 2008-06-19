/* 
 * The Sleuth Kit
 *
 * $Date: 2007/12/18 22:43:53 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
 *
 */
 
/**
 * \file tsk_dos.h
 * C header file with DOS and internal data structures. 
 */
#ifndef _TSK_DOS_H
#define _TSK_DOS_H

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct {
        uint8_t boot;
        uint8_t start_chs[3];
        uint8_t ptype;
        uint8_t end_chs[3];
        uint8_t start_sec[4];
        uint8_t size_sec[4];
    } dos_part;

/* Boot Sector w/partition table */
    typedef struct {
        uint8_t f1[3];
        /* the next three are actually part of NTFS and FAT, but
         * we use them for sanity checks in the detect code */
        char oemname[8];
        uint8_t ssize[2];       /* sector size in bytes */
        uint8_t csize;          /* cluster size in sectors */
        uint8_t filler[432];
        dos_part ptable[4];
        uint8_t magic[2];
    } dos_sect;

#define DOS_MAGIC	0xaa55
#define DOS_PART_SOFFSET 0

#ifdef __cplusplus
}
#endif
#endif
