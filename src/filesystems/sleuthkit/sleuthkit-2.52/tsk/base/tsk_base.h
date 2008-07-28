/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2007 Brian Carrier.  All Rights reserved
 *
 * $Date: 2007/12/20 20:32:38 $
 */
 
/** \file tsk_base.h
 * Contains the type and function definitions that are needed
 * by external programs to use the TSK library.  
 * Note that this file is not meant to be directly included.   
 * It is included by both libtsk.h and tsk_base_i.h.
 */
#ifndef _TSK_BASE_H
#define _TSK_BASE_H

// standard C header files
#include <stdio.h>
#include <stdlib.h>

/* include the TSK-specific header file that we created in autoconf
 * On Win32 though, we will not have this file...
 */
#if !defined(_WIN32) && !defined (__WIN32__)
#include "tsk/tsk_incs.h"
#endif

// get some other TSK / OS settings
#include "tsk_os.h"

#ifdef __cplusplus
extern "C" {
#endif



/**
 * Return values for some TSK functions that need to differentiate between errors and corrupt data.
 */
typedef enum {
    TSK_OK,     ///< Ok -- success
    TSK_ERR,    ///< System error -- should abort
    TSK_COR     ///< Data is corrupt, can still process another set of data
} TSK_RETVAL_ENUM;


/** \name List Structure */
//@{
    typedef struct TSK_LIST TSK_LIST;
    /** 
     * Linked list structure that holds a 'key' and optional 'length'.
     * The length is used for run lists.
     */
    struct TSK_LIST {
        TSK_LIST *next; ///< Pointer to next entry in list
        uint64_t key;   ///< Key that is used for sorting 
        uint64_t len;   ///< Length value (of run)
    };

    extern uint8_t tsk_list_add(void *context, TSK_LIST ** list, uint64_t key);
    extern uint8_t tsk_list_find(TSK_LIST * list, uint64_t key);
    extern void tsk_list_free(TSK_LIST * list);
//@}


/** \name Cross-platform printf */
//@{
    extern void tsk_fprintf(FILE * fd, const char *msg, ...);
    //extern void tsk_snprintf(WCHAR *wbuf, int wlen, char *msg, ...);
    extern void tsk_printf(const char *msg, ...);
//@}



/** \name printf macros if system does not define them */
//@{
#ifndef PRIx64
#define PRIx64 "llx"
#endif

#ifndef PRIX64
#define PRIX64 "llX"
#endif

#ifndef PRIu64
#define PRIu64 "llu"
#endif

#ifndef PRId64
#define PRId64 "lld"
#endif

#ifndef PRIo64
#define PRIo64 "llo"
#endif

#ifndef PRIx32
#define PRIx32 "x"
#endif

#ifndef PRIX32
#define PRIX32 "X"
#endif

#ifndef PRIu32
#define PRIu32 "u"
#endif

#ifndef PRId32
#define PRId32 "d"
#endif

#ifndef PRIx16
#define PRIx16 "hx"
#endif

#ifndef PRIX16
#define PRIX16 "hX"
#endif

#ifndef PRIu16
#define PRIu16 "hu"
#endif

#ifndef PRIu8
#define PRIu8 "hhu"
#endif

#ifndef PRIx8
#define PRIx8 "hhx"
#endif
//@}



/** @name  Internal integer types and printf macros*/
//@{
    typedef uint64_t TSK_INUM_T;    ///< Data type used to internally store metadata / inode addresses
#define PRIuINUM	PRIu64
#define PRIxINUM	PRIx64
#define PRIdINUM	PRId64

    typedef uint32_t TSK_UID_T; ///< Data type used to internally store User IDs
#define PRIuUID	    PRIu32
#define PRIxUID	    PRIx32
#define PRIdUID	    PRId32

    typedef uint32_t TSK_GID_T; ///< Data type used to internally store Group IDs
#define PRIuGID	    PRIu32
#define PRIxGID	    PRIx32
#define PRIdGID	    PRId32

    typedef uint64_t TSK_DADDR_T; ///< Data type used to internally store sector and block addresses
#define PRIuDADDR   PRIu64
#define PRIxDADDR   PRIx64
#define PRIdDADDR   PRId64

    typedef int64_t TSK_OFF_T; ///< Data type used to internally store volume, file, etc. sizes and offsets
#define PRIuOFF		PRIu64
#define PRIxOFF		PRIx64
#define PRIdOFF		PRId64

    typedef uint32_t TSK_PNUM_T; ///< Data type used to internally store partition addresses 
#define PRIuPNUM	PRIu32
#define PRIxPNUM	PRIx32
#define PRIdPNUM	PRId32
//@}


    extern void tsk_print_version(FILE *);
    extern const char *tskGetVersion();


/*********** RETURN VALUES ************/

/**
 * Values that callback functions can return to calling walk function. 
 */
typedef enum {
    TSK_WALK_CONT = 0x0,     ///< Walk function should continue to next object
    TSK_WALK_STOP = 0x1,     ///< Walk function should stop processing units and return OK
    TSK_WALK_ERROR = 0x2,     ///< Walk function should stop processing units and return error
} TSK_WALK_RET_ENUM;


/************ ERROR HANDLING *************/
    extern int tsk_verbose;     ///< Set to 1 to have verbose debug messages printed to stderr

    /** \name Error Handling */
//@{
#define TSK_ERRSTR_L	512
#define TSK_ERRSTR_PR_L	(TSK_ERRSTR_L << 2)

    extern uint32_t tsk_errno;
    extern char tsk_errstr[TSK_ERRSTR_L];
    extern char tsk_errstr2[TSK_ERRSTR_L];
    extern char tsk_errstr_print[TSK_ERRSTR_PR_L];

    extern const char *tsk_error_get();
    extern void tsk_error_print(FILE *);
    extern void tsk_error_reset();

#define TSK_ERR_AUX	0x01000000
#define TSK_ERR_IMG	0x02000000
#define TSK_ERR_MM	0x04000000
#define TSK_ERR_FS	0x08000000
#define TSK_ERR_HDB	0x10000000
#define TSK_ERR_MASK	0x00ffffff

#define TSK_ERR_AUX_MALLOC	(TSK_ERR_AUX | 0)
#define TSK_ERR_AUX_MAX		2

#define TSK_ERR_IMG_NOFILE	(TSK_ERR_IMG | 0)
#define TSK_ERR_IMG_OFFSET	(TSK_ERR_IMG | 1)
#define TSK_ERR_IMG_UNKTYPE	(TSK_ERR_IMG | 2)
#define TSK_ERR_IMG_UNSUPTYPE 	(TSK_ERR_IMG | 3)
#define TSK_ERR_IMG_OPEN 	(TSK_ERR_IMG | 4)
#define TSK_ERR_IMG_STAT	(TSK_ERR_IMG | 5)
#define TSK_ERR_IMG_SEEK	(TSK_ERR_IMG | 6)
#define TSK_ERR_IMG_READ	(TSK_ERR_IMG | 7)
#define TSK_ERR_IMG_READ_OFF	(TSK_ERR_IMG | 8)
#define TSK_ERR_IMG_LAYERS	(TSK_ERR_IMG | 9)
#define TSK_ERR_IMG_MAGIC	(TSK_ERR_IMG | 10)
#define TSK_ERR_IMG_WRITE	(TSK_ERR_IMG | 11)
#define TSK_ERR_IMG_MAX		12

#define TSK_ERR_MM_UNKTYPE	(TSK_ERR_MM | 0)
#define TSK_ERR_MM_UNSUPTYPE	(TSK_ERR_MM | 1)
#define TSK_ERR_MM_READ		(TSK_ERR_MM | 2)
#define TSK_ERR_MM_MAGIC	(TSK_ERR_MM | 3)
#define TSK_ERR_MM_WALK_RNG	(TSK_ERR_MM | 4)
#define TSK_ERR_MM_BUF		(TSK_ERR_MM | 5)
#define TSK_ERR_MM_BLK_NUM	(TSK_ERR_MM | 6)
#define TSK_ERR_MM_MAX		7

#define TSK_ERR_FS_UNKTYPE	(TSK_ERR_FS | 0)
#define TSK_ERR_FS_UNSUPTYPE	(TSK_ERR_FS | 1)
#define TSK_ERR_FS_FUNC		(TSK_ERR_FS | 2)
#define TSK_ERR_FS_WALK_RNG	(TSK_ERR_FS | 3)
#define TSK_ERR_FS_READ		(TSK_ERR_FS | 4)
#define TSK_ERR_FS_ARG		(TSK_ERR_FS | 5)
#define TSK_ERR_FS_BLK_NUM	(TSK_ERR_FS | 6)
#define TSK_ERR_FS_INODE_NUM	(TSK_ERR_FS | 7)
#define TSK_ERR_FS_INODE_INT	(TSK_ERR_FS | 8)
#define TSK_ERR_FS_MAGIC	(TSK_ERR_FS | 9)
#define TSK_ERR_FS_FWALK	(TSK_ERR_FS | 10)
#define TSK_ERR_FS_WRITE	(TSK_ERR_FS | 11)
#define TSK_ERR_FS_UNICODE	(TSK_ERR_FS | 12)
#define TSK_ERR_FS_RECOVER	(TSK_ERR_FS | 13)
#define TSK_ERR_FS_GENFS	(TSK_ERR_FS | 14)
#define TSK_ERR_FS_CORRUPT	(TSK_ERR_FS | 15)
#define TSK_ERR_FS_MAX		16


#define TSK_ERR_HDB_UNKTYPE     (TSK_ERR_HDB | 0)
#define TSK_ERR_HDB_UNSUPTYPE   (TSK_ERR_HDB | 1)
#define TSK_ERR_HDB_READDB	(TSK_ERR_HDB | 2)
#define TSK_ERR_HDB_READIDX	(TSK_ERR_HDB | 3)
#define TSK_ERR_HDB_ARG		(TSK_ERR_HDB | 4)
#define TSK_ERR_HDB_WRITE	(TSK_ERR_HDB | 5)
#define TSK_ERR_HDB_CREATE	(TSK_ERR_HDB | 6)
#define TSK_ERR_HDB_DELETE      (TSK_ERR_HDB | 7)
#define TSK_ERR_HDB_MISSING     (TSK_ERR_HDB | 8)
#define TSK_ERR_HDB_PROC        (TSK_ERR_HDB | 9)
#define TSK_ERR_HDB_OPEN        (TSK_ERR_HDB | 10)
#define TSK_ERR_HDB_CORRUPT     (TSK_ERR_HDB | 11)
#define TSK_ERR_HDB_MAX		12

//@}


/** \name Endian Ordering Functions */
//@{
    /** 
     * Flag that identifies the endian ordering of the data being read.
     */
typedef enum {
    TSK_LIT_ENDIAN=	0x01,   ///< Data is in little endian
    TSK_BIG_ENDIAN=	0x02    ///< Data is in big endian
} TSK_ENDIAN_ENUM;

/* macros to read in multi-byte fields
 * file system is an array of 8-bit values, not 32-bit values
 */
    extern uint8_t tsk_guess_end_u16(TSK_ENDIAN_ENUM *, uint8_t *, uint16_t);
    extern uint8_t tsk_guess_end_u32(TSK_ENDIAN_ENUM *, uint8_t *, uint32_t);

/** \internal
 * Read a 16-bit unsigned value.
 * @param endian Flag that identifies local ordering.
 * @param x Byte array to read from
 * @returns 16-bit unsigned value
 */
#define tsk_getu16(endian, x)   \
    (uint16_t)(((endian) == TSK_LIT_ENDIAN) ? \
	  (((uint8_t *)(x))[0] + (((uint8_t *)(x))[1] << 8)) :    \
	  (((uint8_t *)(x))[1] + (((uint8_t *)(x))[0] << 8)) )

/** \internal
 * Read a 16-bit signed value.
 * @param endian Flag that identifies local ordering.
 * @param x Byte array to read from
 * @returns 16-bit signed value
 */
#define tsk_gets16(endian, x)	\
	((int16_t)tsk_getu16(endian, x))


/** \internal
 * Read a 32-bit unsigned value.
 * @param endian Flag that identifies local ordering.
 * @param x Byte array to read from
 * @returns 32-bit unsigned value
 */
#define tsk_getu32(endian, x)	\
	(uint32_t)( ((endian) == TSK_LIT_ENDIAN)  ?	\
     ((((uint8_t *)(x))[0] <<  0) + \
	  (((uint8_t *)(x))[1] <<  8) + \
	  (((uint8_t *)(x))[2] << 16) + \
	  (((uint8_t *)(x))[3] << 24) ) \
	:	\
	 ((((uint8_t *)(x))[3] <<  0) + \
	  (((uint8_t *)(x))[2] <<  8) + \
	  (((uint8_t *)(x))[1] << 16) + \
	  (((uint8_t *)(x))[0] << 24) ) )

/** \internal
 * Read a 32-bit signed value.
 * @param endian Flag that identifies local ordering.
 * @param x Byte array to read from
 * @returns 32-bit signed value
 */
#define tsk_gets32(endian, x)	\
	((int32_t)tsk_getu32(endian, x))

/** \internal
 * Read a 48-bit unsigned value.
 * @param endian Flag that identifies local ordering.
 * @param x Byte array to read from
 * @returns 48-bit unsigned value
 */
#define tsk_getu48(endian, x)   \
	(uint64_t)( ((endian) == TSK_LIT_ENDIAN)  ?	\
      ((uint64_t) \
	  ((uint64_t)((uint8_t *)(x))[0] <<  0)+ \
	  ((uint64_t)((uint8_t *)(x))[1] <<  8) + \
      ((uint64_t)((uint8_t *)(x))[2] << 16) + \
	  ((uint64_t)((uint8_t *)(x))[3] << 24) + \
      ((uint64_t)((uint8_t *)(x))[4] << 32) + \
      ((uint64_t)((uint8_t *)(x))[5] << 40)) \
	: \
      ((uint64_t) \
	  ((uint64_t)((uint8_t *)(x))[5] <<  0)+ \
	  ((uint64_t)((uint8_t *)(x))[4] <<  8) + \
      ((uint64_t)((uint8_t *)(x))[3] << 16) + \
	  ((uint64_t)((uint8_t *)(x))[2] << 24) + \
      ((uint64_t)((uint8_t *)(x))[1] << 32) + \
      ((uint64_t)((uint8_t *)(x))[0] << 40)) )


/** \internal
 * Read a 64-bit unsigned value.
 * @param endian Flag that identifies local ordering.
 * @param x Byte array to read from
 * @returns 64-bit unsigned value
 */
#define tsk_getu64(endian, x)   \
	(uint64_t)( ((endian) == TSK_LIT_ENDIAN)  ?	\
      ((uint64_t) \
	  ((uint64_t)((uint8_t *)(x))[0] << 0)  + \
	  ((uint64_t)((uint8_t *)(x))[1] << 8) + \
      ((uint64_t)((uint8_t *)(x))[2] << 16) + \
	  ((uint64_t)((uint8_t *)(x))[3] << 24) + \
      ((uint64_t)((uint8_t *)(x))[4] << 32) + \
      ((uint64_t)((uint8_t *)(x))[5] << 40) + \
      ((uint64_t)((uint8_t *)(x))[6] << 48) + \
      ((uint64_t)((uint8_t *)(x))[7] << 56)) \
	: \
      ((uint64_t) \
	  ((uint64_t)((uint8_t *)(x))[7] <<  0) + \
	  ((uint64_t)((uint8_t *)(x))[6] <<  8) + \
      ((uint64_t)((uint8_t *)(x))[5] << 16) + \
	  ((uint64_t)((uint8_t *)(x))[4] << 24) + \
      ((uint64_t)((uint8_t *)(x))[3] << 32) + \
      ((uint64_t)((uint8_t *)(x))[2] << 40) + \
      ((uint64_t)((uint8_t *)(x))[1] << 48) + \
      ((uint64_t)((uint8_t *)(x))[0] << 56)) )

/** \internal
 * Read a 64-bit signed value.
 * @param endian Flag that identifies local ordering.
 * @param x Byte array to read from
 * @returns 64-bit signed value
 */
#define tsk_gets64(endian, x)	\
	((int64_t)tsk_getu64(endian, x))

//@}




/** 
 * Data structure used to hold blobs of data along with the address from where it came.
 */
    typedef struct {
        char *data;     ///< Buffer for data
        size_t size;    ///< Size of buffer
        size_t used;    ///< Amount of buffer used
        TSK_DADDR_T addr;   ///< Address of data source
    } TSK_DATA_BUF;

    extern TSK_DATA_BUF *tsk_data_buf_alloc(void *context, size_t);
    extern void tsk_data_buf_free(TSK_DATA_BUF *);



    extern TSK_OFF_T tsk_parse_offset(const TSK_TCHAR *);
    extern int tsk_parse_inum(const TSK_TCHAR * str, TSK_INUM_T *, uint32_t *,
        uint16_t *, int *);


// getopt and windows stuff

#ifdef TSK_WIN32
    extern int optind, opterr;
    extern TSK_TCHAR *optarg;
    int getopt(int argc, TSK_TCHAR * argv[], TSK_TCHAR * optstring);
#endif



/** \name MD5 and SHA-1 hashing */
//@{

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
 */


/* POINTER defines a generic pointer type */
    typedef unsigned char *POINTER;

/* UINT2 defines a two byte word */
//typedef unsigned short int UINT2;
    typedef uint16_t UINT2;

/* UINT4 defines a four byte word */
    typedef uint32_t UINT4;

/* Added for sha1 */
/* BYTE defines a unsigned character */
    typedef uint8_t BYTE;

#ifndef TRUE
#define FALSE 0
#define TRUE  ( !FALSE )
#endif                          /* TRUE */



/* MD5 context. */
    typedef struct {
        UINT4 state[4];         /* state (ABCD) */
        UINT4 count[2];         /* number of bits, modulo 2^64 (lsb first) */
        unsigned char buffer[64];       /* input buffer */
    } TSK_MD5_CTX;

    void TSK_MD5_Init(TSK_MD5_CTX *);
    void TSK_MD5_Update(TSK_MD5_CTX *, unsigned char *, unsigned int);
    void TSK_MD5_Final(unsigned char[16], TSK_MD5_CTX *);



/* sha.h */

/* The structure for storing SHS info */

    typedef struct {
        UINT4 digest[5];        /* Message digest */
        UINT4 countLo, countHi; /* 64-bit bit count */
        UINT4 data[16];         /* SHS data buffer */
        int Endianness;
    } TSK_SHA_CTX;

/* Message digest functions */

    void TSK_SHA_Init(TSK_SHA_CTX *);
    void TSK_SHA_Update(TSK_SHA_CTX *, BYTE * buffer, int count);
    void TSK_SHA_Final(BYTE * output, TSK_SHA_CTX *);
//@}

#ifdef __cplusplus
}
#endif
#endif
