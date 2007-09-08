/*
 * The Sleuth Kit
 * 
 * $Date: 2007/04/25 21:46:05 $
 */
#ifndef _AUX_LIB_H
#define _AUX_LIB_H

#include <stdio.h>
#include <stdlib.h>

#include "tsk_os.h"

#if !defined (TSK_WIN32)
#include <sys/param.h>
#endif

#include "talloc.h"
#define free talloc_free
#define malloc tsk_malloc

#ifdef __cplusplus
extern "C" {
#endif

    void *global_talloc_context;
    extern char *tsk_malloc(size_t);
    extern char *tsk_realloc(char *, size_t);
    extern char *tsk_strdup(const char *);

    extern char *tsk_split_at(char *, int);
    extern char *tsk_split_at_right(char *, int);

/* printf macros - if the OS does not have inttypes.h yet */

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



    typedef unsigned long ULONG;
    typedef unsigned long long ULLONG;
    typedef unsigned char UCHAR;

#ifndef rounddown
#define rounddown(x, y)	\
    ((((x) % (y)) == 0) ? (x) : \
    (roundup((x),(y)) - (y)))
#endif


/* Standard local variable sizes */

// Metadata - inode number
    typedef uint64_t INUM_T;
#define PRIuINUM	PRIu64
#define PRIxINUM	PRIx64
#define PRIdINUM	PRId64

// Disk sector / block address
    typedef uint64_t DADDR_T;
#define PRIuDADDR   PRIu64
#define PRIxDADDR   PRIx64
#define PRIdDADDR   PRId64

// Byte offset
    typedef uint64_t OFF_T;
#define PRIuOFF		PRIu64
#define PRIxOFF		PRIx64
#define PRIdOFF		PRId64

#if !defined (_WIN32) && !defined(__WIN32__)
    typedef int64_t SSIZE_T;
#endif

#define PRIuSSIZE		PRIu64
#define PRIxSSIZE		PRIx64
#define PRIdSSIZE		PRId64

// Partition Number
    typedef uint32_t PNUM_T;
#define PRIuPNUM	PRIu32
#define PRIxPNUM	PRIx32
#define PRIdPNUM	PRId32


    extern void tsk_print_version(FILE *);
    extern char *tskGetVersion();
    extern SSIZE_T tsk_parse_offset(TSK_TCHAR *);
    extern int tsk_parse_inum(const TSK_TCHAR * str, INUM_T *, uint32_t *,
        uint16_t *, int *);


/* 
 * ** Dealing with endian differences
 * */

#define TSK_LIT_ENDIAN	0x01
#define TSK_BIG_ENDIAN	0x02

/* macros to read in multi-byte fields
 * file system is an array of 8-bit values, not 32-bit values
 */
    extern uint8_t tsk_guess_end_u16(uint8_t *, uint8_t *, uint16_t);
    extern uint8_t tsk_guess_end_u32(uint8_t *, uint8_t *, uint32_t);

/* 16-bit values */
#define tsk_getu16(flag, x)   \
    (uint16_t)(((flag) & TSK_LIT_ENDIAN) ? \
	  (((uint8_t *)(x))[0] + (((uint8_t *)(x))[1] << 8)) :    \
	  (((uint8_t *)(x))[1] + (((uint8_t *)(x))[0] << 8)) )

#define tsk_gets16(flag, x)	\
	((int16_t)tsk_getu16(flag, x))

/* 32-bit values */
#define tsk_getu32(flag, x)	\
	(uint32_t)( ((flag) & TSK_LIT_ENDIAN)  ?	\
     ((((uint8_t *)(x))[0] <<  0) + \
	  (((uint8_t *)(x))[1] <<  8) + \
	  (((uint8_t *)(x))[2] << 16) + \
	  (((uint8_t *)(x))[3] << 24) ) \
	:	\
	 ((((uint8_t *)(x))[3] <<  0) + \
	  (((uint8_t *)(x))[2] <<  8) + \
	  (((uint8_t *)(x))[1] << 16) + \
	  (((uint8_t *)(x))[0] << 24) ) )

#define tsk_gets32(flag, x)	\
	((int32_t)tsk_getu32(flag, x))

#define tsk_getu48(flag, x)   \
	(uint64_t)( ((flag) & TSK_LIT_ENDIAN)  ?	\
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


#define tsk_getu64(flag, x)   \
	(uint64_t)( ((flag) & TSK_LIT_ENDIAN)  ?	\
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

#define tsk_gets64(flag, x)	\
	((int64_t)tsk_getu64(flag, x))





/*********** RETURN VALUES ************/

    /* Flags for the return value of walk actions */
#define TSK_WALK_CONT	0x0
#define TSK_WALK_STOP	0x1
#define TSK_WALK_ERROR	0x2



/************ ERROR HANDLING *************/
    extern int tsk_verbose;

#define TSK_ERRSTR_L	512
#define TSK_ERRSTR_PR_L	(TSK_ERRSTR_L << 2)

    extern uint32_t tsk_errno;
    extern char tsk_errstr[TSK_ERRSTR_L];
    extern char tsk_errstr2[TSK_ERRSTR_L];
    extern char tsk_errstr_print[TSK_ERRSTR_PR_L];

    extern char *tsk_error_get();
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



/************* DATA BUF ******************/
    typedef struct TSK_DATA_BUF TSK_DATA_BUF;

    struct TSK_DATA_BUF {
        char *data;             /* buffer memory */
        size_t size;            /* buffer size */
        size_t used;            /* amount of space used */
        DADDR_T addr;           /* start block */
    };

    extern TSK_DATA_BUF *tsk_data_buf_alloc(size_t);
    extern void tsk_data_buf_free(TSK_DATA_BUF *);


    // basic check to see if a Unicode file has been included 
    // in an app that is using this as a library
#ifndef TSK_UNI_REPLACEMENT_CHAR

/**************** UNICODE *******************/
/*
 * Copyright 2001-2004 Unicode, Inc.
 * 
 * Disclaimer
 * 
 * This source code is provided as is by Unicode, Inc. No claims are
 * made as to fitness for any particular purpose. No warranties of any
 * kind are expressed or implied. The recipient agrees to determine
 * applicability of information provided. If this file has been
 * purchased on magnetic or optical media from Unicode, Inc., the
 * sole remedy for any claim will be exchange of defective media
 * within 90 days of receipt.
 * 
 * Limitations on Rights to Redistribute This Code
 * 
 * Unicode, Inc. hereby grants the right to freely use the information
 * supplied in this file in the creation of products supporting the
 * Unicode Standard, and to make copies of this file in any form
 * for internal or external distribution as long as this notice
 * remains attached.
 */

/* ---------------------------------------------------------------------

    Conversions between UTF32, UTF-16, and UTF-8.  Header file.

    Several funtions are included here, forming a complete set of
    conversions between the three formats.  UTF-7 is not included
    here, but is handled in a separate source file.

    Each of these routines takes pointers to input buffers and output
    buffers.  The input buffers are const.

    Each routine converts the text between *sourceStart and sourceEnd,
    putting the result into the buffer between *targetStart and
    targetEnd. Note: the end pointers are *after* the last item: e.g. 
    *(sourceEnd - 1) is the last item.

    The return result indicates whether the conversion was successful,
    and if not, whether the problem was in the source or target buffers.
    (Only the first encountered problem is indicated.)

    After the conversion, *sourceStart and *targetStart are both
    updated to point to the end of last text successfully converted in
    the respective buffers.

    Input parameters:
	sourceStart - pointer to a pointer to the source buffer.
		The contents of this are modified on return so that
		it points at the next thing to be converted.
	targetStart - similarly, pointer to pointer to the target buffer.
	sourceEnd, targetEnd - respectively pointers to the ends of the
		two buffers, for overflow checking only.

    These conversion functions take a TSKConversionFlags argument. When this
    flag is set to strict, both irregular sequences and isolated surrogates
    will cause an error.  When the flag is set to lenient, both irregular
    sequences and isolated surrogates are converted.

    Whether the flag is strict or lenient, all illegal sequences will cause
    an error return. This includes sequences such as: <F4 90 80 80>, <C0 80>,
    or <A0> in UTF-8, and values above 0x10FFFF in UTF-32. Conformant code
    must check for illegal sequences.

    When the flag is set to lenient, characters over 0x10FFFF are converted
    to the replacement character; otherwise (when the flag is set to strict)
    they constitute an error.

    Output parameters:
	The value "TSKsourceIllegal" is returned from some routines if the input
	sequence is malformed.  When "TSKsourceIllegal" is returned, the source
	value will point to the illegal value that caused the problem. E.g.,
	in UTF-8 when a sequence is malformed, it points to the start of the
	malformed sequence.  

    Author: Mark E. Davis, 1994.
    Rev History: Rick McGowan, fixes & updates May 2001.
		 Fixes & updates, Sept 2001.

------------------------------------------------------------------------ */

/* ---------------------------------------------------------------------
    The following 4 definitions are compiler-specific.
    The C standard does not guarantee that wchar_t has at least
    16 bits, so wchar_t is no less portable than unsigned short!
    All should be unsigned values to avoid sign extension during
    bit mask & shift operations.
------------------------------------------------------------------------ */

#define TSK_IS_CNTRL(x) \
    (((x) < 0x20) && ((x) >= 0x00))

    typedef unsigned long UTF32;        /* at least 32 bits */
    typedef unsigned short UTF16;       /* at least 16 bits */
    typedef unsigned char UTF8; /* typically 8 bits */
    typedef unsigned char Boolean;      /* 0 or 1 */

/* Some fundamental constants */
#define TSK_UNI_REPLACEMENT_CHAR (UTF32)0x0000FFFD
#define TSK_UNI_MAX_BMP (UTF32)0x0000FFFF
#define TSK_UNI_MAX_UTF16 (UTF32)0x0010FFFF
#define TSK_UNI_MAX_UTF32 (UTF32)0x7FFFFFFF
#define TSK_UNI_MAX_LEGAL_UTF32 (UTF32)0x0010FFFF

    typedef enum {
        TSKconversionOK,        /* conversion successful */
        TSKsourceExhausted,     /* partial character in source, but hit end */
        TSKtargetExhausted,     /* insuff. room in target for conversion */
        TSKsourceIllegal        /* source sequence is illegal/malformed */
    } TSKConversionResult;

    typedef enum {
        TSKstrictConversion = 0,
        TSKlenientConversion
    } TSKConversionFlags;

    TSKConversionResult tsk_UTF8toUTF16(const UTF8 ** sourceStart,
        const UTF8 * sourceEnd,
        UTF16 ** targetStart, UTF16 * targetEnd, TSKConversionFlags flags);

    TSKConversionResult tsk_UTF16toUTF8(uint16_t,
        const UTF16 ** sourceStart, const UTF16 * sourceEnd,
        UTF8 ** targetStart, UTF8 * targetEnd, TSKConversionFlags flags);

    Boolean tsk_isLegalUTF8Sequence(const UTF8 * source,
        const UTF8 * sourceEnd);

#endif
// getopt and windows stuff

#ifdef TSK_WIN32
    extern int optind, opterr;
    extern TSK_TCHAR *optarg;
    int getopt(int argc, TSK_TCHAR * argv[], TSK_TCHAR * optstring);
#endif


    extern void tsk_fprintf(FILE * fd, char *msg, ...);
    //extern void tsk_snprintf(WCHAR *wbuf, int wlen, char *msg, ...);
    extern void tsk_printf(char *msg, ...);


    typedef struct TSK_LIST TSK_LIST;
    struct TSK_LIST {
        TSK_LIST *next;
        uint64_t key;
        uint64_t len;
    };

    extern uint8_t tsk_list_add(TSK_LIST ** list, uint64_t key);
    extern uint8_t tsk_list_find(TSK_LIST * list, uint64_t key);
    extern void tsk_list_free(TSK_LIST * list);




/*************************** HASH STUFF *********************/

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

/*
#ifdef __alpha
typedef unsigned int UINT4;
#else
typedef unsigned long int UINT4;
#endif
*/


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
    } MD5_CTX;

    void MD5Init(MD5_CTX *);
    void MD5Update(MD5_CTX *, unsigned char *, unsigned int);
    void MD5Final(unsigned char[16], MD5_CTX *);



/* sha.h */

/* The structure for storing SHS info */

    typedef struct {
        UINT4 digest[5];        /* Message digest */
        UINT4 countLo, countHi; /* 64-bit bit count */
        UINT4 data[16];         /* SHS data buffer */
        int Endianness;
    } SHA_CTX;

/* Message digest functions */

    void SHAInit(SHA_CTX *);
    void SHAUpdate(SHA_CTX *, BYTE * buffer, int count);
    void SHAFinal(BYTE * output, SHA_CTX *);



#ifdef __cplusplus
}
#endif
#endif
