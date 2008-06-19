/*
** The Sleuth Kit 
**
** $Date: 2008/01/29 05:18:23 $
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003-2008 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002 @stake Inc.  All rights reserved
** 
** Copyright (c) 1997,1998,1999, International Business Machines          
** Corporation and others. All Rights Reserved.
*/

/** \file tsk_fs.h
 * External header file for file system support.
 * Note that this file is not meant to be directly included.  
 * It is included by both libtsk.h and tsk_fs_i.h.
 */

#ifndef _TSK_FS_H
#define _TSK_FS_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/****************  FILE SYSTEM TYPES SECTION ********************/

    /** 
     * Values for the file system type.  The most-significant nibble is 
     * the high-level type.  The least-sigificant nibble is the specific 
     * sub-type of implementation.  
     */
    enum TSK_FS_INFO_TYPE_ENUM {
        TSK_FS_INFO_TYPE_FS_MASK = 0xf0,        ///< Mask for general file system type
        TSK_FS_INFO_TYPE_SUB_MASK = 0x0f,       ///< Mask for file system sub-type (version)

        TSK_FS_INFO_TYPE_UNSUPP = 0x00, ///< Unsupported file system

        TSK_FS_INFO_TYPE_FFS_TYPE = 0x10,       ///< FFS General type
        TSK_FS_INFO_TYPE_FFS_1 = 0x11,  ///< UFS1 (FreeBSD, OpenBSD, BSDI ...)
        TSK_FS_INFO_TYPE_FFS_1B = 0x12, ///< UFS1b (Solaris - has no type)
        TSK_FS_INFO_TYPE_FFS_2 = 0x13,  ///< UFS2 - FreeBSD, NetBSD 
        TSK_FS_INFO_TYPE_FFS_AUTO = 0x14,       ///< UFS Autodetect - passed to ffs_open to detect specific type

        TSK_FS_INFO_TYPE_EXT_TYPE = 0x20,       ///< Ext2/3 General type
        TSK_FS_INFO_TYPE_EXT_2 = 0x21,  ///< Ext2 file system
        TSK_FS_INFO_TYPE_EXT_3 = 0x22,  ///< Ext3 file system
        TSK_FS_INFO_TYPE_EXT_AUTO = 0x23,       ///< Ext2/3 Autodetect - passed to ext2fs_open to detect specific type

        TSK_FS_INFO_TYPE_FAT_TYPE = 0x30,       ///< FAT general type
        TSK_FS_INFO_TYPE_FAT_12 = 0x31, ///< FAT12 file system
        TSK_FS_INFO_TYPE_FAT_16 = 0x32, ///< FAT16 file system
        TSK_FS_INFO_TYPE_FAT_32 = 0x33, ///< FAT32 file system
        TSK_FS_INFO_TYPE_FAT_AUTO = 0x34,       ///< FAT Autodetect - passed to fatfs_open to detect specific type

        TSK_FS_INFO_TYPE_NTFS_TYPE = 0x40,      ///< NTFS general type
        TSK_FS_INFO_TYPE_NTFS = 0x40,   ///< NTFS file system
        TSK_FS_INFO_TYPE_NTFS_AUTO = 0x40,      ///< NTFS Autodetect - passed to ntfs_open to detect type

        TSK_FS_INFO_TYPE_SWAP_TYPE = 0x50,      ///< SWAP general type
        TSK_FS_INFO_TYPE_SWAP = 0x50,   ///< SWAP file system

        TSK_FS_INFO_TYPE_RAW_TYPE = 0x60,       ///< RAW general type
        TSK_FS_INFO_TYPE_RAW = 0x60,    ///< RAW file system

        TSK_FS_INFO_TYPE_ISO9660_TYPE = 0x70,   ///< ISO9660 general type
        TSK_FS_INFO_TYPE_ISO9660 = 0x70,        ///< ISO9660 file system

        TSK_FS_INFO_TYPE_HFS_TYPE = 0x80,       ///< HFS+ general type
        TSK_FS_INFO_TYPE_HFS = 0x80,    ///< HFS file system
    };
    typedef enum TSK_FS_INFO_TYPE_ENUM TSK_FS_INFO_TYPE_ENUM;

    extern TSK_FS_INFO_TYPE_ENUM tsk_fs_parse_type(const TSK_TCHAR *);
    extern void tsk_fs_print_types(FILE *);
    extern const char *tsk_fs_get_type(TSK_FS_INFO_TYPE_ENUM);

    typedef struct TSK_FS_INFO TSK_FS_INFO;
    typedef struct TSK_FS_DATA TSK_FS_DATA;
    typedef struct TSK_FS_DATA_RUN TSK_FS_DATA_RUN;
    typedef struct TSK_FS_INODE_NAME_LIST TSK_FS_INODE_NAME_LIST;
    typedef struct TSK_FS_JENTRY TSK_FS_JENTRY;




/************************************************************************* 
 * Directory entries 
 */

 /**
  * File name flags that are used when walking directories and when specifying the status of
  * a name in the TSK_FS_DENT structure
  */
    enum TSK_FS_DENT_FLAG_ENUM {
        TSK_FS_DENT_FLAG_ALLOC = (1 << 0),      ///< Name is in an allocated state
        TSK_FS_DENT_FLAG_UNALLOC = (1 << 1),    ///< Name is in an unallocated state
        TSK_FS_DENT_FLAG_RECURSE = (1 << 2),    ///< Recurse into directories (dent_walk only)
    };
    typedef enum TSK_FS_DENT_FLAG_ENUM TSK_FS_DENT_FLAG_ENUM;


/**
 * File type values -- as specified in the directory entry structure.
 */
    enum TSK_FS_DENT_TYPE_ENUM {
        TSK_FS_DENT_TYPE_UNDEF = 0,     ///< Unknown type
        TSK_FS_DENT_TYPE_FIFO = 1,      ///< Named pipe 
        TSK_FS_DENT_TYPE_CHR = 2,       ///< Character device
        TSK_FS_DENT_TYPE_DIR = 4,       ///< Directory 
        TSK_FS_DENT_TYPE_BLK = 6,       ///< Block device
        TSK_FS_DENT_TYPE_REG = 8,       ///< Regular file 
        TSK_FS_DENT_TYPE_LNK = 10,      ///< Symbolic link 
        TSK_FS_DENT_TYPE_SOCK = 12,     ///< Socket 
        TSK_FS_DENT_TYPE_SHAD = 13,     ///< Shadow inode (solaris) 
        TSK_FS_DENT_TYPE_WHT = 14,      ///< Whiteout (openbsd) 
    };
    typedef enum TSK_FS_DENT_TYPE_ENUM TSK_FS_DENT_TYPE_ENUM;

#define TSK_FS_DENT_TYPE_MAX_STR 15     ///< Number of types that have a short string name

/* ascii representation of above types */
    extern char tsk_fs_dent_str[TSK_FS_DENT_TYPE_MAX_STR][2];

    /**
     * Generic structure to store the file name information that is stored in
     * a directory. Most file systems seperate the file name from the metadata, but
     * some do not (such as FAT). This structure contains the name and a pointer to the
     * metadata, if it exists 
     */
    struct TSK_FS_DENT {
        char *name;             ///< The name of the file (in UTF-8)
        size_t name_max;         ///< The number of bytes allocated to name

        char *shrt_name;        ///< The short name of the file (FAT and NTFS only) or null (in UTF-8)
        size_t shrt_name_max;    ///< The number of bytes allocated to shrt_name

        char *path;             ///< The parent directory name (exists only when the directory was recursed into) (in UTF-8)
        unsigned int pathdepth; ///< The number of directories in the parent directory

        TSK_INUM_T inode;           ///< Address of the metadata structure that the name points to. 
        struct TSK_FS_INODE *fsi;       ///< Pointer to the metadata structure that the name points to. 

        TSK_FS_DENT_TYPE_ENUM ent_type; ///< File type information (directory, file, etc.)
        TSK_FS_DENT_FLAG_ENUM flags;    ///< Flags that describe allocation status etc. 
    };

    typedef struct TSK_FS_DENT TSK_FS_DENT;


/******************* INODE / META DATA **************/


/**
 * Metadata flags used in TSK_FS_INODE.flags and in request to inode_walk
 */
    enum TSK_FS_INODE_FLAG_ENUM {
        TSK_FS_INODE_FLAG_ALLOC = (1 << 0),     ///< Metadata structure is currently in an allocated state
        TSK_FS_INODE_FLAG_UNALLOC = (1 << 1),   ///< Metadata structure is currently in an unallocated state
        TSK_FS_INODE_FLAG_USED = (1 << 2),      ///< Metadata structure has been allocated at least once
        TSK_FS_INODE_FLAG_UNUSED = (1 << 3),    ///< Metadata structure has never been allocated. 
        TSK_FS_INODE_FLAG_ORPHAN = (1 << 4),    ///< Metadata structure is unallocated and has no file name pointing to it.
        TSK_FS_INODE_FLAG_COMP = (1 << 5)       ///< The file contents are compressed. 
    };
    typedef enum TSK_FS_INODE_FLAG_ENUM TSK_FS_INODE_FLAG_ENUM;

    enum TSK_FS_INODE_ATTR_FLAG_ENUM {
        TSK_FS_INODE_ATTR_EMPTY,        ///< Attributes have not been studied
        TSK_FS_INODE_ATTR_STUDIED,      ///< Attributes have been studied successfully
        TSK_FS_INODE_ATTR_ERROR ///< Attributes have been studied and errors occured
    };
    typedef enum TSK_FS_INODE_ATTR_FLAG_ENUM TSK_FS_INODE_ATTR_FLAG_ENUM;


    /**
     * Size of name array in TSK_FS_INODE_NAME_LIST structure
     */
#define TSK_FS_INODE_NAME_LIST_NSIZE    512

    /**
     * Relatively generic structure to hold file names that are stored with
     * the file metadata.  Note that this is different from the
     * file name stored in the directory heirarchy, which is 
     * part of the tsk_fs_dent_... code.  This is currently
     * used for NTFS and FAT file systems only.
     */
    struct TSK_FS_INODE_NAME_LIST {
        TSK_FS_INODE_NAME_LIST *next;   ///< Pointer to next name (or NULL)
        char name[TSK_FS_INODE_NAME_LIST_NSIZE];        ///< Name in UTF-8 (does not include parent directory name)
        TSK_INUM_T par_inode;       ///< Inode address of parent directory (NTFS only)
        uint32_t par_seq;       ///< Sequence number of parent directory (NTFS only)
    };

    /** 
     * Generic data strcture to hold file meta data 
     */
    struct TSK_FS_INODE {
        TSK_INUM_T addr;            ///< Address of meta data structure 
        mode_t mode;            ///< file type and permissions
        int nlink;              ///< link count 
        TSK_OFF_T size;             ///< file size 
        TSK_UID_T uid;              ///< owner id
        TSK_GID_T gid;              ///< group id

        /* @@@ Need to make these 64-bits ... ? */
        time_t mtime;           ///< last modified time
        time_t atime;           ///< last accessed time
        time_t ctime;           ///< last status changed time

        /* filesystem specific times */
        union {
            struct {
                time_t crtime;  ///< NTFS Creation time
            } ntfs;
            struct {
                time_t dtime;   ///< Linux deletion time
            } ext2;
            struct {
                time_t bkup_time;       ///< HFS+ backup time
                time_t attr_mtime;      ///< HFS+ mtime
            } hfs;
        } time2;

        TSK_DADDR_T *direct_addr;   ///< List of direct blocks 
        int direct_count;       ///< Number of blocks in direct list
        TSK_DADDR_T *indir_addr;    ///< List of indirect blocks
        int indir_count;        ///< Number of blocks in indirect list

        uint32_t seq;           ///< Sequence number of file (NTFS Only) 

        TSK_FS_DATA *attr;      ///< Run for content (or NTFS file attribute) 
        TSK_FS_INODE_ATTR_FLAG_ENUM attr_state; ///< State of the attribute structure
        uint8_t attr_flags;     ///< Identifies flags used to load attribute run (FAT Only right now -- RECOVERY or not RECOVERY)

        TSK_FS_INODE_NAME_LIST *name;   ///< Name of file stored in metadata (FAT and NTFS Only)
        char *link;             ///< Name of target file if this is a symbolic link

        TSK_FS_INODE_FLAG_ENUM flags;   ///< Flags for file
    };

    typedef struct TSK_FS_INODE TSK_FS_INODE;

    extern TSK_FS_INODE *tsk_fs_inode_alloc(int, int);
    extern TSK_FS_INODE *tsk_fs_inode_realloc(TSK_FS_INODE *, int, int);
    extern void tsk_fs_inode_free(TSK_FS_INODE *);


/** String that is prepended to orphan FAT & NTFS files when the file
 * name is known, but the parent is not */
#define TSK_FS_ORPHAN_STR "-ORPHAN_FILE-"

/* Type of file in the mode field of Inodes.  FAT and NTFS are converted
 * to this mode value */

    /**
     * Values for the mode field -- which identifies the file type 
     * and permissions.
     */
    enum TSK_FS_INODE_MODE_ENUM {

        /* the following are file types */
        TSK_FS_INODE_MODE_FMT = 0170000,        ///< Mask to apply to mode to isolate file type
        TSK_FS_INODE_MODE_FIFO = 0010000,       ///< Named pipe (fifo) 
        TSK_FS_INODE_MODE_CHR = 0020000,        ///< Character device 
        TSK_FS_INODE_MODE_DIR = 0040000,        ///< Directory file 
        TSK_FS_INODE_MODE_BLK = 0060000,        ///< Block device 
        TSK_FS_INODE_MODE_REG = 0100000,        ///< Regular file
        TSK_FS_INODE_MODE_LNK = 0120000,        ///< Symbolic link
        TSK_FS_INODE_MODE_SHAD = 0130000,       ///< SOLARIS ONLY 
        TSK_FS_INODE_MODE_SOCK = 0140000,       ///< UNIX domain socket
        TSK_FS_INODE_MODE_WHT = 0160000,        ///< Whiteout

        /* The following describe the file permissions */
        TSK_FS_INODE_MODE_ISUID = 0004000,      ///< set user id on execution 
        TSK_FS_INODE_MODE_ISGID = 0002000,      ///< set group id on execution 
        TSK_FS_INODE_MODE_ISVTX = 0001000,      ///< sticky bit 

        TSK_FS_INODE_MODE_IRUSR = 0000400,      ///< R for owner 
        TSK_FS_INODE_MODE_IWUSR = 0000200,      ///< W for owner 
        TSK_FS_INODE_MODE_IXUSR = 0000100,      ///< X for owner 

        TSK_FS_INODE_MODE_IRGRP = 0000040,      ///< R for group 
        TSK_FS_INODE_MODE_IWGRP = 0000020,      ///< W for group 
        TSK_FS_INODE_MODE_IXGRP = 0000010,      ///< X for group 

        TSK_FS_INODE_MODE_IROTH = 0000004,      ///< R for other 
        TSK_FS_INODE_MODE_IWOTH = 0000002,      ///< W for other 
        TSK_FS_INODE_MODE_IXOTH = 0000001       ///< X for other 
    };
    typedef enum TSK_FS_INODE_MODE_ENUM TSK_FS_INODE_MODE_ENUM;


#define TSK_FS_INODE_MODE_TYPE_SHIFT	12      ///< Number of bits to shift mode to isolate file type
#define TSK_FS_INODE_MODE_TYPE_STR_MAX 15       ///< Number of file types in shortname array

    extern char tsk_fs_inode_mode_str[TSK_FS_INODE_MODE_TYPE_STR_MAX][2];


    /** Flags that are used when calling block_walk, in callback of
     * of block_walk, and in callback of file_walk */
    enum TSK_FS_BLOCK_FLAG_ENUM {
        TSK_FS_BLOCK_FLAG_ALLOC = (1 << 0),     ///< Block is allocated
        TSK_FS_BLOCK_FLAG_UNALLOC = (1 << 1),   ///< Block is unallocated
        TSK_FS_BLOCK_FLAG_CONT = (1 << 2),      ///< Block contains file content
        TSK_FS_BLOCK_FLAG_META = (1 << 3),      ///< Block contains file system metadata
        TSK_FS_BLOCK_FLAG_BAD = (1 << 4),       ///< Block has been marked as bad by the file system
        TSK_FS_BLOCK_FLAG_ALIGN = (1 << 5),     ///< Return entire block when walking -- applies to FS with fragments
        TSK_FS_BLOCK_FLAG_RES = (1 << 6),       ///< The data passed in the file_walk callback is from an NTFS resident file
        TSK_FS_BLOCK_FLAG_SPARSE = (1 << 7),    ///< The data passed in the file_walk calback was stored as sparse (all zeros)
        TSK_FS_BLOCK_FLAG_COMP = (1 << 8)       ///< The data passed in the file_walk callback was stored in a compressed form
    };
    typedef enum TSK_FS_BLOCK_FLAG_ENUM TSK_FS_BLOCK_FLAG_ENUM;



    /**
     * Flags used when calling file_walk, the action of file_walk uses
     * the TSK_FS_BLOCK_FLAG  flags */
    enum TSK_FS_FILE_FLAG_ENUM {
        TSK_FS_FILE_FLAG_AONLY = (1 << 0),      ///< Do not include file content in callback -- supply adddress only
        TSK_FS_FILE_FLAG_SLACK = (1 << 1),      ///< Include the file slack space in the callback
        TSK_FS_FILE_FLAG_RECOVER = (1 << 2),    ///< Use special data recovery techniques for deleted files
        TSK_FS_FILE_FLAG_META = (1 << 3),       ///< Return blocks that contain metadata (such as indirect UFS/ExtX blocks)
        TSK_FS_FILE_FLAG_NOSPARSE = (1 << 4),   ///< Do not use callback for sparse blocks
        TSK_FS_FILE_FLAG_NOID = (1 << 5)        ///< Ignore the Id argument given in the call to file_walk -- use only the type                                          
    };
    typedef enum TSK_FS_FILE_FLAG_ENUM TSK_FS_FILE_FLAG_ENUM;

/* walk callback functions */
    typedef TSK_WALK_RET_ENUM(*TSK_FS_INODE_WALK_CB) (TSK_FS_INFO *, TSK_FS_INODE *,
        void *);
    typedef TSK_WALK_RET_ENUM(*TSK_FS_BLOCK_WALK_CB) (TSK_FS_INFO *, TSK_DADDR_T, char *,
        TSK_FS_BLOCK_FLAG_ENUM, void *);
    typedef TSK_WALK_RET_ENUM(*TSK_FS_DENT_TYPE_WALK_CB) (TSK_FS_INFO *,
        TSK_FS_DENT *, void *);
    typedef TSK_WALK_RET_ENUM(*TSK_FS_FILE_WALK_CB) (TSK_FS_INFO *, TSK_DADDR_T, char *,
        size_t, TSK_FS_BLOCK_FLAG_ENUM, void *);
    typedef TSK_WALK_RET_ENUM(*TSK_FS_JBLK_WALK_CB) (TSK_FS_INFO *, char *, int,
        void *);
    typedef TSK_WALK_RET_ENUM(*TSK_FS_JENTRY_WALK_CB) (TSK_FS_INFO *,
        TSK_FS_JENTRY *, int, void *);


/******************************* TSK_FS_INFO ******************/

    /**
     * Flags for the FS_INFO structure 
     */
    enum TSK_FS_INFO_FLAG_ENUM {
        TSK_FS_INFO_FLAG_HAVE_SEQ = (1 << 0)    ///< File system has sequence numbers in the inode addresses.
    };
    typedef enum TSK_FS_INFO_FLAG_ENUM TSK_FS_INFO_FLAG_ENUM;


/**
 * Stores state information for an open file system. 
 * One of these are generated for each open files system and it contains
 * file system-type specific data.  These values are all filled in by
 * the file system code and not the caller functions. 
 */
    struct TSK_FS_INFO {
        TSK_IMG_INFO *img_info; ///< Pointer to the image layer state
        TSK_OFF_T offset;         ///< Byte offset into img_info that fs starts 

        /* meta data */
        TSK_INUM_T inum_count;      ///< Number of inodes 
        TSK_INUM_T root_inum;       ///< Address of root inode 
        TSK_INUM_T first_inum;      ///< Address of first valid inode 
        TSK_INUM_T last_inum;       ///< Address of last valid inode

        /* content */
        TSK_DADDR_T block_count;    ///< Number of blocks in fs
        TSK_DADDR_T first_block;    ///< Address of first block
        TSK_DADDR_T last_block;     ///< Address of last block as reported by file system (could be larger than last_block if end of image does not exist)
        TSK_DADDR_T last_block_act; ///< Address of last block -- adjusted so that it is equal to the last block in the image or volume (if image is not complete)
        unsigned int block_size;        ///< Size of each block (in bytes)
        unsigned int dev_bsize; ///< Size of device block (typically always 512)

        /* Journal */
        TSK_INUM_T journ_inum;      ///< Address of journal inode

        TSK_FS_INFO_TYPE_ENUM ftype;    ///< type of file system 
        char *duname;           ///< string "name" of data unit type 
        TSK_FS_INFO_FLAG_ENUM flags;    ///< flags for image

        TSK_ENDIAN_ENUM endian;    ///< Endian order of data

        TSK_LIST *list_inum_named;      /**< List of unallocated inodes that
					 * are pointed to by a file name -- 
					 * Used to find orphans
					 */

        /** Pointer to file system-specific function that passes a range of blocks to a callback function. 
         * @param fs File system to analyze
         * @param start Starting block in range to walk from
         * @param end Ending block in range to walk to
         * @param flags Flags for walking
         * @param cb Callback function
         * @param ptr Pointer to data that is passed to callback
         * @returns 1 on error and 0 on success
         */
         uint8_t(*block_walk) (TSK_FS_INFO * fs, TSK_DADDR_T start,
            TSK_DADDR_T end, TSK_FS_BLOCK_FLAG_ENUM flags,
            TSK_FS_BLOCK_WALK_CB cb, void *ptr);

        /** Pointer to file system-specific function that passes a range of inodes to a callback function. 
         * @param fs File system to analyze
         * @param start Starting inode in range to walk from
         * @param end Ending inode in range to walk to
         * @param flags Flags for walking
         * @param cb Callback function
         * @param ptr Pointer to data that is passed to callback
         * @returns 1 on error and 0 on success
         */
         uint8_t(*inode_walk) (TSK_FS_INFO * fs, TSK_INUM_T start, TSK_INUM_T end,
            TSK_FS_INODE_FLAG_ENUM flags, TSK_FS_INODE_WALK_CB cb,
            void *ptr);

        /** Pointer to file system-specific function that looks up a file and returns the info in a generic format.
         * @param fs File system to analyze
         * @param addr Metadata address of file to lookup
         * @returns NULL on error
         */
        TSK_FS_INODE *(*inode_lookup) (TSK_FS_INFO * fs, TSK_INUM_T addr);

        /**
         * Pointer to file system specific function that prints details on a specific file to a file handle. 
         *
         * @param fs File system file is located in
         * @param hFile File handle to print text to
         * @param inum Address of file in file system
         * @param numblock The number of blocks in file to force print (can go beyond file size)
         * @param sec_skew Clock skew in seconds to also print times in
         * 
         * @returns 1 on error and 0 on success
         */
         uint8_t(*istat) (TSK_FS_INFO * fs, FILE * hFile, TSK_INUM_T inum,
            TSK_DADDR_T numblock, int32_t sec_skew);

         /**
         * Pointer to a file system-specific function that calls a callback function with the contents of each block in a file. 
         *
         * @param fs File system file is located in
         * @param fs_inode File to read and analyze
         * @param type Attribute type to read and analyze (does not apply to all file systems)
         * @param id Attribute id to read and analyze (does not apply to all file systems)
         * @param flags Flags to use while reading
         * @param cb Callback function that is called for each block
         * @param ptr Pointer to data that is passed to the callback
         * @returns 1 on error and 0 on success
         */
         uint8_t(*file_walk) (TSK_FS_INFO * fs, TSK_FS_INODE * fs_inode,
            uint32_t type, uint16_t id, TSK_FS_FILE_FLAG_ENUM flags,
            TSK_FS_FILE_WALK_CB cb, void *ptr);


        /**
         * Pointer to file system-specific function that processes the contents of a directory and passes each file name to a callback function.
         *
         * @param fs File system to analyze
         * @param inode Metadata address of directory to analyze
         * @param flags Flags used during analysis
         * @param action Callback function that is called for each file name
         * @param ptr Pointer to data that is passed to callback
         * @returns 1 on error and 0 on success
         */
         uint8_t(*dent_walk) (TSK_FS_INFO * fs, TSK_INUM_T inode,
            TSK_FS_DENT_FLAG_ENUM flags, TSK_FS_DENT_TYPE_WALK_CB action,
            void *ptr);

        /** Open the journal */
         uint8_t(*jopen) (TSK_FS_INFO *, TSK_INUM_T);

        /** Walk the blocks in a journal */
         uint8_t(*jblk_walk) (TSK_FS_INFO *, TSK_DADDR_T, TSK_DADDR_T, int,
            TSK_FS_JBLK_WALK_CB, void *);

        /** Walk the entries in a journal */
         uint8_t(*jentry_walk) (TSK_FS_INFO *, int, TSK_FS_JENTRY_WALK_CB,
            void *);

         /**
         * Pointer to file system-specific function that prints file system details to a file handle.
         *
         * @param fs File system to print details on
         * @param hFile File handle to print text to
         * 
         * @returns 1 on error and 0 on success
         */
         uint8_t(*fsstat) (TSK_FS_INFO * fs, FILE * hFile);

        /** Check the integrity / sanity of the file system (not implemented) */
         uint8_t(*fscheck) (TSK_FS_INFO *, FILE *);

        /** 
         * Pointer to file system-specific function that closes the file system and frees the allocated memory 
         * @param fs File system to close
         */
        void (*close) (TSK_FS_INFO * fs);
    };



/***************************************************************
 * Generic inode structure for filesystem-independent operations.
 */


/* 
 * All non-resident addresses will be stored here so that the search
 * programs (find_inode) can account for the addresses. 
 *
 * All resident non-standard attributes will be stored here so they
 * can be displayed.  By default, the $Data attribute will be saved
 * in the TSK_FS_INODE structure. If the $Data attribute is resident,
 * then the dir/indir stuff will be 0 and the $Data will be the
 * first element in this linked list 
 */

    /** 
     * Flags used for data runs in attributes (FS_DATA)
     */
    enum TSK_FS_DATA_RUN_FLAG_ENUM {
        TSK_FS_DATA_RUN_FLAG_FILLER = 0x1,      ///< Run entry is a filler because we haven't seen the actual run for this location yet
        TSK_FS_DATA_RUN_FLAG_SPARSE = 0x2       ///< Run is sparse -- blocks in this run should contain all zeros
    };
    typedef enum TSK_FS_DATA_RUN_FLAG_ENUM TSK_FS_DATA_RUN_FLAG_ENUM;

/* len = 0 when not being used */
    /**
     * Generic structure used to describe a run of consecutive blocks.
     * These are in a linked list.
     */
    struct TSK_FS_DATA_RUN {
        TSK_FS_DATA_RUN *next;  ///< Pointer to the next run in the attribute
        TSK_DADDR_T offset;         ///< Logical block offset of this run in the "file"
        TSK_DADDR_T addr;           ///< Starting block address of run
        TSK_DADDR_T len;            ///< Number of blocks in run
        TSK_FS_DATA_RUN_FLAG_ENUM flags;        ///< Flags for run
    };


    /**
     * Flags used for the TSK_FS_DATA structure, which is used to 
     * store attribute data */
    enum TSK_FS_DATA_FLAG_ENUM {
        TSK_FS_DATA_INUSE = 0x1,        ///< Attribute structure is in use
        TSK_FS_DATA_NONRES = 0x2,       ///< Attribute is for non-resident data
        TSK_FS_DATA_RES = 0x4,  ///< Attribute is for resident data
        TSK_FS_DATA_ENC = 0x10, ///< Attribute data is encrypted
        TSK_FS_DATA_COMP = 0x20,        ///< Attribute data is compressed
        TSK_FS_DATA_SPARSE = 0x40,      ///< Attribute data is sparse
        TSK_FS_DATA_RECOVERY = 0x80,    ///< Attribute layout was determined in recovery mode
    };
    typedef enum TSK_FS_DATA_FLAG_ENUM TSK_FS_DATA_FLAG_ENUM;

    /**
     * Generic structure to hold attributes for files.  Attributes are a
     * general term to describe any group of "data" -- it could be file 
     * contents or meta data.  This structures are used
     * currently only for NTFS because it has "multiple attributes", but
     * it could be used for other FS in the future.  These are grouped
     * into an unsorted linked list.
     */
    struct TSK_FS_DATA {
        TSK_FS_DATA *next;      ///< Pointer to next attribute in list
        TSK_FS_DATA_FLAG_ENUM flags;    ///< Flags for attribute
        char *name;             ///< Attribute name (could be NULL) (in UTF-8)
        size_t nsize;           ///< Number of bytes allocated to name
        uint32_t type;          ///< Type of attribute
        uint16_t id;            ///< Id of attribute

        TSK_OFF_T size;             ///< Size in bytes of attribute

        /* Run-List data (non-resident) */
        TSK_FS_DATA_RUN *run;   ///< Linked list of runs for non-resident attributes
        TSK_FS_DATA_RUN *run_end;       ///< Pointer to final run in the list
        TSK_OFF_T allocsize;        ///< Number of bytes that are allocated in all clusters of non-resident run (will be larger than size)
        uint32_t compsize;      ///< Size of compression units (needed only if file is compressed)

        /* stream data (resident) */
        size_t buflen;          ///< Number of bytes allocated to resident buffer
        uint8_t *buf;           ///< Buffer for resident data
    };



    extern TSK_FS_DATA *tsk_fs_data_alloc(TSK_FS_DATA_FLAG_ENUM);
    extern TSK_FS_DATA_RUN *tsk_fs_data_run_alloc();
    extern TSK_FS_DATA *tsk_fs_data_getnew_attr(TSK_FS_DATA *,
        TSK_FS_DATA_FLAG_ENUM);
    extern void tsk_fs_data_clear_list(TSK_FS_DATA *);

    extern TSK_FS_DATA *tsk_fs_data_put_str(TSK_FS_DATA *, const char *,
        uint32_t, uint16_t, void *, unsigned int);

    extern TSK_FS_DATA *tsk_fs_data_put_run(TSK_FS_DATA *, TSK_OFF_T,
        TSK_FS_DATA_RUN *, const char *, uint32_t, uint16_t, TSK_OFF_T,
        TSK_FS_DATA_FLAG_ENUM, uint32_t);

    extern TSK_FS_DATA *tsk_fs_data_lookup(TSK_FS_DATA *, uint32_t,
        uint16_t);
    extern TSK_FS_DATA *tsk_fs_data_lookup_noid(TSK_FS_DATA *, uint32_t);

    extern void tsk_fs_data_run_free(TSK_FS_DATA_RUN *);
    extern void tsk_fs_data_free(TSK_FS_DATA *);



/**************** Journal Stuff **********************/
    struct TSK_FS_JENTRY {
        TSK_DADDR_T jblk;           /* journal block address */
        TSK_DADDR_T fsblk;          /* fs block that journal entry is about */
    };



/* function decs */
    extern TSK_FS_DENT *tsk_fs_dent_alloc(size_t, size_t);
    extern TSK_FS_DENT *tsk_fs_dent_realloc(TSK_FS_DENT *, size_t);
    extern void tsk_fs_dent_free(TSK_FS_DENT *);
    extern void tsk_fs_dent_print(FILE *, TSK_FS_DENT *,
        TSK_FS_INFO *, TSK_FS_DATA *);
    extern void tsk_fs_dent_print_long(FILE *, TSK_FS_DENT *,
        TSK_FS_INFO *, TSK_FS_DATA *);
    extern void tsk_fs_dent_print_mac(FILE *, TSK_FS_DENT *,
        TSK_FS_INFO *, TSK_FS_DATA * fs_data, const char *);

    extern void tsk_fs_make_ls(mode_t, char *);
    extern void tsk_fs_print_day(FILE *, time_t);
    extern void tsk_fs_print_time(FILE *, time_t);

/*
** Is this string a "." or ".."
*/
#define TSK_FS_ISDOT(str) ( ((str[0] == '.') && \
 ( ((str[1] == '.') && (str[2] == '\0')) || (str[1] == '\0') ) ) ? 1 : 0 )



/**************************************************************8
 * Generic routines.
 */
    extern TSK_FS_INFO *tsk_fs_open(TSK_IMG_INFO *, TSK_OFF_T,
        const TSK_TCHAR *);

/* fs_io routines */
    extern ssize_t tsk_fs_read_block(TSK_FS_INFO *, TSK_DATA_BUF *, size_t,
        TSK_DADDR_T);
    extern ssize_t tsk_fs_read_block_nobuf(TSK_FS_INFO *, char *, size_t,
        TSK_DADDR_T);
#define tsk_fs_read_random(fsi, buf, len, offs)	\
	(fsi)->img_info->read_random((fsi)->img_info, (fsi)->offset, (buf), (len), (offs))

    extern char *tsk_fs_load_file(TSK_FS_INFO *, TSK_FS_INODE *, uint32_t,
        uint16_t, int);

    extern ssize_t
        tsk_fs_read_file(TSK_FS_INFO *, TSK_FS_INODE *, uint32_t, uint16_t,
        TSK_OFF_T, size_t, char *);

    extern ssize_t
        tsk_fs_read_file_noid(TSK_FS_INFO *, TSK_FS_INODE *, TSK_OFF_T,
        size_t, char *);

    extern ssize_t
        tsk_fs_read_file_slack(TSK_FS_INFO *, TSK_FS_INODE *, uint32_t, uint16_t,
        TSK_OFF_T, size_t, char *);

    extern ssize_t
        tsk_fs_read_file_noid_slack(TSK_FS_INFO *, TSK_FS_INODE *, TSK_OFF_T,
        size_t, char *);




/***** LIBRARY ROUTINES FOR COMMAND LINE FUNCTIONS */
#define TSK_FS_DCALC_DD        0x1
#define TSK_FS_DCALC_DLS       0x2
#define TSK_FS_DCALC_SLACK     0x4
    extern int8_t tsk_fs_dcalc(TSK_FS_INFO * fs, uint8_t lclflags,
        TSK_DADDR_T cnt);


#define TSK_FS_DCAT_HEX                0x1
#define TSK_FS_DCAT_ASCII   0x2
#define TSK_FS_DCAT_HTML       0x4
#define TSK_FS_DCAT_STAT       0x8
    extern uint8_t tsk_fs_dcat(TSK_FS_INFO * fs, uint8_t lclflags,
        TSK_DADDR_T addr, TSK_DADDR_T read_num_units);


#define TSK_FS_DLS_CAT     0x01
#define TSK_FS_DLS_LIST    0x02
#define TSK_FS_DLS_SLACK   0x04
    extern uint8_t tsk_fs_dls(TSK_FS_INFO * fs, uint8_t lclflags,
        TSK_DADDR_T bstart, TSK_DADDR_T bend, TSK_FS_BLOCK_FLAG_ENUM flags);

    extern uint8_t tsk_fs_dstat(TSK_FS_INFO * fs, uint8_t lclflags,
        TSK_DADDR_T addr, TSK_FS_BLOCK_FLAG_ENUM flags);

#define TSK_FS_FFIND_ALL 0x1
    extern uint8_t tsk_fs_ffind(TSK_FS_INFO * fs, uint8_t lclflags,
        TSK_INUM_T inode, uint32_t type, uint16_t id, int flags);



#define TSK_FS_FLS_DOT         0x001
#define TSK_FS_FLS_LONG        0x002
#define TSK_FS_FLS_FILE        0x004
#define TSK_FS_FLS_DIR         0x008
#define TSK_FS_FLS_FULL        0x010
#define TSK_FS_FLS_MAC         0x020
    extern uint8_t tsk_fs_fls(TSK_FS_INFO * fs, uint8_t lclflags,
        TSK_INUM_T inode, int flags, TSK_TCHAR * pre, int32_t skew);


    extern uint8_t tsk_fs_icat(TSK_FS_INFO * fs, uint8_t lclflags,
        TSK_INUM_T inum, uint32_t type, uint16_t id, int flags);


#define TSK_FS_IFIND_ALL       0x01
#define TSK_FS_IFIND_PATH      0x04
#define TSK_FS_IFIND_DATA      0x08
#define TSK_FS_IFIND_PAR       0x10
#define TSK_FS_IFIND_PAR_LONG  0x20
    extern int8_t tsk_fs_ifind_path(TSK_FS_INFO * fs, uint8_t lclflags,
        TSK_TCHAR * path, TSK_INUM_T * result);
    extern uint8_t tsk_fs_ifind_data(TSK_FS_INFO * fs, uint8_t lclflags,
        TSK_DADDR_T blk);
    extern uint8_t tsk_fs_ifind_par(TSK_FS_INFO * fs, uint8_t lclflags,
        TSK_INUM_T par);


#define TSK_FS_ILS_OPEN        (1<<0)
#define TSK_FS_ILS_MAC		(1<<1)
#define TSK_FS_ILS_LINK	(1<<2)
#define TSK_FS_ILS_UNLINK	(1<<3)

    extern uint8_t tsk_fs_ils(TSK_FS_INFO * fs, uint8_t lclflags,
        TSK_INUM_T istart, TSK_INUM_T ilast, int flags, int32_t skew,
        TSK_TCHAR * img);



    extern uint8_t
        fatfs_file_walk_off(TSK_FS_INFO * fs, TSK_FS_INODE * fs_inode,
        uint32_t type, uint16_t id, TSK_OFF_T a_st_off,
        TSK_FS_FILE_FLAG_ENUM flags, TSK_FS_FILE_WALK_CB action,
        void *ptr);


#ifdef __cplusplus
}
#endif
#endif
/* LICENSE
 * .ad
 * .fi
 *	This software is distributed under the IBM Public License.
 * AUTHOR(S)
 *	Wietse Venema
 *	IBM T.J. Watson Research
 *	P.O. Box 704
 *	Yorktown Heights, NY 10598, USA
 --*/
