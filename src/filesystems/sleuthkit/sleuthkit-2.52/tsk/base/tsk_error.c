/*
 * The Sleuth Kit 
 *
 * $Date: 2007/12/20 20:32:38 $
 *
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2006-2007 Brian Carrier.  All Rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */
#include "tsk_base_i.h"

/**
 * \file tsk_error.c
 * Contains the error handling code and variables.
 */


/* Global variables that fit here as well as anywhere */
char *progname = "unknown";
int tsk_verbose = 0;

uint32_t tsk_errno = 0;         /* Set when an error occurs */
char tsk_errstr[TSK_ERRSTR_L];  /* Contains an error-specific string
                                 * and is valid only when tsk_errno is set 
                                 *
                                 * This should be set when errno is set,
                                 * if it is not needed, then set 
                                 * tsk_errstr[0] to '\0'.
                                 * */

char tsk_errstr2[TSK_ERRSTR_L]; /* Contains a caller-specific string 
                                 * and is valid only when tsk_errno is set 
                                 *
                                 * This is typically set to start with a NULL
                                 * char when errno is set and then set with
                                 * a string by the code that called the 
                                 * function that had the error.  For
                                 * example, the X_read() function may set why
                                 * the read failed in tsk_errstr and the
                                 * function that called X_read() can provide
                                 * more context about why X_read() was 
                                 * called in the first place
                                 */

char tsk_errstr_print[TSK_ERRSTR_PR_L];

const char *tsk_err_aux_str[TSK_ERR_IMG_MAX] = {
    "Insufficient memory",
    ""
};

/* imagetools specific error strings */
const char *tsk_err_img_str[TSK_ERR_IMG_MAX] = {
    "Missing image file names",
    "Invalid image offset",
    "Cannot determine image type",
    "Unsupported image type",
    "Error opening image file",
    "Error stat(ing) image file",
    "Error seeking in image file",
    "Error reading image file",
    "Read offset too large for image file",
    "Invalid image format layer sequence",
    "Invalid magic value",
    "Error writing data",
};


const char *tsk_err_mm_str[TSK_ERR_MM_MAX] = {
    "Cannot determine partition type",
    "Unsupported partition type",
    "Error reading image file",
    "Invalid magic value",
    "Invalid walk range",
    "Invalid buffer size",
    "Invalid sector address"
};

const char *tsk_err_fs_str[TSK_ERR_FS_MAX] = {
    "Cannot determine file system type",
    "Unsupported file system type",
    "Function not supported",
    "Invalid walk range",
    "Error reading image file",
    "Invalid argument",
    "Invalid block address",
    "Invalid metadata address",
    "Error in metadata structure",
    "Invalid magic value",
    "Error extracting file from image",
    "Error writing data",
    "Error converting Unicode",
    "Error recovering deleted file",
    "General file system error",
    "File system is corrupt"
};

const char *tsk_err_hdb_str[TSK_ERR_HDB_MAX] = {
    "Cannot determine hash database type",
    "Unsupported hash database type",
    "Error reading hash database file",
    "Error reading hash database index",
    "Invalid argument",
    "Error writing data",
    "Error creating file",
    "Error deleting file",
    "Missing file",
    "Error creating process",
    "Error opening file",
    "Corrupt hash database"
};


/**
 * Return the string with the current error message.  The string does not end with a 
 * newline and it should not be freed.
 *
 * @returns String (in static buffer) with error message or NULL if there is no error
 */
const char *
tsk_error_get()
{
    size_t pidx = 0;

    if (tsk_errno == 0)
        return NULL;

    memset(tsk_errstr_print, 0, TSK_ERRSTR_PR_L);
    if (tsk_errno & TSK_ERR_AUX) {
        if ((TSK_ERR_MASK & tsk_errno) < TSK_ERR_AUX_MAX)
            snprintf(&tsk_errstr_print[pidx], TSK_ERRSTR_PR_L - pidx,
                "%s", tsk_err_aux_str[tsk_errno & TSK_ERR_MASK]);
        else
            snprintf(&tsk_errstr_print[pidx], TSK_ERRSTR_PR_L - pidx,
                "auxtools error: %" PRIu32, TSK_ERR_MASK & tsk_errno);
    }
    else if (tsk_errno & TSK_ERR_IMG) {
        if ((TSK_ERR_MASK & tsk_errno) < TSK_ERR_IMG_MAX)
            snprintf(&tsk_errstr_print[pidx], TSK_ERRSTR_PR_L - pidx,
                "%s", tsk_err_img_str[tsk_errno & TSK_ERR_MASK]);
        else
            snprintf(&tsk_errstr_print[pidx], TSK_ERRSTR_PR_L - pidx,
                "imgtools error: %" PRIu32, TSK_ERR_MASK & tsk_errno);
    }
    else if (tsk_errno & TSK_ERR_MM) {
        if ((TSK_ERR_MASK & tsk_errno) < TSK_ERR_MM_MAX)
            snprintf(&tsk_errstr_print[pidx], TSK_ERRSTR_PR_L - pidx,
                "%s", tsk_err_mm_str[tsk_errno & TSK_ERR_MASK]);
        else
            snprintf(&tsk_errstr_print[pidx], TSK_ERRSTR_PR_L - pidx,
                "mmtools error: %" PRIu32, TSK_ERR_MASK & tsk_errno);
    }
    else if (tsk_errno & TSK_ERR_FS) {
        if ((TSK_ERR_MASK & tsk_errno) < TSK_ERR_FS_MAX)
            snprintf(&tsk_errstr_print[pidx], TSK_ERRSTR_PR_L - pidx,
                "%s", tsk_err_fs_str[tsk_errno & TSK_ERR_MASK]);
        else
            snprintf(&tsk_errstr_print[pidx], TSK_ERRSTR_PR_L - pidx,
                "fstools error: %" PRIu32, TSK_ERR_MASK & tsk_errno);
    }
    else if (tsk_errno & TSK_ERR_HDB) {
        if ((TSK_ERR_MASK & tsk_errno) < TSK_ERR_HDB_MAX)
            snprintf(&tsk_errstr_print[pidx], TSK_ERRSTR_PR_L - pidx,
                "%s", tsk_err_hdb_str[tsk_errno & TSK_ERR_MASK]);
        else
            snprintf(&tsk_errstr_print[pidx], TSK_ERRSTR_PR_L - pidx,
                "hashtools error: %" PRIu32, TSK_ERR_MASK & tsk_errno);
    }
    else {
        snprintf(&tsk_errstr_print[pidx], TSK_ERRSTR_PR_L - pidx,
            "Unknown Error: %" PRIu32, tsk_errno);
    }
    pidx = strlen(tsk_errstr_print);

    /* Print the unique string, if it exists */
    if (tsk_errstr[0] != '\0') {
        snprintf(&tsk_errstr_print[pidx], TSK_ERRSTR_PR_L - pidx,
            " (%s)", tsk_errstr);
        pidx = strlen(tsk_errstr_print);
    }

    if (tsk_errstr2[0] != '\0') {
        snprintf(&tsk_errstr_print[pidx], TSK_ERRSTR_PR_L - pidx,
            " (%s)", tsk_errstr2);
        pidx = strlen(tsk_errstr_print);
    }
    return (char *) &tsk_errstr_print[0];
}

/**
 * Print the current error message to a file.
 *
 * @param hFile File to print message to
 */
void
tsk_error_print(FILE * hFile)
{
    const char *str;
    if (tsk_errno == 0)
        return;

    str = tsk_error_get();
    if (str != NULL) {
        tsk_fprintf(hFile, "%s\n", str);
    }
    else {
        tsk_fprintf(hFile, "Error creating Sleuth Kit error string (Errno: %d)\n", tsk_errno);
    }
}

/* Clear the error number and error message */
void
tsk_error_reset()
{
    tsk_errno = 0;
    tsk_errstr[0] = '\0';
    tsk_errstr2[0] = '\0';
}
