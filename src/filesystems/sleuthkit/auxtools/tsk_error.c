#include <stdio.h>
#include <stdlib.h>

#include "tsk_os.h"

#if defined (HAVE_UNISTD)
#include <unistd.h>
#endif

#include "tsk_types.h"
#include "tsk_error.h"

/* Global variables that fit here as well as anywhere */
char *progname = "unknown";
int verbose = 0;

uint32_t tsk_errno = 0;		/* Set when an error occurs */
char tsk_errstr[TSK_ERRSTR_L];	/* Contains an error-specific string
				 * and is valid only when tsk_errno is set 
				 *
				 * This should be set when errno is set,
				 * if it is not needed, then set 
				 * tsk_errstr[0] to '\0'.
				 * */

char tsk_errstr2[TSK_ERRSTR_L];	/* Contains a caller-specific string 
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

char tsk_errstr3[TSK_ERRSTR_L];	/* The static buffer used in tsk_error_str */

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
    "Cannot determine partiton type",
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
    "General file system error"
};



/* Print the error message to hFile */
void
tsk_error_print(FILE * hFile)
{
    fprintf(hFile, "%s\n", tsk_error_str());
}

/* Print the error message to the static error buffer and return it */
char *
tsk_error_str()
{
    int written = 0;
    tsk_errstr3[0] = '\0';

    if (tsk_errno == 0)
        return tsk_errstr3;

    if (tsk_errno & TSK_ERR_AUX) {
	if ((TSK_ERR_MASK & tsk_errno) < TSK_ERR_AUX_MAX)
	    written += snprintf(tsk_errstr3, TSK_ERRSTR_L - written, "%s",
                    		tsk_err_aux_str[tsk_errno & TSK_ERR_MASK]);
	else
	    written += snprintf(tsk_errstr3, TSK_ERRSTR_L - written, 
                            "auxtools error: %" PRIu32,
		                    TSK_ERR_MASK & tsk_errno);
    }
    else if (tsk_errno & TSK_ERR_IMG) {
	if ((TSK_ERR_MASK & tsk_errno) < TSK_ERR_IMG_MAX)
	    written += snprintf(tsk_errstr3, TSK_ERRSTR_L - written, "%s",
		                    tsk_err_img_str[tsk_errno & TSK_ERR_MASK]);
	else
	    written += snprintf(tsk_errstr3, TSK_ERRSTR_L - written,
                            "imgtools error: %" PRIu32,
                            TSK_ERR_MASK & tsk_errno);
    }
    else if (tsk_errno & TSK_ERR_MM) {
	if ((TSK_ERR_MASK & tsk_errno) < TSK_ERR_MM_MAX)
	    written += snprintf(tsk_errstr3, TSK_ERRSTR_L - written, "%s",
                            tsk_err_mm_str[tsk_errno & TSK_ERR_MASK]);
	else
	    written += snprintf(tsk_errstr3, TSK_ERRSTR_L - written,
                            "mmtools error: %" PRIu32,
                    		TSK_ERR_MASK & tsk_errno);
    }
    else if (tsk_errno & TSK_ERR_FS) {
	if ((TSK_ERR_MASK & tsk_errno) < TSK_ERR_FS_MAX)
	    written += snprintf(tsk_errstr3, TSK_ERRSTR_L - written,
                            "%s", tsk_err_fs_str[tsk_errno & TSK_ERR_MASK]);
	else
	    written += snprintf(tsk_errstr3, TSK_ERRSTR_L - written,
                            "fstools error: %" PRIu32,
		                    TSK_ERR_MASK & tsk_errno);
    }
    else {
	written += snprintf(tsk_errstr3, TSK_ERRSTR_L - written,
                        "Error: %" PRIu32, tsk_errno);
    }

    /* Print the unique string, if it exists */
    if (tsk_errstr[0] != '\0')
	written += snprintf(tsk_errstr3, TSK_ERRSTR_L - written,
                        " (%s)", tsk_errstr);

    if (tsk_errstr2[0] != '\0')
	written += snprintf(tsk_errstr3, TSK_ERRSTR_L,
                        " (%s)", tsk_errstr2);

    return tsk_errstr3;
}

/* Clear the error number and error message */
void
tsk_error_reset()
{
	tsk_errno = 0;
	tsk_errstr[0] = '\0';
	tsk_errstr2[0] = '\0';
	tsk_errstr3[0] = '\0';
}

