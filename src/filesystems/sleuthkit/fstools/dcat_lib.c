/*
** dcat
** The  Sleuth Kit 
**
** $Date: 2006/11/29 22:02:08 $
**
** Given an image , block number, and size, display the contents
** of the block to stdout.
** 
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2006 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
** TCTUTILs
** Copyright (c) 2001 Brian Carrier.  All rights reserved
**
**
** This software is distributed under the Common Public License 1.0
**
*/

#include "fs_tools_i.h"
#include <ctype.h>


static void
stats(FS_INFO * fs)
{
    tsk_printf("%d: Size of Addressable Unit\n", fs->block_size);
}


/* return 1 on error and 0 on success */
uint8_t
fs_dcat(FS_INFO * fs, uint8_t lclflags, DADDR_T addr,
    DADDR_T read_num_units)
{
    OFF_T read_num_bytes;
    DATA_BUF *buf;
    SSIZE_T cnt;

    if (lclflags & DCAT_STAT) {
	stats(fs);
	return 0;
    }

#ifdef TSK_WIN32
    if (-1 == _setmode(_fileno(stdout), _O_BINARY)) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_WRITE;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "dcat_lib: error setting stdout to binary: %s",
	    strerror(errno));
	return 1;
    }
#endif

    /* Multiply number of units by block size  to get size in bytes */
    read_num_bytes = read_num_units * fs->block_size;

    if (lclflags & DCAT_HTML) {
	tsk_printf("<html>\n");
	tsk_printf("<head>\n");
	tsk_printf("<title>Unit: %" PRIuDADDR "   Size: %" PRIuOFF
	    " bytes</title>\n", addr, read_num_bytes);
	tsk_printf("</head>\n");
	tsk_printf("<body>\n");

    }
    if (read_num_bytes > 0xffffffff) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_ARG;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "fs_dcat: number of bytes to read is too large -- try dls (%"
	    PRIuOFF ")", read_num_bytes);
	return 1;
    }

    buf = data_buf_alloc((size_t) read_num_bytes);
    if (buf == NULL) {
	return 1;
    }

    /* Read the data */
    if (addr > fs->last_block) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_ARG;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "fs_dcat: block is larger than last block in image (%"
	    PRIuDADDR ")", fs->last_block);
	return 1;
    }
    cnt = fs_read_block(fs, buf, read_num_bytes, addr);
    if (cnt != (SSIZE_T) read_num_bytes) {
	if (cnt != -1) {
	    tsk_error_reset();
	    tsk_errno = TSK_ERR_FS_READ;
	}
	snprintf(tsk_errstr2, TSK_ERRSTR_L,
	    "dcat: Error reading block at %" PRIuDADDR, addr);
	return 1;
    }


    /* do a hexdump like printout */
    if (lclflags & DCAT_HEX) {
	OFF_T idx1, idx2;

	if (lclflags & DCAT_HTML)
	    tsk_printf("<table border=0>\n");

	for (idx1 = 0; idx1 < read_num_bytes; idx1 += 16) {
	    if (lclflags & DCAT_HTML)
		tsk_printf("<tr><td>%" PRIuOFF "</td>", idx1);
	    else
		tsk_printf("%" PRIuOFF "\t", idx1);


	    for (idx2 = 0; idx2 < 16; idx2++) {
		if ((lclflags & DCAT_HTML) && (0 == (idx2 % 4)))
		    tsk_printf("<td>");

		tsk_printf("%.2x", buf->data[idx2 + idx1] & 0xff);

		if (3 == (idx2 % 4)) {
		    if (lclflags & DCAT_HTML)
			tsk_printf("</td>");
		    else
			tsk_printf(" ");
		}
	    }

	    tsk_printf("\t");
	    for (idx2 = 0; idx2 < 16; idx2++) {
		if ((lclflags & DCAT_HTML) && (0 == (idx2 % 4)))
		    tsk_printf("<td>");

		if ((isascii((int) buf->data[idx2 + idx1])) &&
		    (!iscntrl((int) buf->data[idx2 + idx1])))
		    tsk_printf("%c", buf->data[idx2 + idx1]);
		else
		    tsk_printf(".");

		if (3 == (idx2 % 4)) {
		    if (lclflags & DCAT_HTML)
			tsk_printf("</td>");
		    else
			tsk_printf(" ");
		}
	    }

	    if (lclflags & DCAT_HTML)
		tsk_printf("</tr>");

	    tsk_printf("\n");
	}


	if (lclflags & DCAT_HTML)
	    tsk_printf("</table>\n");
	else
	    tsk_printf("\n");

    }				/* end of if hexdump */

    /* print in all ASCII */
    else if (lclflags & DCAT_ASCII) {
	OFF_T idx;
	for (idx = 0; idx < read_num_bytes; idx++) {

	    if ((isprint((int) buf->data[idx]))
		|| (buf->data[idx] == '\t')) {
		tsk_printf("%c", buf->data[idx]);
	    }
	    else if ((buf->data[idx] == '\n') || (buf->data[idx] == '\r')) {
		if (lclflags & DCAT_HTML)
		    tsk_printf("<br>");
		tsk_printf("%c", buf->data[idx]);
	    }
	    else
		tsk_printf(".");
	}
	if (lclflags & DCAT_HTML)
	    tsk_printf("<br>");

	tsk_printf("\n");
    }

    /* print raw */
    else {
	if (fwrite(buf->data, (size_t) read_num_bytes, 1, stdout) != 1) {
	    tsk_error_reset();
	    tsk_errno = TSK_ERR_FS_WRITE;
	    snprintf(tsk_errstr, TSK_ERRSTR_L,
		"dcat_lib: error writing to stdout: %s", strerror(errno));
	    data_buf_free(buf);
	    return 1;
	}

	if (lclflags & DCAT_HTML)
	    tsk_printf("<br>\n");
    }

    data_buf_free(buf);

    if (lclflags & DCAT_HTML)
	tsk_printf("</body>\n</html>\n");

    return 0;
}
