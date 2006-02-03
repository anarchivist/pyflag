/*
** dcat
** The  Sleuth Kit 
**
** $Date: 2005/09/02 23:34:02 $
**
** Given an image , block number, and size, display the contents
** of the block to stdout.
** 
** Brian Carrier [carrier@sleuthkit.org]
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

#include "libfstools.h"
#include <ctype.h>


static void
stats(FS_INFO * fs)
{
    printf("%d: Size of Addressable Unit\n", fs->block_size);
}


uint8_t
fs_dcat(FS_INFO * fs, uint8_t lclflags, DADDR_T addr,
	DADDR_T read_num_units)
{
    OFF_T read_num_bytes;
    DATA_BUF *buf;

    if (lclflags & DCAT_STAT) {
	stats(fs);
	return 1;
    }

    /* Multiply number of units by block size  to get size in bytes */
    read_num_bytes = read_num_units * fs->block_size;

    if (lclflags & DCAT_HTML) {
	printf("<html>\n");
	printf("<head>\n");
	printf("<title>Unit: %" PRIuDADDR "   Size: %" PRIuOFF
	       " bytes</title>\n", addr, read_num_bytes);
	printf("</head>\n");
	printf("<body>\n");

    }

    buf = data_buf_alloc(read_num_bytes);

    /* Read the data */
    if (addr > fs->last_block) {
	printf("Error: block is larger than last block in image (%"
	       PRIuDADDR ")\n", fs->last_block);
	return 1;
    }
    if (fs_read_block(fs, buf, read_num_bytes, addr) != read_num_bytes) {
	error("dcat: Error reading block at %" PRIuDADDR ": %m", addr);
    }


    /* do a hexdump like printout */
    if (lclflags & DCAT_HEX) {
	OFF_T idx1, idx2;

	if (lclflags & DCAT_HTML)
	    printf("<table border=0>\n");

	for (idx1 = 0; idx1 < read_num_bytes; idx1 += 16) {
	    if (lclflags & DCAT_HTML)
		printf("<tr><td>%" PRIuOFF "</td>", idx1);
	    else
		printf("%" PRIuOFF "\t", idx1);


	    for (idx2 = 0; idx2 < 16; idx2++) {
		if ((lclflags & DCAT_HTML) && (0 == (idx2 % 4)))
		    printf("<td>");

		printf("%.2x", buf->data[idx2 + idx1] & 0xff);

		if (3 == (idx2 % 4)) {
		    if (lclflags & DCAT_HTML)
			printf("</td>");
		    else
			printf(" ");
		}
	    }

	    printf("\t");
	    for (idx2 = 0; idx2 < 16; idx2++) {
		if ((lclflags & DCAT_HTML) && (0 == (idx2 % 4)))
		    printf("<td>");

		if ((isascii((int) buf->data[idx2 + idx1])) &&
		    (!iscntrl((int) buf->data[idx2 + idx1])))
		    printf("%c", buf->data[idx2 + idx1]);
		else
		    printf(".");

		if (3 == (idx2 % 4)) {
		    if (lclflags & DCAT_HTML)
			printf("</td>");
		    else
			printf(" ");
		}
	    }

	    if (lclflags & DCAT_HTML)
		printf("</tr>");

	    printf("\n");
	}


	if (lclflags & DCAT_HTML)
	    printf("</table>\n");
	else
	    printf("\n");

    }				/* end of if hexdump */

    /* print in all ASCII */
    else if (lclflags & DCAT_ASCII) {
	OFF_T idx;
	for (idx = 0; idx < read_num_bytes; idx++) {

	    if ((isprint((int) buf->data[idx]))
		|| (buf->data[idx] == '\t')) {
		printf("%c", buf->data[idx]);
	    }
	    else if ((buf->data[idx] == '\n') || (buf->data[idx] == '\r')) {
		if (lclflags & DCAT_HTML)
		    printf("<br>");
		printf("%c", buf->data[idx]);
	    }
	    else
		printf(".");
	}
	if (lclflags & DCAT_HTML)
	    printf("<br>");

	printf("\n");
    }

    /* print raw */
    else {
	if (fwrite(buf->data, read_num_bytes, 1, stdout) != 1)
	    error("write: %m");

	if (lclflags & DCAT_HTML)
	    printf("<br>\n");
    }

    data_buf_free(buf);

    if (lclflags & DCAT_HTML)
	printf("</body>\n</html>\n");

    return 0;
}
