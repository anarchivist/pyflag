
/* Taken from LibStrfunc v7.3 */

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include "libstrfunc.h"


static char base64_code_chars[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/==";

void base64_append(char **ou, int *line_count, char data)
{
    if (*line_count == 76) {
        *(*ou)++ = '\n';
        *line_count = 0;
    }
    *(*ou)++ = data;
    (*line_count)++;
}


char *base64_encode(void *data, size_t size)
{
    int line_count = 0;
    return base64_encode_multiple(data, size, &line_count);
}


char *base64_encode_multiple(void *data, size_t size, int *line_count)
{
    char *output;
    char *ou;
    unsigned char *p   = (unsigned char *)data;
    unsigned char *dte = p + size;

    if (data == NULL || size == 0) return NULL;

    ou = output = (char *)malloc(size / 3 * 4 + (size / 57) + 5);
    if (!output) return NULL;

    while((dte-p) >= 3) {
        unsigned char x = p[0];
        unsigned char y = p[1];
        unsigned char z = p[2];
        base64_append(&ou, line_count, base64_code_chars[ x >> 2 ]);
        base64_append(&ou, line_count, base64_code_chars[ ((x & 0x03) << 4) | (y >> 4) ]);
        base64_append(&ou, line_count, base64_code_chars[ ((y & 0x0F) << 2) | (z >> 6) ]);
        base64_append(&ou, line_count, base64_code_chars[ z & 0x3F ]);
        p+=3;
    };
    if ((dte-p) == 2) {
        base64_append(&ou, line_count, base64_code_chars[ *p >> 2 ]);
        base64_append(&ou, line_count, base64_code_chars[ ((*p & 0x03) << 4) | (p[1] >> 4) ]);
        base64_append(&ou, line_count, base64_code_chars[ ((p[1] & 0x0F) << 2) ]);
        base64_append(&ou, line_count, '=');
    } else if ((dte-p) == 1) {
        base64_append(&ou, line_count, base64_code_chars[ *p >> 2 ]);
        base64_append(&ou, line_count, base64_code_chars[ ((*p & 0x03) << 4) ]);
        base64_append(&ou, line_count, '=');
        base64_append(&ou, line_count, '=');
    };

    *ou=0;
    return output;
};


void hexdump(char *hbuf, int start, int stop, int ascii) /* {{{ HexDump all or a part of some buffer */
{
    char c;
    int diff,i;

    while (start < stop ) {
        diff = stop - start;
        if (diff > 16) diff = 16;

        fprintf(stderr, ":%08X  ",start);

        for (i = 0; i < diff; i++) {
            if( 8 == i ) fprintf( stderr, " " );
            fprintf(stderr, "%02X ",(unsigned char)*(hbuf+start+i));
        }
        if (ascii) {
            for (i = diff; i < 16; i++) fprintf(stderr, "   ");
            for (i = 0; i < diff; i++) {
                c = *(hbuf+start+i);
                fprintf(stderr, "%c", isprint(c) ? c : '.');
            }
        }
        fprintf(stderr, "\n");
        start += 16;
    }
}
