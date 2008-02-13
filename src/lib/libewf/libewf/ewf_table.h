/*
 * EWF table section
 *
 * Copyright (c) 2006-2007, Joachim Metz <forensics@hoffmannbv.nl>,
 * Hoffmann Investigations. All rights reserved.
 *
 * Refer to AUTHORS for acknowledgements.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * - Neither the name of the creator, related organisations, nor the names of
 *   its contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 * - All advertising materials mentioning features or use of this software
 *   must acknowledge the contribution by people stated in the acknowledgements.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER, COMPANY AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _EWF_TABLE_H
#define _EWF_TABLE_H

#include "libewf_includes.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EWF_TABLE ewf_table_t
#define EWF_TABLE_SIZE sizeof( EWF_TABLE )

#define EWF_TABLE_OFFSET ewf_table_offset_t
#define EWF_TABLE_OFFSET_SIZE sizeof( EWF_TABLE_OFFSET )

typedef struct ewf_table ewf_table_t;
typedef struct ewf_table_offset ewf_table_offset_t;

struct ewf_table
{
	/* The amount of chunks in the table
	 * consists of 4 bytes (32 bits)
	 */
	uint8_t amount_of_chunks[ 4 ];

	/* Padding
	 * consists of 16 bytes
	 * value should be 0x00
	 */
	uint8_t padding[ 16 ];

	/* The section crc of all (previous) table data
	 * consits of 4 bytes
	 * starts with offset 76
	 */
	uint8_t crc[ 4 ];

	/* The offset array
	 * consits of 4 bytes per offset
	 * as long as necessary
	 * can contain 16375 entries per table
	 */

	/* The last offset is followed by a 4 byte CRC
	 */
};

struct ewf_table_offset
{
	/* An offset
	 * consits of 4 bytes
	 */
	uint8_t offset[ 4 ];
};

ssize_t ewf_table_read( EWF_TABLE *table, int file_descriptor );
ssize_t ewf_table_offsets_read( EWF_TABLE_OFFSET *offsets, int file_descriptor, uint32_t amount );
ssize_t ewf_table_write( EWF_TABLE *table, int file_descriptor );
ssize_t ewf_table_offsets_write( EWF_TABLE_OFFSET *offsets, int file_descriptor, uint32_t amount, uint8_t write_crc );

#ifdef __cplusplus
}
#endif

#endif

