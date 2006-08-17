/*
 * Library for the Expert Witness Compression Format Support (EWF)
 * The file format both used by Encase and FTK are based upon EWF
 *
 * Copyright (c) 2006, Joachim Metz <forensics@hoffmannbv.nl>,
 * Hoffmann Investigations. All rights reserved.
 *
 * This code is derrived from information and software contributed by
 * - Expert Witness Compression Format specification by Andrew Rosen
 *   (http://www.arsdata.com/SMART/whitepaper.html)
 * - libevf from PyFlag by Michael Cohen
 *   (http://pyflag.sourceforge.net/)
 * - Open SSL for the implementation of the MD5 hash algorithm
 * - Wietse Venema for error handling code
 *
 * Additional credits go to
 * - Robert Jan Mora for testing and other contribution
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
 *   must acknowledge the contribution by people stated above.
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

#ifndef _LIBEWF_H
#define _LIBEWF_H

#include "definitions.h"

#include "notify.h"

#include "ewf_compress.h"
#include "file.h"
#include "file_read.h"
#include "file_write.h"
#include "handle.h"
#include "header_values.h"
#include "version.h"

#ifdef __cplusplus
extern "C" {
#endif

extern uint8_t libewf_check_file_signature( const char *filename );
extern LIBEWF_HANDLE *libewf_open( const char **filenames, uint32_t file_amount, uint8_t flags );
extern int64_t libewf_read_random( LIBEWF_HANDLE *handle, void *buffer, uint64_t size, uint64_t offset );
extern void libewf_close( LIBEWF_HANDLE *handle );
extern uint64_t libewf_data_size( LIBEWF_HANDLE *handle );
extern char *libewf_data_md5hash( LIBEWF_HANDLE *handle );
extern char *libewf_calculate_md5hash( LIBEWF_HANDLE *handle );

extern int64_t libewf_read_to_file_descriptor( LIBEWF_HANDLE *handle, int output_file_descriptor, void (*callback)( uint64_t bytes_read, uint64_t bytes_total ) );

extern LIBEWF_HANDLE *libewf_set_write_parameters( LIBEWF_HANDLE *handle, uint64_t input_file_size, uint32_t sectors_per_chunk, uint32_t bytes_per_sector, uint32_t error_granularity_sectors, uint64_t ewf_file_size, int8_t compression_level, uint8_t format, LIBEWF_HEADER_VALUES *header_values );
extern int64_t libewf_write_from_file_descriptor( LIBEWF_HANDLE *handle, int input_file_descriptor, void (*callback)( uint64_t bytes_read, uint64_t bytes_total ) );

#ifdef __cplusplus
}
#endif

#endif

