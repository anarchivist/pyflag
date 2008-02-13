/*
 * Library for the Expert Witness Compression Format Support (EWF)
 * The file format both used by EnCase and FTK are based upon EWF
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

#ifndef _LIBEWF_H
#define _LIBEWF_H

#include <libewf/libewf_definitions.h>
#include <libewf/libewf_extern.h>
#include <libewf/libewf_handle.h>
#include <libewf/libewf_types.h>

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Return the library version
 */
#if 0 || defined( HAVE_WIDE_CHARACTER_TYPE )
LIBEWF_EXTERN const wchar_t *libewf_get_version( void );
#else
LIBEWF_EXTERN const char *libewf_get_version( void );
#endif

/* Detects if a file is an EWF file (check for the EWF file signature)
 * Returns 1 if true, 0 if not, or -1 on error
 */
#if ( 0 || defined( HAVE_WIDE_CHARACTER_TYPE ) ) && defined( HAVE_WIDE_CHARACTER_SUPPORT_FUNCTIONS )
LIBEWF_EXTERN int8_t libewf_check_file_signature( const wchar_t *filename );
#else
LIBEWF_EXTERN int8_t libewf_check_file_signature( const char *filename );
#endif

/* Opens EWF file(s)
 * For reading files should contain all filenames that make up an EWF image
 * For writing files should contain the base of the filename, extentions like .e01 will be automatically added
 * Returns a pointer to the new instance of handle, NULL on error
 */
#if ( 0 || defined( HAVE_WIDE_CHARACTER_TYPE ) ) && defined( HAVE_WIDE_CHARACTER_SUPPORT_FUNCTIONS )
LIBEWF_EXTERN LIBEWF_HANDLE *libewf_open( wchar_t * const filenames[], uint16_t file_amount, uint8_t flags );
#else
LIBEWF_EXTERN LIBEWF_HANDLE *libewf_open( char * const filenames[], uint16_t file_amount, uint8_t flags );
#endif

/* Seeks a certain offset of the media data within the EWF file(s)
 * It will set the related file offset to the specific chunk offset
 * Returns the offset if seek is successful, or -1 on error
 */
LIBEWF_EXTERN off_t libewf_seek_offset( LIBEWF_HANDLE *handle, off_t offset );

/* Reads data from the curent offset into a buffer
 * This function swaps byte pairs if specified
 * Returns the amount of bytes read, or -1 on error
 */
LIBEWF_EXTERN ssize_t libewf_read_buffer( LIBEWF_HANDLE *handle, void *buffer, size_t size );

/* Reads media data from an offset into a buffer
 * This function swaps byte pairs if specified
 * Returns the amount of bytes read, or -1 on error
 */
LIBEWF_EXTERN ssize_t libewf_read_random( LIBEWF_HANDLE *handle, void *buffer, size_t size, off_t offset );

/* Writes data in EWF format from a buffer, the necessary settings of the write values must have been made
 * This function swaps byte pairs if specified
 * Returns the amount of input bytes written, 0 when no longer bytes can be written, or -1 on error
 */
LIBEWF_EXTERN ssize_t libewf_write_buffer( LIBEWF_HANDLE *handle, void *buffer, size_t size );

/* Writes data in EWF format from a buffer at an specific offset,
 * the necessary settings of the write values must have been made
 * This function swaps byte pairs
 * Returns the amount of input bytes written, 0 when no longer bytes can be written, or -1 on error
 */
LIBEWF_EXTERN ssize_t libewf_write_random( LIBEWF_HANDLE *handle, void *buffer, size_t size, off_t offset );

/* Finalizes the write by correcting the EWF the meta data in the segment files
 * This function is required after writing from stream
 * Returns the amount of input bytes written, or -1 on error
 */
LIBEWF_EXTERN ssize_t libewf_write_finalize( LIBEWF_HANDLE *handle );

/* Closes the EWF handle and frees memory used within the handle
 * Returns 1 if successful, or -1 on error
 */
LIBEWF_EXTERN int8_t libewf_close( LIBEWF_HANDLE *handle );

/* Returns the amount of bytes per sector from the media information, 0 if not set, -1 on error
 */
LIBEWF_EXTERN int32_t libewf_get_bytes_per_sector( LIBEWF_HANDLE *handle );

/* Returns the amount of sectors from the media information, 0 if not set, -1 on error
 */
LIBEWF_EXTERN int32_t libewf_get_amount_of_sectors( LIBEWF_HANDLE *handle );

/* Returns the chunk size from the media information, 0 if not set, -1 on error
 */
LIBEWF_EXTERN int32_t libewf_get_chunk_size( LIBEWF_HANDLE *handle );

/* Returns the error granularity from the media information, 0 if not set, -1 on error
 */
LIBEWF_EXTERN int32_t libewf_get_error_granularity( LIBEWF_HANDLE *handle );

/* Returns the compression level value, or -1 on error
 */
LIBEWF_EXTERN int8_t libewf_get_compression_level( LIBEWF_HANDLE *handle );

/* Returns the size of the contained media data, 0 if not set, -1 on error
 */
LIBEWF_EXTERN int64_t libewf_get_media_size( LIBEWF_HANDLE *handle );

/* Returns the media type value, or -1 on error
 */
LIBEWF_EXTERN int8_t libewf_get_media_type( LIBEWF_HANDLE *handle );

/* Returns the media flags value, or -1 on error
 */
LIBEWF_EXTERN int8_t libewf_get_media_flags( LIBEWF_HANDLE *handle );

/* Returns the volume type value, or -1 on error
 */
LIBEWF_EXTERN int8_t libewf_get_volume_type( LIBEWF_HANDLE *handle );

/* Returns the format value, or -1 on error
 */
LIBEWF_EXTERN int8_t libewf_get_format( LIBEWF_HANDLE *handle );

/* Returns 1 if the GUID is set, or -1 on error
 */
LIBEWF_EXTERN int8_t libewf_get_guid( LIBEWF_HANDLE *handle, uint8_t *guid, size_t size );

/* Returns the amount of chunks written, 0 if no chunks have been written, or -1 on error
 */
LIBEWF_EXTERN int64_t libewf_get_write_amount_of_chunks( LIBEWF_HANDLE *handle );

/* Retrieves the header value specified by the identifier
 * Returns 1 if successful, 0 if value not present, -1 on error
 */
#if 0 || defined( HAVE_WIDE_CHARACTER_TYPE )
LIBEWF_EXTERN int8_t libewf_get_header_value( LIBEWF_HANDLE *handle, wchar_t *identifier, wchar_t *value, size_t length );
#else
LIBEWF_EXTERN int8_t libewf_get_header_value( LIBEWF_HANDLE *handle, char *identifier, char *value, size_t length );
#endif

/* Retrieves the header value case number
 * Returns 1 if successful, 0 if value not present, -1 on error
 */
#if 0 || defined( HAVE_WIDE_CHARACTER_TYPE )
#define libewf_get_header_value_case_number( handle, value, length ) \
        libewf_get_header_value( handle, L"case_number", value, length )
#else
#define libewf_get_header_value_case_number( handle, value, length ) \
        libewf_get_header_value( handle, "case_number", value, length )
#endif

/* Retrieves the header value description
 * Returns 1 if successful, 0 if value not present, -1 on error
 */
#if 0 || defined( HAVE_WIDE_CHARACTER_TYPE )
#define libewf_get_header_value_description( handle, value, length ) \
        libewf_get_header_value( handle, L"description", value, length )
#else
#define libewf_get_header_value_description( handle, value, length ) \
        libewf_get_header_value( handle, "description", value, length )
#endif

/* Retrieves the header value examiner name
 * Returns 1 if successful, 0 if value not present, -1 on error
 */
#if 0 || defined( HAVE_WIDE_CHARACTER_TYPE )
#define libewf_get_header_value_examiner_name( handle, value, length ) \
        libewf_get_header_value( handle, L"examiner_name", value, length )
#else
#define libewf_get_header_value_examiner_name( handle, value, length ) \
        libewf_get_header_value( handle, "examiner_name", value, length )
#endif

/* Retrieves the header value evidence number
 * Returns 1 if successful, 0 if value not present, -1 on error
 */
#if 0 || defined( HAVE_WIDE_CHARACTER_TYPE )
#define libewf_get_header_value_evidence_number( handle, value, length ) \
        libewf_get_header_value( handle, L"evidence_number", value, length )
#else
#define libewf_get_header_value_evidence_number( handle, value, length ) \
        libewf_get_header_value( handle, "evidence_number", value, length )
#endif

/* Retrieves the header value notes
 * Returns 1 if successful, 0 if value not present, -1 on error
 */
#if 0 || defined( HAVE_WIDE_CHARACTER_TYPE )
#define libewf_get_header_value_notes( handle, value, length ) \
        libewf_get_header_value( handle, L"notes", value, length )
#else
#define libewf_get_header_value_notes( handle, value, length ) \
        libewf_get_header_value( handle, "notes", value, length )
#endif

/* Retrieves the header value acquiry date
 * Returns 1 if successful, 0 if value not present, -1 on error
 */
#if 0 || defined( HAVE_WIDE_CHARACTER_TYPE )
#define libewf_get_header_value_acquiry_date( handle, value, length ) \
        libewf_get_header_value( handle, L"acquiry_date", value, length )
#else
#define libewf_get_header_value_acquiry_date( handle, value, length ) \
        libewf_get_header_value( handle, "acquiry_date", value, length )
#endif

/* Retrieves the header value system date
 * Returns 1 if successful, 0 if value not present, -1 on error
 */
#if 0 || defined( HAVE_WIDE_CHARACTER_TYPE )
#define libewf_get_header_value_system_date( handle, value, length ) \
        libewf_get_header_value( handle, L"system_date", value, length )
#else
#define libewf_get_header_value_system_date( handle, value, length ) \
        libewf_get_header_value( handle, "system_date", value, length )
#endif

/* Retrieves the header value acquiry operating system
 * Returns 1 if successful, 0 if value not present, -1 on error
 */
#if 0 || defined( HAVE_WIDE_CHARACTER_TYPE )
#define libewf_get_header_value_acquiry_operating_system( handle, value, length ) \
        libewf_get_header_value( handle, L"acquiry_operating_system", value, length )
#else
#define libewf_get_header_value_acquiry_operating_system( handle, value, length ) \
        libewf_get_header_value( handle, "acquiry_operating_system", value, length )
#endif

/* Retrieves the header value acquiry software version
 * Returns 1 if successful, 0 if value not present, -1 on error
 */
#if 0 || defined( HAVE_WIDE_CHARACTER_TYPE )
#define libewf_get_header_value_acquiry_software_version( handle, value, length ) \
        libewf_get_header_value( handle, L"acquiry_software_version", value, length )
#else
#define libewf_get_header_value_acquiry_software_version( handle, value, length ) \
        libewf_get_header_value( handle, "acquiry_software_version", value, length )
#endif

/* Retrieves the header value password
 * Returns 1 if successful, 0 if value not present, -1 on error
 */
#if 0 || defined( HAVE_WIDE_CHARACTER_TYPE )
#define libewf_get_header_value_password( handle, value, length ) \
        libewf_get_header_value( handle, L"password", value, length )
#else
#define libewf_get_header_value_password( handle, value, length ) \
        libewf_get_header_value( handle, "password", value, length )
#endif

/* Retrieves the header value compression type
 * Returns 1 if successful, 0 if value not present, -1 on error
 */
#if 0 || defined( HAVE_WIDE_CHARACTER_TYPE )
#define libewf_get_header_value_compression_type( handle, value, length ) \
        libewf_get_header_value( handle, L"compression_type", value, length )
#else
#define libewf_get_header_value_compression_type( handle, value, length ) \
        libewf_get_header_value( handle, "compression_type", value, length )
#endif

/* Retrieves the header value model
 * Returns 1 if successful, 0 if value not present, -1 on error
 */
#if 0 || defined( HAVE_WIDE_CHARACTER_TYPE )
#define libewf_get_header_value_model( handle, value, length ) \
        libewf_get_header_value( handle, L"model", value, length )
#else
#define libewf_get_header_value_model( handle, value, length ) \
        libewf_get_header_value( handle, "model", value, length )
#endif

/* Retrieves the header value serial number
 * Returns 1 if successful, 0 if value not present, -1 on error
 */
#if 0 || defined( HAVE_WIDE_CHARACTER_TYPE )
#define libewf_get_header_value_serial_number( handle, value, length ) \
        libewf_get_header_value( handle, L"serial_number", value, length )
#else
#define libewf_get_header_value_serial_number( handle, value, length ) \
        libewf_get_header_value( handle, "serial_number", value, length )
#endif

/* Retrieves the hash value specified by the identifier
 * Returns 1 if successful, 0 if value not present, -1 on error
 */
#if 0 || defined( HAVE_WIDE_CHARACTER_TYPE )
LIBEWF_EXTERN int8_t libewf_get_hash_value( LIBEWF_HANDLE *handle, wchar_t *identifier, wchar_t *value, size_t length );
#else
LIBEWF_EXTERN int8_t libewf_get_hash_value( LIBEWF_HANDLE *handle, char *identifier, char *value, size_t length );
#endif

/* Sets the media values
 * Returns 1 if successful, -1 on error
 */
LIBEWF_EXTERN int8_t libewf_set_media_values( LIBEWF_HANDLE *handle, uint32_t sectors_per_chunk, uint32_t bytes_per_sector );

/* Returns 1 if the GUID is set, or -1 on error
 */
LIBEWF_EXTERN int8_t libewf_set_guid( LIBEWF_HANDLE *handle, uint8_t *guid, size_t size );

/* Sets the write segment file size
 * Returns 1 if successful, -1 on error
 */
LIBEWF_EXTERN int8_t libewf_set_write_segment_file_size( LIBEWF_HANDLE *handle, uint32_t segment_file_size );

/* Sets the write error granularity
 * Returns 1 if successful, -1 on error
 */
LIBEWF_EXTERN int8_t libewf_set_write_error_granularity( LIBEWF_HANDLE *handle, uint32_t error_granularity );

/* Sets the write compression values
 * Returns 1 if successful, -1 on error
 */
LIBEWF_EXTERN int8_t libewf_set_write_compression_values( LIBEWF_HANDLE *handle, int8_t compression_level, uint8_t compress_empty_block );

/* Sets the media type
 * Returns 1 if successful, -1 on error
 */
LIBEWF_EXTERN int8_t libewf_set_write_media_type( LIBEWF_HANDLE *handle, uint8_t media_type, uint8_t volume_type );

/* Sets the write output format
 * Returns 1 if successful, -1 on error
 */
LIBEWF_EXTERN int8_t libewf_set_write_format( LIBEWF_HANDLE *handle, uint8_t format );

/* Sets the write input size
 * Returns 1 if successful, -1 on error
 */
LIBEWF_EXTERN int8_t libewf_set_write_input_size( LIBEWF_HANDLE *handle, uint64_t input_write_size );

/* Sets the header value specified by the identifier
 * Returns 1 if successful, -1 on error
 */
#if 0 || defined( HAVE_WIDE_CHARACTER_TYPE )
LIBEWF_EXTERN int8_t libewf_set_header_value( LIBEWF_HANDLE *handle, wchar_t *identifier, wchar_t *value, size_t length );
#else
LIBEWF_EXTERN int8_t libewf_set_header_value( LIBEWF_HANDLE *handle, char *identifier, char *value, size_t length );
#endif

/* Sets the header value case number
 * Returns 1 if successful, -1 on error
 */
#if 0 || defined( HAVE_WIDE_CHARACTER_TYPE )
#define libewf_set_header_value_case_number( handle, value, length ) \
        libewf_set_header_value( handle, L"case_number", value, length )
#else
#define libewf_set_header_value_case_number( handle, value, length ) \
        libewf_set_header_value( handle, "case_number", value, length )
#endif

/* Sets the header value description
 * Returns 1 if successful, -1 on error
 */
#if 0 || defined( HAVE_WIDE_CHARACTER_TYPE )
#define libewf_set_header_value_description( handle, value, length ) \
        libewf_set_header_value( handle, L"description", value, length )
#else
#define libewf_set_header_value_description( handle, value, length ) \
        libewf_set_header_value( handle, "description", value, length )
#endif

/* Sets the header value examiner name
 * Returns 1 if successful, -1 on error
 */
#if 0 || defined( HAVE_WIDE_CHARACTER_TYPE )
#define libewf_set_header_value_examiner_name( handle, value, length ) \
        libewf_set_header_value( handle, L"examiner_name", value, length )
#else
#define libewf_set_header_value_examiner_name( handle, value, length ) \
        libewf_set_header_value( handle, "examiner_name", value, length )
#endif

/* Sets the header value evidence number
 * Returns 1 if successful, -1 on error
 */
#if 0 || defined( HAVE_WIDE_CHARACTER_TYPE )
#define libewf_set_header_value_evidence_number( handle, value, length ) \
        libewf_set_header_value( handle, L"evidence_number", value, length )
#else
#define libewf_set_header_value_evidence_number( handle, value, length ) \
        libewf_set_header_value( handle, "evidence_number", value, length )
#endif

/* Sets the header value notes
 * Returns 1 if successful, -1 on error
 */
#if 0 || defined( HAVE_WIDE_CHARACTER_TYPE )
#define libewf_set_header_value_notes( handle, value, length ) \
        libewf_set_header_value( handle, L"notes", value, length )
#else
#define libewf_set_header_value_notes( handle, value, length ) \
        libewf_set_header_value( handle, "notes", value, length )
#endif

/* Sets the header value acquiry date
 * Returns 1 if successful, -1 on error
 */
#if 0 || defined( HAVE_WIDE_CHARACTER_TYPE )
#define libewf_set_header_value_acquiry_date( handle, value, length ) \
        libewf_set_header_value( handle, L"acquiry_date", value, length )
#else
#define libewf_set_header_value_acquiry_date( handle, value, length ) \
        libewf_set_header_value( handle, "acquiry_date", value, length )
#endif

/* Sets the header value system date
 * Returns 1 if successful, -1 on error
 */
#if 0 || defined( HAVE_WIDE_CHARACTER_TYPE )
#define libewf_set_header_value_system_date( handle, value, length ) \
        libewf_set_header_value( handle, L"system_date", value, length )
#else
#define libewf_set_header_value_system_date( handle, value, length ) \
        libewf_set_header_value( handle, "system_date", value, length )
#endif

/* Sets the header value acquiry operating system
 * Returns 1 if successful, -1 on error
 */
#if 0 || defined( HAVE_WIDE_CHARACTER_TYPE )
#define libewf_set_header_value_acquiry_operating_system( handle, value, length ) \
        libewf_set_header_value( handle, L"acquiry_operating_system", value, length )
#else
#define libewf_set_header_value_acquiry_operating_system( handle, value, length ) \
        libewf_set_header_value( handle, "acquiry_operating_system", value, length )
#endif

/* Sets the header value acquiry software version
 * Returns 1 if successful, -1 on error
 */
#if 0 || defined( HAVE_WIDE_CHARACTER_TYPE )
#define libewf_set_header_value_acquiry_software_version( handle, value, length ) \
        libewf_set_header_value( handle, L"acquiry_software_version", value, length )
#else
#define libewf_set_header_value_acquiry_software_version( handle, value, length ) \
        libewf_set_header_value( handle, "acquiry_software_version", value, length )
#endif

/* Sets the header value password
 * Returns 1 if successful, -1 on error
 */
#if 0 || defined( HAVE_WIDE_CHARACTER_TYPE )
#define libewf_set_header_value_password( handle, value, length ) \
        libewf_set_header_value( handle, L"password", value, length )
#else
#define libewf_set_header_value_password( handle, value, length ) \
        libewf_set_header_value( handle, "password", value, length )
#endif

/* Sets the header value compression type
 * Returns 1 if successful, -1 on error
 */
#if 0 || defined( HAVE_WIDE_CHARACTER_TYPE )
#define libewf_set_header_value_compression_type( handle, value, length ) \
        libewf_set_header_value( handle, L"compression_type", value, length )
#else
#define libewf_set_header_value_compression_type( handle, value, length ) \
        libewf_set_header_value( handle, "compression_type", value, length )
#endif

/* Sets the header value model
 * Returns 1 if successful, -1 on error
 */
#if 0 || defined( HAVE_WIDE_CHARACTER_TYPE )
#define libewf_set_header_value_model( handle, value, length ) \
        libewf_set_header_value( handle, L"model", value, length )
#else
#define libewf_set_header_value_model( handle, value, length ) \
        libewf_set_header_value( handle, "model", value, length )
#endif

/* Sets the header value serial number
 * Returns 1 if successful, -1 on error
 */
#if 0 || defined( HAVE_WIDE_CHARACTER_TYPE )
#define libewf_set_header_value_serial_number( handle, value, length ) \
        libewf_set_header_value( handle, L"serial_number", value, length )
#else
#define libewf_set_header_value_serial_number( handle, value, length ) \
        libewf_set_header_value( handle, "serial_number", value, length )
#endif

/* Sets the hash value specified by the identifier
 * Returns 1 if successful, -1 on error
 */
#if 0 || defined( HAVE_WIDE_CHARACTER_TYPE )
LIBEWF_EXTERN int8_t libewf_set_hash_value( LIBEWF_HANDLE *handle, wchar_t *identifier, wchar_t *value, size_t length );
#else
LIBEWF_EXTERN int8_t libewf_set_hash_value( LIBEWF_HANDLE *handle, char *identifier, char *value, size_t length );
#endif

/* Sets the swap byte pairs, used by both read and write
 * Returns 1 if successful, -1 on error
 */
LIBEWF_EXTERN int8_t libewf_set_swap_byte_pairs( LIBEWF_HANDLE *handle, uint8_t swap_byte_pairs );

/* Calculates the MD5 hash and creates a printable string of the calculated md5 hash
 * Returns 1 if successful, -1 on error
 */
#if 0 || defined( HAVE_WIDE_CHARACTER_TYPE )
LIBEWF_EXTERN int8_t libewf_calculate_md5_hash( LIBEWF_HANDLE *handle, wchar_t *string, size_t length );
#else
LIBEWF_EXTERN int8_t libewf_calculate_md5_hash( LIBEWF_HANDLE *handle, char *string, size_t length );
#endif

/* Creates a printable string of the stored md5 hash
 * Returns 1 if successful, -1 on error
 */
#if 0 || defined( HAVE_WIDE_CHARACTER_TYPE )
LIBEWF_EXTERN int8_t libewf_get_stored_md5_hash( LIBEWF_HANDLE *handle, wchar_t *string, size_t length );
#else
LIBEWF_EXTERN int8_t libewf_get_stored_md5_hash( LIBEWF_HANDLE *handle, char *string, size_t length );
#endif

/* Creates a printable string of the calculated md5 hash
 * Returns 1 if successful, -1 on error
 */
#if 0 || defined( HAVE_WIDE_CHARACTER_TYPE )
LIBEWF_EXTERN int8_t libewf_get_calculated_md5_hash( LIBEWF_HANDLE *handle, wchar_t *string, size_t length );
#else
LIBEWF_EXTERN int8_t libewf_get_calculated_md5_hash( LIBEWF_HANDLE *handle, char *string, size_t length );
#endif

/* Parses the header values from the xheader, header2 or header section
 * Will parse the first available header in order mentioned above
 * Returns 1 if successful, -1 on error
 */
LIBEWF_EXTERN int8_t libewf_parse_header_values( LIBEWF_HANDLE *handle, uint8_t date_format );

/* Parses the hash values from the xhash section
 * Returns 1 if successful, -1 on error
 */
LIBEWF_EXTERN int8_t libewf_parse_hash_values( LIBEWF_HANDLE *handle );

/* Add an acquiry error
 * Returns 1 if successful, -1 on error
 */
LIBEWF_EXTERN int8_t libewf_add_acquiry_error( LIBEWF_HANDLE *handle, uint64_t sector, uint32_t amount_of_sectors );

/* Set the notify values
 */
LIBEWF_EXTERN void libewf_set_notify_values( FILE *stream, uint8_t verbose );

#ifdef __cplusplus
}
#endif

#endif

