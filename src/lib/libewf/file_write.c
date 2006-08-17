/*
 * libewf file writing
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

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <string.h>
#include <time.h>
#include <zlib.h>
#include <errno.h>

#include "libewf_endian.h"
#include "notify.h"
#include "md5.h"

#include "ewf_compress.h"
#include "ewf_crc.h"
#include "ewf_data.h"
#include "ewf_error2.h"
#include "ewf_md5hash.h"
#include "ewf_file_header.h"
#include "ewf_hash.h"
#include "ewf_header.h"
#include "ewf_header2.h"
#include "ewf_section.h"
#include "ewf_volume.h"
#include "ewf_table.h"
#include "file_write.h"
#include "handle.h"
#include "section_list.h"
#include "offset_table.h"
#include "segment_table.h"

/* Write a section start to file
 */
int64_t libewf_section_write( LIBEWF_HANDLE *handle, int file_descriptor, char *section_type, uint64_t section_data_size, uint64_t start_offset )
{
	EWF_SECTION *section;
	size_t section_type_size;
	uint64_t section_size;
	uint64_t section_offset;
	ssize_t write_count;

	if( handle == NULL )
	{
		LIBEWF_FATAL_PRINT( "libewf_section_write: incorrect handle.\n" );
	}
	section           = ewf_section_alloc();
	section_type_size = strlen( section_type );
	section_size      = EWF_SECTION_SIZE + section_data_size;
	section_offset    = start_offset + section_size;

	if( section_type_size >= 16 )
	{
		LIBEWF_FATAL_PRINT( "libewf_section_write: section type is too long.\n" );
	}
	memcpy( (uint8_t *) section->type, (uint8_t *) section_type, section_type_size );

	revert_64bit( section_size, section->size );
	revert_64bit( section_offset, section->next );

	write_count = ewf_section_write( section, file_descriptor );

	ewf_section_free( section );

	if( write_count == -1 )
	{
		LIBEWF_FATAL_PRINT( "libewf_section_write: unable to write section to file.\n" );
	}
	return( write_count );
}

/* Write the last section start to file
 * This is used for the next and done sections, these sections point back towards themselves
 */
int64_t libewf_last_section_write( LIBEWF_HANDLE *handle, int file_descriptor, char *section_type, uint64_t start_offset )
{
	EWF_SECTION *section;
	size_t section_type_size;
	uint64_t section_size;
	uint64_t section_offset;
	ssize_t write_count;

	if( handle == NULL )
	{
		LIBEWF_FATAL_PRINT( "libewf_last_section_write: incorrect handle.\n" );
	}
	section           = ewf_section_alloc();
	section_type_size = strlen( section_type );
	section_size      = EWF_SECTION_SIZE;
	section_offset    = start_offset;

	if( section_type_size >= 16 )
	{
		LIBEWF_FATAL_PRINT( "libewf_last_section_write: section type is too long.\n" );
	}
	memcpy( (uint8_t *) section->type, (uint8_t *) section_type, section_type_size );

	revert_64bit( section_size, section->size );
	revert_64bit( section_offset, section->next );

	write_count = ewf_section_write( section, file_descriptor );

	ewf_section_free( section );

	if( write_count == -1 )
	{
		LIBEWF_FATAL_PRINT( "libewf_last_section_write: unable to write section to file.\n" );
	}
	return( write_count );
}

/* Write a header section to file
 */
int64_t libewf_section_header_write( LIBEWF_HANDLE *handle, int file_descriptor, uint64_t start_offset, EWF_HEADER *header, uint32_t size )
{
	EWF_HEADER *compressed_header;
	int64_t section_write_count;
	int64_t header_write_count;

	if( handle == NULL )
	{
		LIBEWF_FATAL_PRINT( "libewf_section_header_write: incorrect handle.\n" );
	}
	if( header == NULL )
	{
		LIBEWF_FATAL_PRINT( "libewf_section_header_write: incorrect header.\n" );
	}
	LIBEWF_VERBOSE_PRINT( "libewf_section_header_write: Header:\n" );
	LIBEWF_VERBOSE_EXEC( ewf_header_fprint( stderr, header ); );

	compressed_header   = ewf_header_compress( header, &size, EWF_COMPRESSION_DEFAULT );
	section_write_count = libewf_section_write( handle, file_descriptor, "header", size, start_offset );
	header_write_count  = ewf_header_write( compressed_header, file_descriptor, size );

	ewf_header_free( compressed_header );

	if( header_write_count == -1 )
	{
		LIBEWF_FATAL_PRINT( "libewf_section_header_write: unable to write header to file.\n" );
	}
	return( section_write_count + header_write_count );
}

/* Write a header2 section to file
 */
int64_t libewf_section_header2_write( LIBEWF_HANDLE *handle, int file_descriptor, uint64_t start_offset, EWF_HEADER *header, uint32_t size )
{
	uint32_t size_utf16;
	EWF_HEADER *utf16_header;
	EWF_HEADER *compressed_header;
	int64_t section_write_count;
	int64_t  header_write_count;

	if( handle == NULL )
	{
		LIBEWF_FATAL_PRINT( "libewf_section_header2_write: incorrect handle.\n" );
	}
	if( header == NULL )
	{
		LIBEWF_FATAL_PRINT( "libewf_section_header2_write: incorrect header.\n" );
	}
	LIBEWF_VERBOSE_PRINT( "libewf_section_header2_write: Header:\n" );
	LIBEWF_VERBOSE_EXEC( ewf_header_fprint( stderr, header ); );

	size_utf16          = ( size * 2 ) + 4;
	utf16_header        = ewf_header2_convert_ascii_to_utf16( header, size );
	compressed_header   = ewf_header_compress( utf16_header, &size_utf16, EWF_COMPRESSION_DEFAULT );
	section_write_count = libewf_section_write( handle, file_descriptor, "header2", size_utf16, start_offset );
	header_write_count  = ewf_header_write( compressed_header, file_descriptor, size_utf16 );

	ewf_header_free( utf16_header );
	ewf_header_free( compressed_header );

	if( header_write_count == -1 )
	{
		LIBEWF_FATAL_PRINT( "libewf_section_header2_write: unable to write header to file.\n" );
	}
	return( section_write_count + header_write_count );
}

/* Write a volume section to file
 */
int64_t libewf_section_volume_write( LIBEWF_HANDLE *handle, int file_descriptor, uint64_t start_offset )
{
	EWF_VOLUME *volume;
	int64_t section_write_count;
	int64_t volume_write_count;
	size_t size = EWF_VOLUME_SIZE;

	if( handle == NULL )
	{
		LIBEWF_FATAL_PRINT( "libewf_section_volume_write: incorrect handle.\n" );
	}
	volume = ewf_volume_alloc();

	revert_32bit( handle->chunk_count, volume->chunk_count );
	revert_32bit( handle->sectors_per_chunk, volume->sectors_per_chunk );
	revert_32bit( handle->bytes_per_sector, volume->bytes_per_sector );
	revert_32bit( handle->sector_count, volume->sector_count );

	LIBEWF_VERBOSE_PRINT( "libewf_section_volume_write: chunk_count: %" PRIu32 ", sectors_per_chunk: %" PRIu32 ", bytes_per_sector: %" PRIu32 ", sector_count: %" PRIu32 ".\n", volume->chunk_count, volume->sectors_per_chunk, volume->bytes_per_sector, volume->sector_count );

	if( handle->format == LIBEWF_FORMAT_ENCASE5 )
	{
		volume->compression_level = handle->compression_level;
	}
	section_write_count = libewf_section_write( handle, file_descriptor, "volume", size, start_offset );
	volume_write_count  = ewf_volume_write( volume, file_descriptor );

	ewf_volume_free( volume );

	if( volume_write_count == -1 )
	{
		LIBEWF_FATAL_PRINT( "libewf_section_volume_write: unable to write volume to file.\n" );
	}
	return( section_write_count + volume_write_count );
}

/* Write a table or table2 section to file
 */
int64_t libewf_section_table_write( LIBEWF_HANDLE *handle, int file_descriptor, uint64_t start_offset, EWF_TABLE_OFFSET *offsets, uint32_t offsets_amount, char *section_header )
{
	EWF_TABLE *table;
	int64_t section_write_count;
	int64_t table_write_count;
	int64_t table_offsets_write_count;
	size_t size = EWF_TABLE_SIZE + ( EWF_TABLE_OFFSET_SIZE * offsets_amount ) + EWF_CRC_SIZE;

	if( handle == NULL )
	{
		LIBEWF_FATAL_PRINT( "libewf_section_table_write: incorrect handle.\n" );
	}
	table = ewf_table_alloc();

	revert_32bit( offsets_amount, table->chunk_count );

	section_write_count       = libewf_section_write( handle, file_descriptor, section_header, size, start_offset );
	table_write_count         = ewf_table_write( table, file_descriptor );
	table_offsets_write_count = ewf_table_offsets_write( offsets, file_descriptor, offsets_amount );

	ewf_table_free( table );

	if( table_write_count == -1 )
	{
		LIBEWF_FATAL_PRINT( "libewf_section_table_write: unable to write table to file.\n" );
	}
	if( table_offsets_write_count == -1 )
	{
		LIBEWF_FATAL_PRINT( "libewf_section_table_write: unable to write table offsets to file.\n" );
	}
	return( section_write_count + table_write_count + table_offsets_write_count );
}

/* Write a data section to file
 */
int64_t libewf_section_data_write( LIBEWF_HANDLE *handle, int file_descriptor, uint64_t start_offset )
{
	EWF_DATA *data;
	int64_t section_write_count;
	int64_t data_write_count;
	size_t size = EWF_DATA_SIZE;

	if( handle == NULL )
	{
		LIBEWF_FATAL_PRINT( "libewf_section_data_write: incorrect handle.\n" );
	}
	data = ewf_data_alloc();

	revert_32bit( handle->chunk_count, data->chunk_count );
	revert_32bit( handle->sectors_per_chunk, data->sectors_per_chunk );
	revert_32bit( handle->bytes_per_sector, data->bytes_per_sector );
	revert_32bit( handle->sector_count, data->sector_count );

	if( handle->format == LIBEWF_FORMAT_ENCASE5 )
	{
		data->compression_level = handle->compression_level;
	}
	section_write_count = libewf_section_write( handle, file_descriptor, "data", size, start_offset );
	data_write_count    = ewf_data_write( data, file_descriptor );

	ewf_data_free( data );

	if( data_write_count == -1 )
	{
		LIBEWF_FATAL_PRINT( "libewf_section_data_write: unable to write data to file.\n" );
	}
	return( section_write_count + data_write_count );
}

/* Write a error2 section to file
 */
int64_t libewf_section_error2_write( LIBEWF_HANDLE *handle, int file_descriptor, uint64_t start_offset, EWF_ERROR2_SECTOR *sectors, uint32_t sectors_amount )
{
	EWF_ERROR2 *error2                 = NULL;
	int64_t section_write_count        = 0;
	int64_t error2_write_count         = 0;
	int64_t error2_sectors_write_count = 0;
	size_t size                        = EWF_ERROR2_SIZE + ( EWF_ERROR2_SECTOR_SIZE * sectors_amount ) + EWF_CRC_SIZE;

	if( handle == NULL )
	{
		LIBEWF_FATAL_PRINT( "libewf_section_error2_write: incorrect handle.\n" );
	}
	error2 = ewf_error2_alloc();

	revert_32bit( sectors_amount, error2->error_count );

	section_write_count        = libewf_section_write( handle, file_descriptor, "error2", size, start_offset );
	error2_write_count         = ewf_error2_write( error2, file_descriptor );
	error2_sectors_write_count = ewf_error2_sectors_write( sectors, file_descriptor, sectors_amount );

	ewf_error2_free( error2 );

	if( error2_write_count == -1 )
	{
		LIBEWF_FATAL_PRINT( "libewf_section_error2_write: unable to write error2 to file.\n" );
	}
	if( error2_sectors_write_count == -1 )
	{
		LIBEWF_FATAL_PRINT( "libewf_section_error2_write: unable to write error2 sectors to file.\n" );
	}
	return( section_write_count + error2_write_count + error2_sectors_write_count );
}

/* Write a hash section to file
 */
int64_t libewf_section_hash_write( LIBEWF_HANDLE *handle, int file_descriptor, uint64_t start_offset, EWF_MD5HASH *md5hash )
{
	EWF_HASH *hash;
	int64_t section_write_count;
	int64_t hash_write_count;
	size_t size = EWF_HASH_SIZE;

	if( handle == NULL )
	{
		LIBEWF_FATAL_PRINT( "libewf_section_hash_write: incorrect handle.\n" );
	}
	hash = ewf_hash_alloc();

	memcpy( (uint8_t *) hash->md5hash, (uint8_t *) md5hash, EWF_MD5HASH_SIZE );

	section_write_count = libewf_section_write( handle, file_descriptor, "hash", size, start_offset );
	hash_write_count    = ewf_hash_write( hash, file_descriptor );

	ewf_hash_free( hash );

	if( hash_write_count == -1 )
	{
		LIBEWF_FATAL_PRINT( "libewf_section_hash_write: unable to write hash to file.\n" );
	}
	return( section_write_count + hash_write_count );
}

/* Create the headers
 */
void libewf_headers_create( LIBEWF_HANDLE *handle, LIBEWF_HEADER_VALUES *header_values )
{
	time_t timestamp = time( NULL );

	if( handle == NULL )
	{
		LIBEWF_FATAL_PRINT( "libewf_headers_create: incorrect handle.\n" );
	}
	if( ( handle->format == LIBEWF_FORMAT_ENCASE1 ) || ( handle->format == LIBEWF_FORMAT_ENCASE2 ) || ( handle->format == LIBEWF_FORMAT_ENCASE3 ) )
	{
		handle->header = libewf_header_values_generate_header_string_encase3( header_values, timestamp, handle->compression_level );
	}
	else if( handle->format == LIBEWF_FORMAT_FTK )
	{
		handle->header = libewf_header_values_generate_header_string_ftk( header_values, timestamp, handle->compression_level );
	}
	else if( handle->format == LIBEWF_FORMAT_ENCASE4 )
	{
		handle->header  = libewf_header_values_generate_header_string_encase4( header_values, timestamp );
		handle->header2 = libewf_header_values_generate_header2_string_encase4( header_values, timestamp );
	}
	else if( handle->format == LIBEWF_FORMAT_ENCASE5 )
	{
		handle->header  = libewf_header_values_generate_header_string_encase4( header_values, timestamp );
		handle->header2 = libewf_header_values_generate_header2_string_encase5( header_values, timestamp );
	}
}

/* Write the headers to file
 */
int64_t libewf_headers_write( LIBEWF_HANDLE *handle, int file_descriptor, uint64_t start_offset )
{
	uint32_t header_size;
	uint32_t header2_size;
	uint64_t segment_file_offset = start_offset;
	int64_t write_count          = 0;
	int64_t total_count          = 0;

	if( handle == NULL )
	{
		LIBEWF_FATAL_PRINT( "libewf_headers_write: incorrect handle.\n" );
	}
	if( handle->header == NULL )
	{
		LIBEWF_FATAL_PRINT( "libewf_headers_write: incorrect header.\n" );
	}
	header_size = strlen( (char *) handle->header );

	if( ( handle->format == LIBEWF_FORMAT_ENCASE1 ) || ( handle->format == LIBEWF_FORMAT_ENCASE2 ) || ( handle->format == LIBEWF_FORMAT_ENCASE3 ) || ( handle->format == LIBEWF_FORMAT_FTK ) )
	{
		/* The header should be written twice
		 */
		write_count          = libewf_section_header_write( handle, file_descriptor, segment_file_offset, handle->header, header_size );
		segment_file_offset += write_count;
		total_count         += write_count;

		write_count          = libewf_section_header_write( handle, file_descriptor, segment_file_offset, handle->header, header_size );
		segment_file_offset += write_count;
		total_count         += write_count;
	}
	else if( ( handle->format == LIBEWF_FORMAT_ENCASE4 ) || ( handle->format == LIBEWF_FORMAT_ENCASE5 ) )
	{
		if( handle->header2 == NULL )
		{
			LIBEWF_FATAL_PRINT( "libewf_headers_write: incorrect header2.\n" );
		}
		header2_size = strlen( (char *) handle->header2 );

		/* The header2 should be written twice
		 */
		write_count          = libewf_section_header2_write( handle, file_descriptor, segment_file_offset, handle->header2, header2_size );
		segment_file_offset += write_count;
		total_count         += write_count;

		write_count          = libewf_section_header2_write( handle, file_descriptor, segment_file_offset, handle->header2, header2_size );
		segment_file_offset += write_count;
		total_count         += write_count;

		/* The header should be written once
		 */
		write_count          = libewf_section_header_write( handle, file_descriptor, segment_file_offset, handle->header, header_size );
		segment_file_offset += write_count;
		total_count         += write_count;
	}
	return( total_count );
}

/* Sets file writing parametes
 */
LIBEWF_HANDLE *libewf_set_write_parameters( LIBEWF_HANDLE *handle, uint64_t input_file_size, uint32_t sectors_per_chunk, uint32_t bytes_per_sector, uint32_t error_granularity_sectors, uint64_t ewf_file_size, int8_t compression_level, uint8_t format, LIBEWF_HEADER_VALUES *header_values )
{
	if( handle == NULL )
	{
		LIBEWF_FATAL_PRINT( "libewf_set_write_parameters: incorrect handle.\n" );
	}
	if( input_file_size <= 0 )
	{
		LIBEWF_FATAL_PRINT( "libewf_set_write_parameters: invalid value for parameter: input_file_size.\n" );
	}
	if( sectors_per_chunk <= 0 )
	{
		LIBEWF_FATAL_PRINT( "libewf_set_write_parameters: invalid value for parameter: sectors_per_chunk.\n" );
	}
	if( bytes_per_sector <= 0 )
	{
		LIBEWF_FATAL_PRINT( "libewf_set_write_parameters: invalid value for parameter: bytes_per_sector.\n" );
	}
	if( error_granularity_sectors <= 0 )
	{
		LIBEWF_FATAL_PRINT( "libewf_set_write_parameters: invalid value for parameter: error_granularity_sectors.\n" );
	}
	if( ewf_file_size <= 0 )
	{
		LIBEWF_FATAL_PRINT( "libewf_set_write_parameters: invalid value for parameter: ewf_file_size.\n" );
	}
	if( header_values == NULL )
	{
		LIBEWF_FATAL_PRINT( "libewf_set_write_parameters: invalid value for parameter: header_values.\n" );
	}
	handle->input_file_size           = input_file_size;
	handle->sectors_per_chunk         = sectors_per_chunk;
	handle->bytes_per_sector          = bytes_per_sector;
	handle->error_granularity_sectors = error_granularity_sectors;
	handle->ewf_file_size             = ewf_file_size;
	handle->compression_level         = compression_level;
	handle->format                    = format;
	handle->chunk_size                = sectors_per_chunk * bytes_per_sector;
	handle->chunks_per_file           = ( ewf_file_size - EWF_FILE_HEADER_SIZE - EWF_DATA_SIZE ) / handle->chunk_size;

	handle->chunk_count = handle->input_file_size / handle->chunk_size;

	if ( handle->input_file_size % handle->chunk_size != 0 )
	{
		handle->chunk_count += 1;
	}
	handle->sector_count = handle->input_file_size / handle->bytes_per_sector;

	libewf_headers_create( handle, header_values );

	LIBEWF_VERBOSE_PRINT( "libewf_set_write_parameters: input file size: %" PRIu32 ".\n", handle->input_file_size );
	LIBEWF_VERBOSE_PRINT( "libewf_set_write_parameters: requested ewf segment file size: %" PRIu64 ".\n", handle->ewf_file_size );

	return( handle );
}

/* Writes data in EWF format from a file descriptor
 */
int64_t libewf_write_from_file_descriptor( LIBEWF_HANDLE *handle, int input_file_descriptor, void (*callback)( uint64_t bytes_read, uint64_t bytes_total ) )
{
	uint16_t filename_size;
	char *filename;
	char *calculated_md5hash_string;
	EWF_FILE_HEADER *file_header;
	EWF_TABLE_OFFSET *offsets;
	EWF_MD5HASH *calculated_md5hash;
	LIBEWF_MD5_CTX md5;

	int64_t total_write_count             = 0;
	int64_t total_read_count              = 0;
	int64_t read_count                    = 0;
	int64_t write_count                   = 0;
	int64_t sectors_read_count            = 0;
	int64_t sectors_write_count           = 0;
	int64_t read_error_count              = 0;
	uint64_t segment_file_offset          = 0;
	uint64_t read_error_offset            = 0;
	uint64_t write_size                   = 0;
	uint64_t sectors_section_offset       = 0;
	uint64_t sectors_size                 = 0;
	int32_t total_read_error_count        = 0;
	uint32_t compressed_data_size         = 0;
	uint32_t maximum_compressed_data_size = 0;
	uint32_t chunk_write_count            = 0;
	uint32_t segment                      = 1;
	uint32_t chunk                        = 0;
	uint32_t bytes_to_read                = 0;
	uint32_t error_granularity_bytes      = handle->error_granularity_sectors * handle->bytes_per_sector;
	uint32_t error_granularity_offset     = 0;
	uint32_t error_remaining_bytes        = 0;
	uint32_t read_remaining_bytes         = 0;
	uint32_t error_skip_bytes             = 0;
	uint32_t sectors_chunk_amount         = 0;
	uint32_t remaining_chunk_amount       = 0;
	uint32_t error2_sector                = 0;
	uint32_t error2_sector_count          = 0;
	EWF_CRC crc                           = 0;

	if( handle->chunk_size <= 0 )
	{
		LIBEWF_FATAL_PRINT( "libewf_write_from_file_descriptor: invalid chunk size.\n" );
	}
	filename_size = strlen( handle->segment_table->filename[ 0 ] );
	filename      = (char *) malloc( sizeof( char ) * ( filename_size + 5 ) );

	if( filename == NULL )
	{
		LIBEWF_FATAL_PRINT( "libewf_write_from_file_descriptor: unable to allocate filename.\n" );
	}
	file_header = ewf_file_header_alloc();

	/* Make sure the compressed data size buffer is large enough
	 * zlib compression can enlarge the data
	 * about 1024 bytes should be enough
	 */
	maximum_compressed_data_size = handle->chunk_size + 1024;

	handle = libewf_handle_cache_realloc( handle, maximum_compressed_data_size );

	LIBEWF_MD5_INIT( &md5 );

	while( total_read_count < handle->input_file_size )
	{
		snprintf( filename, ( filename_size + 5 ), "%s.e%.2" PRIx32, handle->segment_table->filename[ 0 ], segment );

		/* Make sure the string is terminated
		 */
		filename[ filename_size + 4 ] = '\0';

		if( handle->segment_table->amount <= segment )
		{
			/* One additional entry in the segment table is needed,
			 * because the 0 entry is used to store the base filename
			 */
			handle->segment_table = libewf_segment_table_values_realloc( handle->segment_table, ( segment + 1 ) );
		}
		handle->segment_table = libewf_segment_table_set_values( handle->segment_table, segment, filename, -1 );

		LIBEWF_VERBOSE_PRINT( "\nlibewf_write_from_file_descriptor: segment file to write: %" PRIu32 " with name: %s\n", segment, filename );

		if( segment != 1 )
		{
			write_count        = libewf_last_section_write( handle, handle->segment_table->file_descriptor[ segment - 1 ], "next", segment_file_offset );
			total_write_count += write_count;

			close( handle->segment_table->file_descriptor[ segment - 1 ] );
		}
		handle->segment_table->file_descriptor[ segment ] = open( handle->segment_table->filename[ segment ], O_WRONLY | O_CREAT | O_TRUNC, 0644 );

		revert_16bit( segment, file_header->fields_segment );

		segment_file_offset = 0;
		write_count         = ewf_file_header_write( file_header, handle->segment_table->file_descriptor[ segment ] );

		if( write_count == 0 )
		{
			LIBEWF_FATAL_PRINT( "libewf_write_from_file_descriptor: unable to write file header to file.\n" );
		}
		segment_file_offset += write_count;
		total_write_count   += write_count;

		if( segment == 1 )
		{
			write_count          = libewf_headers_write( handle, handle->segment_table->file_descriptor[ segment ], segment_file_offset );
			segment_file_offset += write_count;
			total_write_count   += write_count;

			write_count          = libewf_section_volume_write( handle, handle->segment_table->file_descriptor[ segment ], segment_file_offset );
			segment_file_offset += write_count;
			total_write_count   += write_count;
		}
		else
		{
			write_count          = libewf_section_data_write( handle, handle->segment_table->file_descriptor[ segment ], segment_file_offset );
			segment_file_offset += write_count;
			total_write_count   += write_count;
		}
		sectors_size  = handle->ewf_file_size;
		sectors_size -= segment_file_offset;

		/* Leave space for at least the sectors, table and table 2 and next or done sections
		 */
		sectors_size -= ( 4 * EWF_SECTION_SIZE ) + ( 2 * handle->chunks_per_file * sizeof( EWF_TABLE_OFFSET ) );

		/* Determine how many chunks will fit in the remaining space
		 */
		sectors_chunk_amount   = sectors_size / ( handle->chunk_size + EWF_CRC_SIZE );
		remaining_chunk_amount = handle->chunk_count - chunk_write_count;

		LIBEWF_VERBOSE_PRINT( "libewf_write_from_file_descriptor: calculated amount of chunks: %d\n", sectors_chunk_amount );

		if( remaining_chunk_amount < handle->chunks_per_file )
		{
			sectors_chunk_amount = remaining_chunk_amount;
		}
		sectors_size = sectors_chunk_amount * ( handle->chunk_size + EWF_CRC_SIZE );

		offsets                = ewf_table_offsets_alloc( sectors_chunk_amount );
		sectors_section_offset = segment_file_offset;

		write_count          = libewf_section_write( handle, handle->segment_table->file_descriptor[ segment ], "sectors", sectors_size, segment_file_offset );
		segment_file_offset += write_count;
		total_write_count   += write_count;

		LIBEWF_VERBOSE_PRINT( "libewf_write_from_file_descriptor: calculated sectors size: %" PRIu64 ".\n", sectors_size );

		sectors_read_count  = 0;
		sectors_write_count = 0;
		chunk               = 0;

		for( chunk = 0; chunk < sectors_chunk_amount; chunk++ )
		{
			/* Make sure there is no data contamination whatsoever
			 */
			handle = libewf_handle_cache_wipe( handle, handle->chunk_size );

			LIBEWF_VERBOSE_PRINT( "libewf_write_from_file_descriptor: reading chunk: %d with size: %" PRIu32 "\n", chunk, handle->chunk_size );

			bytes_to_read     = handle->chunk_size;
			read_error_offset = 0;
			read_error_count  = 0;

			while( 1 )
			{
				read_count = read( input_file_descriptor, &handle->raw_data[ read_error_offset ], bytes_to_read );

				LIBEWF_VERBOSE_PRINT( "libewf_write_from_file_descriptor: read chunk: %d with size: %" PRIi64 "\n", chunk, read_count );

				/* The last read is OK, correct read_count */
				if( read_count == bytes_to_read )
				{
					read_count = read_error_offset + bytes_to_read;
				}
				/* The entire read is OK */
				if( read_count == handle->chunk_size )
				{
					break;
				}
				/* At the end of the input */
				if( ( total_read_count + read_count ) == handle->input_file_size )
				{
					break;
				}
				/* No bytes were read */
				if( read_count == 0 )
				{
					LIBEWF_FATAL_PRINT( "libewf_write_from_file_descriptor: error reading data: unexpected end of data bytes read: %" PRIu64 " total bytes to read: %" PRIu64 ".\n", total_read_count, handle->input_file_size );
				}
				if( errno == ESPIPE )
				{
					LIBEWF_FATAL_PRINT( "libewf_write_from_file_descriptor: error reading data: Invalid seek\n" );
				}
				else if( errno == EPERM )
				{
					LIBEWF_FATAL_PRINT( "libewf_write_from_file_descriptor: error reading data: Operation not permitted\n" );
				}
				else if( errno == ENXIO )
				{
					LIBEWF_FATAL_PRINT( "libewf_write_from_file_descriptor: error reading data: No such device or address\n" );
				}
				else if( errno == ENODEV )
				{
					LIBEWF_FATAL_PRINT( "libewf_write_from_file_descriptor: error reading data: No such device\n" );
				}
				/* There was a read error at a certain offset
				 */
				if( read_count > 0 )
				{
					read_error_offset += read_count;
				}
				LIBEWF_VERBOSE_PRINT( "libewf_write_from_file_descriptor: read error: %d at offset %" PRIu64 "\n", errno, ( total_read_count + read_error_offset ) );

				if( read_error_count >= 3 )
				{
					total_read_error_count++;

					if( handle->error2_sectors == NULL )
					{
						 handle->error2_sectors = ewf_error2_sectors_alloc( total_read_error_count );
					}
					else
					{
						 handle->error2_sectors = ewf_error2_sectors_realloc( handle->error2_sectors, total_read_error_count );
					}
					/* Check if last chunk is smaller than the chunk size and take corrective measures
					 */
					if( ( total_read_count + handle->chunk_size ) > handle->input_file_size )
					{
						read_remaining_bytes = handle->input_file_size - total_read_count;
					}
					else
					{
						read_remaining_bytes = handle->chunk_size;
					}
					error_remaining_bytes    = read_remaining_bytes - read_error_offset;
					error2_sector            = total_read_count;
					error_granularity_offset = ( read_error_offset / error_granularity_bytes ) * error_granularity_bytes;
					error_skip_bytes         = ( error_granularity_offset + error_granularity_bytes ) - read_error_offset;

					if( handle->alternative_write_method == 0 )
					{
						LIBEWF_VERBOSE_PRINT( "libewf_write_from_file_descriptor: wiping block of %" PRIu32 " bytes at offset %" PRIu32 ".\n", error_granularity_bytes, error_granularity_offset );

						memset( &handle->raw_data[ error_granularity_offset ], 0, error_granularity_bytes );

						error2_sector      += error_granularity_offset;
						error2_sector_count = error_granularity_bytes;
					}
					else
					{
						error2_sector      += read_error_offset;
						error2_sector_count = error_skip_bytes;
					}
					error2_sector       /= handle->bytes_per_sector;
					error2_sector_count /= handle->bytes_per_sector;

					LIBEWF_VERBOSE_PRINT( "libewf_write_from_file_descriptor: adding error2: %" PRIi32 " sector: %" PRIu32 ", count: %" PRIu32 "\n", total_read_error_count, error2_sector, error2_sector_count );
					revert_32bit( error2_sector, handle->error2_sectors[ total_read_error_count - 1 ].sector );
					revert_32bit( error2_sector_count, handle->error2_sectors[ total_read_error_count - 1 ].sector_count );

					LIBEWF_VERBOSE_PRINT( "libewf_write_from_file_descriptor: skipping %" PRIu32 " bytes.\n", error_skip_bytes );
					lseek( input_file_descriptor, error_skip_bytes, SEEK_CUR );

					if( error_remaining_bytes > error_granularity_bytes )
					{
						bytes_to_read      = error_remaining_bytes - error_skip_bytes;
						read_error_offset += error_skip_bytes;

						LIBEWF_VERBOSE_PRINT( "libewf_write_from_file_descriptor: remaining to read from chunk %" PRIu32 " bytes.\n", bytes_to_read );
					}
					else
					{
						read_count = read_remaining_bytes;

						LIBEWF_VERBOSE_PRINT( "libewf_write_from_file_descriptor: no remaining bytes to read from chunk.\n" );
						break;
					}
				}
				read_error_count++;
			}
			total_read_count += read_count;

			/* Callback for status update
			 */
			if( callback != NULL )
			{
				callback( total_read_count, handle->input_file_size );
			}
			LIBEWF_MD5_UPDATE( &md5, handle->raw_data, read_count );

			sectors_read_count  += read_count;
			write_size           = 0;
			compressed_data_size = maximum_compressed_data_size;

			if( handle->compression_level != EWF_COMPRESSION_NONE )
			{
				int result = ewf_sectors_chunk_compress( handle->chunk_data, &compressed_data_size, handle->raw_data, read_count, handle->compression_level );

				if( result != Z_OK )
				{
					LIBEWF_FATAL_PRINT( "libewf_write_from_file_descriptor: unable to compress chunk: %d\n", chunk );
				}
			}
			if( compressed_data_size < handle->chunk_size )
			{
				/* No additional CRC required, zlib creates its own CRC
				 */
				write_size  = compressed_data_size;
				write_count = ewf_sectors_chunk_write( handle->chunk_data, handle->segment_table->file_descriptor[ segment ], write_size );

				memcpy( (uint8_t *) &crc, (uint8_t *) &handle->chunk_data[ compressed_data_size - EWF_CRC_SIZE ], EWF_CRC_SIZE );

				LIBEWF_VERBOSE_PRINT( "libewf_write_from_file_descriptor: writing COMPRESSED chunk: %d at offset: %" PRIu64 " with size: %" PRIu64 ", with crc: %" PRIu32 "\n", chunk, segment_file_offset, write_size, crc );

				revert_32bit( ( segment_file_offset | EWF_OFFSET_COMPRESSED_WRITE_MASK ), offsets[ chunk ].offset );
			}
			else
			{
				write_size = read_count + EWF_CRC_SIZE;

				crc = ewf_crc( (void *) handle->raw_data, read_count, 1 );

				revert_32bit( crc, &handle->raw_data[ read_count ] );

				LIBEWF_VERBOSE_PRINT( "libewf_write_from_file_descriptor: writing UNCOMPRESSED chunk: %d at offset: %" PRIu64 " with size: %" PRIu64 ", with crc: %" PRIu32 "\n", chunk, segment_file_offset, write_size, crc );

				write_count = ewf_sectors_chunk_write( handle->raw_data, handle->segment_table->file_descriptor[ segment ], write_size );

				revert_32bit( segment_file_offset, offsets[ chunk ].offset );
			}

			if( write_count != write_size )
			{
				LIBEWF_FATAL_PRINT( "libewf_write_from_file_descriptor: unable to write data\n" );
			}
			segment_file_offset += write_count;
			total_write_count   += write_count;
			sectors_write_count += write_count;

			chunk_write_count++;
		}
		LIBEWF_VERBOSE_PRINT( "libewf_write_from_file_descriptor: written sectors size: %" PRIu64 ".\n", sectors_write_count );
		if( lseek( handle->segment_table->file_descriptor[ segment ], (off_t) sectors_section_offset, SEEK_SET ) == -1 )
		{
			LIBEWF_FATAL_PRINT( "libewf_write_from_file_descriptor: unable to find offset to correct sectors size\n" );
		}
		libewf_section_write( handle, handle->segment_table->file_descriptor[ segment ], "sectors", sectors_write_count, sectors_section_offset );
		
		LIBEWF_VERBOSE_PRINT( "libewf_write_from_file_descriptor: correcting sectors section size: %" PRIu64 " offset: %" PRIu64 "\n", sectors_write_count, sectors_section_offset );
		LIBEWF_VERBOSE_PRINT( "libewf_write_from_file_descriptor: back to end of data at offset: %" PRIu64 "\n", segment_file_offset );

		if( lseek( handle->segment_table->file_descriptor[ segment ], (off_t) segment_file_offset, SEEK_SET ) == -1 )
		{
			LIBEWF_FATAL_PRINT( "libewf_write_from_file_descriptor: unable to find offset to continue\n" );
		}
		write_count          = libewf_section_table_write( handle, handle->segment_table->file_descriptor[ segment ], segment_file_offset, offsets, sectors_chunk_amount, "table" );
		segment_file_offset += write_count;
		total_write_count   += write_count;

		write_count          = libewf_section_table_write( handle, handle->segment_table->file_descriptor[ segment ], segment_file_offset, offsets, sectors_chunk_amount, "table2" );
		segment_file_offset += write_count;
		total_write_count   += write_count;

		ewf_table_offsets_free( offsets );

		segment++;

		if( segment > 255 )
		{
			LIBEWF_FATAL_PRINT( "libewf_write_from_file_descriptor: more than 255 segment files not yet supported.\n" );
		}
	}
	free( filename );
	ewf_file_header_free( file_header );

	/* Write the data section for a single segment file
	 * the segment count will be upto 2
	 */
	if( segment == 2 )
	{
		write_count          = libewf_section_data_write( handle, handle->segment_table->file_descriptor[ segment - 1 ], segment_file_offset );
		segment_file_offset += write_count;
		total_write_count   += write_count;
	}
	/* Write the error2 section if required (for Encase 5 format only)
	 */
	if( ( total_read_error_count > 0 ) && ( ( handle->format == LIBEWF_FORMAT_ENCASE3 ) || ( handle->format == LIBEWF_FORMAT_ENCASE4 ) || ( handle->format == LIBEWF_FORMAT_ENCASE5 ) ) )
	{
		write_count          = libewf_section_error2_write( handle, handle->segment_table->file_descriptor[ segment - 1 ], segment_file_offset, handle->error2_sectors, total_read_error_count );
		segment_file_offset += write_count;
		total_write_count   += write_count;
	}
	calculated_md5hash = ewf_md5hash_alloc();

  	LIBEWF_MD5_FINAL( calculated_md5hash, &md5 );

	write_count          = libewf_section_hash_write( handle, handle->segment_table->file_descriptor[ segment - 1 ], segment_file_offset, calculated_md5hash );
	segment_file_offset += write_count;
	total_write_count   += write_count;

	calculated_md5hash_string = ewf_md5hash_to_string( calculated_md5hash );

	LIBEWF_VERBOSE_PRINT( "libewf_write_from_file_descriptor: MD5 calculated: %s\n", calculated_md5hash_string );

	ewf_md5hash_free( calculated_md5hash );

	free( calculated_md5hash_string );

	write_count          = libewf_last_section_write( handle, handle->segment_table->file_descriptor[ segment - 1 ], "done", segment_file_offset );
	segment_file_offset += write_count;
	total_write_count   += write_count;

	close( handle->segment_table->file_descriptor[ segment - 1 ] );

	return( total_write_count );
}

