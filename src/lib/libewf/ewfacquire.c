/*
 * ewfacquire
 * Reads data from a file and writes it in EWF format
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
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef LINUX
#include <linux/fs.h>
#endif

#ifdef CYGWIN
#include <cygwin/fs.h>
#endif

#ifdef BSD
#include <sys/ioctl.h>
#include <sys/disk.h>
#include <sys/disklabel.h>
#endif

#ifdef DARWIN
#include <sys/ioctl.h>
#include <sys/disk.h>
#endif

#include "libewf.h"

/* Prints the executable usage information
 */
void usage( void )
{
	fprintf( stderr, "Usage: ewfacquire [ -hqvV ] source\n" );

	fprintf( stderr, "\tsource: the source file or device\n" );

	fprintf( stderr, "\t-h:     shows this help\n" );
	fprintf( stderr, "\t-q:     quiet shows no status information\n" );
	fprintf( stderr, "\t-v:     verbose output to stderr\n" );
	fprintf( stderr, "\t-V:     print version\n" );

	exit( EXIT_FAILURE );
}

/* Prints the executable version information
 */
void version( void )
{
	fprintf( stderr, "ewfacquire version: %s\n", LIBEWF_VERSION );

	exit( EXIT_SUCCESS );
}

/* Get variable input from the user
 * with a maximum of 1023 characters
 */
char *get_user_input_variable( char *request_string )
{
	char user_input_buffer[ 1024 ];

	char *user_input_buffer_ptr = &user_input_buffer[ 0 ];
	char *user_input            = NULL;
	char *end_of_input          = NULL;
	uint32_t input_length       = 0;
	uint32_t string_iterator    = 0;
	uint8_t string_valid        = 1;

	if( request_string == NULL )
	{
		return( NULL );
	}
	while( 1 )
	{
		fprintf( stdout, "%s: ", request_string );

		user_input_buffer_ptr = fgets( user_input_buffer_ptr, 1023, stdin );

		if( user_input_buffer_ptr != NULL )
		{
			end_of_input = memchr( user_input_buffer_ptr, '\n', 1024 );

			if( end_of_input == NULL )
			{
				return( NULL );
			}
			input_length = end_of_input - user_input_buffer_ptr;

			if( input_length <= 0 )
			{
				return( NULL );
			}
			for( string_iterator = 0; string_iterator < input_length; string_iterator++ )
			{
				if( user_input_buffer[ string_iterator ] < 0x20 )
				{
					fprintf( stdout, "Invalid character in input, please try again or terminate using Ctrl^C.\n" );

					string_valid = 0;
				}
				else if( user_input_buffer[ string_iterator ] >= 0x7f )
				{
					fprintf( stdout, "Invalid character in input, please try again or terminate using Ctrl^C.\n" );

					string_valid = 0;
				}
			}
			if( string_valid == 1 )
			{
				user_input = malloc( sizeof( char ) * ( input_length + 1 ) );

				if( user_input == NULL )
				{
					fprintf( stdout, "Unable to allocate memory for string.\n" );

					exit( EXIT_FAILURE );
				}
				memcpy( user_input, user_input_buffer_ptr, input_length );

				user_input[ input_length ] = '\0';

				break;
			}
		}
		else
		{
			fprintf( stdout, "Error reading input, please try again or terminate using Ctrl^C.\n" );
		}
	}
	return( user_input );
}

/* Get variable containing a size definnition input from the user
 * with a maximum of 1023 characters
 */
uint32_t get_user_input_size_variable( char *request_string, uint32_t minimum, uint32_t maximum, uint32_t default_value )
{
	char user_input_buffer[ 1024 ];

	char *user_input_buffer_ptr = &user_input_buffer[ 0 ];
	char *last_character        = NULL;
	uint32_t input_length       = 0;
	uint32_t size_value         = 0;

	if( request_string == NULL )
	{
		return( 0 );
	}
	while( 1 )
	{
		fprintf( stdout, "%s (%" PRIu32 " >= value >= %" PRIu32 ") [%" PRIu32 "]: ", request_string, minimum, maximum, default_value );

		user_input_buffer_ptr = fgets( user_input_buffer_ptr, 1023, stdin );

		if( user_input_buffer_ptr != NULL )
		{
			/* Remove the trailing newline character
			 */
			input_length = strlen( user_input_buffer_ptr ) - 1;

			if( input_length <= 0 )
			{
				return( default_value );
			}
			last_character = &user_input_buffer_ptr[ input_length ];
			size_value     = strtoul( user_input_buffer_ptr, &last_character, 0 );

			if( ( size_value >= minimum ) && ( size_value <= maximum ) )
			{
				break;
			}
			else
			{
				fprintf( stdout, "Value not within specified range, please try again or terminate using Ctrl^C.\n" );
			}
		}
		else
		{
			fprintf( stdout, "Error reading input, please try again or terminate using Ctrl^C.\n" );
		}
	}
	return( size_value );
}

/* Get fixed value input from the user
 * The first value is considered the default value
 */
char *get_user_input_fixed_value( char *request_string, char **values, uint8_t amount )
{
	char user_input_buffer[ 1024 ];

	char *user_input_buffer_ptr = &user_input_buffer[ 0 ];

	uint32_t input_length = 0;
	uint8_t iterator      = 0;
	uint8_t value_match   = 0;
	uint8_t value_size    = 0;
	char *user_input      = NULL;

	if( request_string == NULL )
	{
		return( NULL );
	}
	while( 1 )
	{
		fprintf( stdout, "%s", request_string );

		iterator = 0;

		while( iterator < amount )
		{
			if( iterator == 0 )
			{
				fprintf( stdout, " [%s] (%s", values[ iterator ], values[ iterator ] );
			}
			else
			{
				fprintf( stdout, ", %s", values[ iterator ] );
			}
			iterator++;
		}
		fprintf( stdout, "): " );

		user_input_buffer_ptr = fgets( user_input_buffer_ptr, 1023, stdin );

		if( user_input_buffer_ptr != NULL )
		{
			iterator = 0;

			/* Remove the trailing newline character
			 */
			input_length = strlen( user_input_buffer_ptr ) - 1;

			/* Check if the default value was selected
			 */
			if( input_length == 0 )
			{
				input_length = strlen( values[ iterator ] );
				value_match  = 1;
			}
			else
			{
				while( iterator < amount )
				{
					value_size = strlen( values[ iterator ] );

					if( strncmp( user_input_buffer_ptr, values[ iterator ], value_size ) == 0 )
					{
						/* Make sure no trailing characters were given
						 */
						if( user_input_buffer_ptr[ value_size ] == '\n' )
						{
							value_match = 1;

							break;
						}
					}
					iterator++;
				}
			}
		}
		else
		{
			fprintf( stdout, "Error reading input, please try again or terminate using Ctrl^C.\n" );
		}
		if( value_match == 1 )
		{
			value_size = strlen( values[ iterator ] );

			user_input = malloc( sizeof( char ) * ( value_size + 1 ) );

			if( user_input == NULL )
			{
				fprintf( stdout, "Unable to allocate memory for string.\n" );

				exit( EXIT_FAILURE );
			}
			memcpy( user_input, values[ iterator ], input_length );

			break;
		}
		else
		{
			fprintf( stdout, "Selected option not supported, please try again or terminate using Ctrl^C.\n" );
		}
	}
	return( user_input );
}

/* Print the status of the acquire process
 */
int8_t last_percentage = -1;

void print_percentage_callback( uint64_t bytes_read, uint64_t bytes_total )
{
	int8_t new_percentage = ( bytes_total > 0 ) ? ( ( bytes_read * 100 ) / bytes_total ) : 1;

	if( new_percentage > last_percentage )
	{
		last_percentage = new_percentage;

		fprintf( stderr, "Status: bytes read: %" PRIu64 "\tof total: %" PRIu64 " (%" PRIi8 "%%).\n", bytes_read, bytes_total, last_percentage );
	}
}

/* The main program
 */
int main( int argc, const char **argv )
{
	struct stat input_file_stat;
	struct utsname utsname_buffer;
	char *filenames[ 1 ];

	LIBEWF_HANDLE *handle               = NULL;
	LIBEWF_HEADER_VALUES *header_values = NULL;
	char *user_input                    = NULL;
	char *filename                      = NULL;
	void *callback                      = &print_percentage_callback;

	int file_descriptor                 = 0;
	int option                          = 0;
	int64_t count                       = 0;
	uint64_t size_input_file            = 0;
	uint64_t ewf_file_size              = 0;
	uint64_t sectors_per_block          = 0;
	uint64_t error_granularity          = 0;
	int8_t compression_level            = EWF_COMPRESSION_NONE;
	uint8_t ewf_format                  = LIBEWF_FORMAT_UNKNOWN;
	char *compression_types[ 3 ]        = { "none", "fast", "best" };
	char *format_types[ 6 ]             = { "ftk", "encase1", "encase2", "encase3", "encase4", "encase5" };
	char *sector_per_block_sizes[ 7 ]   = { "64", "128", "256", "512", "1024", "2048", "4096" };

	while( ( option = getopt( argc, (char **) argv, "hqvV" ) ) > 0 )
	{
		switch( option )
		{
			case '?':
			default:
				fprintf( stderr, "Invalid argument: %s\n", argv[ optind ] );
				usage();

			case 'h':
				usage();

			case 'q':
				callback = NULL;
				break;

			case 'v':
				libewf_verbose = 1;
				break;

			case 'V':
				version();
		}
	}
	if( optind == argc )
	{
		fprintf( stderr, "Missing source file or device.\n" );
		usage();
	}
	/* Check if to read from stdin
	 */
	if( strncmp( argv[ optind ], "-", 1 ) == 0 )
	{
		fprintf( stderr, "Reading from stdin not supported.\n" );

		exit( EXIT_FAILURE );
	}
	/* Check the input file or device size
	 */
	file_descriptor = open( argv[ optind ], O_RDONLY );

	if( file_descriptor == -1 )
	{
		fprintf( stderr, "Error opening file: %s.\n", argv[ optind ] );

		exit( EXIT_FAILURE );
	}
	size_input_file = 0;

	if( fstat( file_descriptor, &input_file_stat ) == 0 )
	{
		size_input_file = input_file_stat.st_size;
	}
	if( size_input_file <= 0 )
	{
#ifdef BLKGETSIZE64
		ioctl( file_descriptor, BLKGETSIZE64, &size_input_file );
#else
#ifdef DIOCGMEDIASIZE
		ioctl( file_descriptor, DIOCGMEDIASIZE, &size_input_file );
#else
#ifdef DIOCGDINFO
		struct disklabel disk_label;

		if( ioctl( file_descriptor, DIOCGDINFO, &disk_label ) != -1 )
		{
			size_input_file = disk_label.d_secperunit * disk_label.d_secsize;
		}
#else
#ifdef DKIOCGETBLOCKCOUNT
		uint32_t block_size  = 0;
		uint64_t block_count = 0;

		ioctl( file_descriptor, DKIOCGETBLOCKSIZE, &block_size );
		ioctl( file_descriptor, DKIOCGETBLOCKCOUNT, &block_count );

		size_input_file = block_count * block_size;

#ifdef _LIBEWF_DEBUG_
		/* Debug code */
		fprintf( stderr, "block size: %" PRIu32 " block count: %" PRIu64 " ", block_size, block_count );
#endif

#else
		size_input_file = 0;
#endif
#endif
#endif
#endif

#ifdef _LIBEWF_DEBUG_
		/* Debug code */
		fprintf( stderr, "device size: %" PRIu64 "\n", size_input_file );
#endif
	}
	if( size_input_file <= 0 )
	{
		fprintf( stderr, "Unable to determine file or device size.\n" );

		exit( EXIT_FAILURE );
	}
	header_values = libewf_header_values_alloc();

	/* Determine acquiry system type
	 */
	if( uname( &utsname_buffer ) == -1 )
	{
		header_values->acquiry_operating_system = libewf_header_values_set_value( header_values->acquiry_operating_system, "Undetermined" );
	}
	else
	{
		header_values->acquiry_operating_system = libewf_header_values_set_value( header_values->acquiry_operating_system, utsname_buffer.sysname );
	}
	header_values->acquiry_software_version = libewf_header_values_set_value( header_values->acquiry_software_version, LIBEWF_VERSION );

	/* Both time values will be generated automatically when set to NULL
	 */
	header_values->system_date      = NULL;
	header_values->acquiry_date     = NULL;
	header_values->password         = NULL;
	header_values->compression_type = NULL;
	
	/* Request the necessary case data
	 */
	fprintf( stdout, "Information about acquiry required, please provide the necessary input\n" );

	/* Output filename
	 */
	while( filename == NULL )
	{
		filename = get_user_input_variable( "Image path and filename without extension" );

		if( filename == NULL )
		{
			fprintf( stdout, "Filename is required, please try again or terminate using Ctrl^C.\n" );
		}
	}
	/* Case number
	 */
	user_input = get_user_input_variable( "Case number" );

	if( user_input != NULL )
	{
		header_values->case_number = libewf_header_values_set_value( header_values->case_number, user_input );

		free( user_input );
	}
	/* Description
	 */
	user_input = get_user_input_variable( "Description" );

	if( user_input != NULL )
	{
		header_values->description = libewf_header_values_set_value( header_values->description, user_input );

		free( user_input );
	}
	/* Evidence number
	 */
	user_input = get_user_input_variable( "Evidence number" );

	if( user_input != NULL )
	{
		header_values->evidence_number = libewf_header_values_set_value( header_values->evidence_number, user_input );

		free( user_input );
	}
	/* Examiner name
	 */
	user_input = get_user_input_variable( "Examiner name" );

	if( user_input != NULL )
	{
		header_values->examiner_name = libewf_header_values_set_value( header_values->examiner_name, user_input );

		free( user_input );
	}
	/* Notes
	 */
	user_input = get_user_input_variable( "Notes" );

	if( user_input != NULL )
	{
		header_values->notes = libewf_header_values_set_value( header_values->notes, user_input );

		free( user_input );
	}
	/* Compression
	 */
	user_input = get_user_input_fixed_value( "Use compression", compression_types, 3 );

	if( strncmp( user_input, "none", 4 ) == 0 )
	{
		compression_level = EWF_COMPRESSION_NONE;
	}
	else if( strncmp( user_input, "fast", 4 ) == 0 )
	{
		compression_level = EWF_COMPRESSION_FAST;
	}
	else if( strncmp( user_input, "best", 4 ) == 0 )
	{
		compression_level = EWF_COMPRESSION_BEST;
	}
	else
	{
		fprintf( stderr, "ewfacquire: unsuported compression type.\n" );

		exit( EXIT_FAILURE );
	}
	free( user_input );

	/* File format
	 */
	user_input = get_user_input_fixed_value( "Use EWF file format", format_types, 6 );

	if( strncmp( user_input, "ftk", 3 ) == 0 )
	{
		ewf_format = LIBEWF_FORMAT_FTK;
	}
	else if( strncmp( user_input, "encase1", 7 ) == 0 )
	{
		ewf_format = LIBEWF_FORMAT_ENCASE1;
	}
	else if( strncmp( user_input, "encase2", 7 ) == 0 )
	{
		ewf_format = LIBEWF_FORMAT_ENCASE2;
	}
	else if( strncmp( user_input, "encase3", 7 ) == 0 )
	{
		ewf_format = LIBEWF_FORMAT_ENCASE3;
	}
	else if( strncmp( user_input, "encase4", 7 ) == 0 )
	{
		ewf_format = LIBEWF_FORMAT_ENCASE4;
	}
	else if( strncmp( user_input, "encase5", 7 ) == 0 )
	{
		ewf_format = LIBEWF_FORMAT_ENCASE5;
	}
	else
	{
		fprintf( stderr, "ewfacquire: unsuported EWF file format type.\n" );

		exit( EXIT_FAILURE );
	}
	free( user_input );

	/* File size
	 */
	ewf_file_size  = get_user_input_size_variable( "Evidence file size in kbytes (2^10)", 1440, ( 2 * 1024 * 1024 ), ( 650 * 1024 ) );
	ewf_file_size *= 1024;

	/* Chunk size (sectors per block)
	 */
	user_input = get_user_input_fixed_value( "The amount of sectors to read at once", sector_per_block_sizes, 7 );

	sectors_per_block = atoll( user_input );

	free( user_input );

	/* Error granularity
	 */
	error_granularity = get_user_input_size_variable( "The amount of sectors to be used as error granularity", 1, sectors_per_block, 64 );

	/* Add overview of data and ask to start acquiry
	 */

	/* Done asking user input
	 */
	fprintf( stdout, "\nStarting acquiry, this could take a while.\n" );

	filenames[ 0 ] = filename;

	handle = libewf_open( (const char **) filenames, 1, LIBEWF_OPEN_WRITE );
	handle = libewf_set_write_parameters( handle, size_input_file, sectors_per_block, 512, error_granularity, ewf_file_size, compression_level, ewf_format, header_values );

	/* Use EnCase alike error handling
	 */
	handle->alternative_write_method = 0;

	count = libewf_write_from_file_descriptor( handle, file_descriptor, callback );

	libewf_close( handle );

	close( file_descriptor );

	fprintf( stderr, "Success: bytes written: %" PRIi64 "\n", count );

	free( filename );

	libewf_header_values_free( header_values );

	return( 0 );
}

