/*
 * This file stores code common to the command line tools.
 * XXX: This should be converted to a proper library.
 *
 * Copyright (C) 2005-2008 Timothy D. Morgan
 * Copyright (C) 2002 Richard Sharpe, rsharpe@richardsharpe.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3 of the License.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  
 *
 * $Id: common.c 121 2008-08-09 17:22:26Z tim $
 */
#ifndef __COMMON_C
#define __COMMON_C

#include <error.h>
#include <errno.h>
#include <stdint.h>

#include <iconv.h>
#include "talloc.h"
iconv_t conv_desc;

const char* key_special_chars = ",\"\\/";
const char* subfield_special_chars = ",\"\\|";
const char* common_special_chars = ",\"\\";

#define REGLOOKUP_VERSION "0.9.0"


void bailOut(int code, char* message)
{
  fprintf(stderr, message);
  exit(code);
}


/* Returns a newly malloc()ed string which contains original buffer,
 * except for non-printable or special characters are quoted in hex
 * with the syntax '\xQQ' where QQ is the hex ascii value of the quoted
 * character.  A null terminator is added, since only ascii, not binary,
 * is returned.
 */
#if 0
static char* quote_buffer(const unsigned char* str, 
			  unsigned int len, const char* special)
{
  unsigned int i, added_len;
  unsigned int num_written = 0;

  unsigned int buf_len = sizeof(char)*(len+1);
  char* ret_val = malloc(buf_len);
  char* tmp_buf;

  if(ret_val == NULL)
    return NULL;

  for(i=0; i<len; i++)
  {
    if(buf_len <= (num_written+5))
    {
      /* Expand the buffer by the memory consumption rate seen so far 
       * times the amount of input left to process.  The expansion is bounded 
       * below by a minimum safety increase, and above by the maximum possible 
       * output string length.  This should minimize both the number of 
       * reallocs() and the amount of wasted memory.
       */
      added_len = (len-i)*num_written/(i+1);
      if((buf_len+added_len) > (len*4+1))
	buf_len = len*4+1;
      else
      {
	if (added_len < 5)
	  buf_len += 5;
	else
	  buf_len += added_len;
      }

      tmp_buf = realloc(ret_val, buf_len);
      if(tmp_buf == NULL)
      {
	talloc_free(ret_val);
	return NULL;
      }
      ret_val = tmp_buf;
    }
    
    if(str[i] < 32 || str[i] > 126 || strchr(special, str[i]) != NULL)
    {
      num_written += snprintf(ret_val + num_written, buf_len - num_written,
			      "\\x%.2X", str[i]);
    }
    else
      ret_val[num_written++] = str[i];
  }
  ret_val[num_written] = '\0';

  return ret_val;
}
#else
static char* quote_buffer(const unsigned char* str, 
			  unsigned int len, const char* special)
{
  int out_len = len+1;
  char *ret_val = talloc_array(str, char, out_len);
  int i=0,j=0;

  if(!ret_val) return NULL;
  
  while(i<len) {
    /* We need to grow the buffer a bit */
    if(j+10 > out_len) {
      out_len += 512;
      ret_val = talloc_realloc(ret_val, ret_val, char, out_len);
    };
    
    if(str[i] < 32 || str[i] > 126 || strchr(special, str[i]) != NULL) {      
      j += snprintf(ret_val + j, out_len - j,
		    "\\x%.2X", str[i]);
    } else {
      ret_val[j] = str[i];
      j++;
    };
    i++;
  };

  ret_val[j]=0;

  return ret_val;
};

#endif

/* Returns a newly malloc()ed string which contains original string, 
 * except for non-printable or special characters are quoted in hex
 * with the syntax '\xQQ' where QQ is the hex ascii value of the quoted
 * character.
 */
static char* quote_string(const char* str, const char* special)
{
  unsigned int len;

  if(str == NULL)
    return NULL;

  len = strlen(str);
  return quote_buffer((const unsigned char*)str, len, special);
}


/*
 * Convert from UTF-16LE to ASCII.  Accepts a Unicode buffer, uni, and
 * it's length, uni_max.  Writes ASCII to the buffer ascii, whose size
 * is ascii_max.  Writes at most (ascii_max-1) bytes to ascii, and null
 * terminates the string.  Returns the length of the string stored in
 * ascii.  On error, returns a negative errno code.
 */
static int uni_to_ascii(unsigned char* uni, char* ascii, 
			unsigned int uni_max, unsigned int ascii_max)
{
  char* inbuf = (char*)uni;
  char* outbuf = ascii;
  size_t in_len = (size_t)uni_max;
  size_t out_len = (size_t)(ascii_max-1);
  int ret;

  /* Set up conversion descriptor. */
  conv_desc = iconv_open("US-ASCII", "UTF-16LE");

  ret = iconv(conv_desc, &inbuf, &in_len, &outbuf, &out_len);
  if(ret == -1)
  {
    iconv_close(conv_desc);
    return -errno;
  }
  *outbuf = '\0';

  iconv_close(conv_desc);  
  return strlen(ascii);
}


/*
 * Convert a data value to a string for display.  Returns NULL on error,
 * and the string to display if there is no error, or a non-fatal
 * error.  On any error (fatal or non-fatal) occurs, (*error_msg) will
 * be set to a newly allocated string, containing an error message.  If
 * a memory allocation failure occurs while generating the error
 * message, both the return value and (*error_msg) will be NULL.  It
 * is the responsibility of the caller to free both a non-NULL return
 * value, and a non-NULL (*error_msg).
 */
static char* data_to_ascii(void *ctx, unsigned char* datap, uint32 len, uint32 type, 
			   char** error_msg)
{
  char* asciip;
  char* ascii;
  char* cur_quoted;
  char* tmp_err;
  const char* str_type;
  int ret_err;

  if(datap == NULL)
  {
    *error_msg = talloc_strdup(ctx, "Data pointer was NULL.");
    return NULL;
  }
  *error_msg = NULL;

  switch (type) 
  {
  case REG_SZ:
  case REG_EXPAND_SZ:
    /* REG_LINK is a symbolic link, stored as a unicode string. */
  case REG_LINK:
    ascii = talloc_array(datap, char, len+1);
    if(ascii == NULL)
      return NULL;
    
    /* Sometimes values have binary stored in them.  If the unicode
     * conversion fails, just quote it raw.
     */
    ret_err = uni_to_ascii(datap, ascii, len, len+1);
    if(ret_err < 0)
    {
      tmp_err = strerror(-ret_err);
      str_type = regfi_type_val2str(type);
      *error_msg = talloc_asprintf(datap, "Unicode conversion failed on %s field; "
				   "printing as binary.  Error: %s", str_type, tmp_err);
      if(*error_msg == NULL)
	return NULL;

      cur_quoted = quote_buffer(datap, len, common_special_chars);
    }
    else
      cur_quoted = quote_string(ascii, common_special_chars);

    if(cur_quoted == NULL)
      {
	*error_msg = talloc_asprintf(datap, "Buffer could not be quoted.");
      }
    return cur_quoted;
    break;

  case REG_DWORD:
    ascii = talloc_asprintf(datap, "0x%.2X%.2X%.2X%.2X", 
			    datap[3], datap[2], datap[1], datap[0]);
    return ascii;
    
  case REG_DWORD_BE:
    ascii = talloc_asprintf(datap, "0x%.2X%.2X%.2X%.2X", 
			    datap[0], datap[1], datap[2], datap[3]);
    return ascii;

  case REG_QWORD:
    ascii = talloc_asprintf(datap, "0x%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X",
			    datap[7], datap[6], datap[5], datap[4],
			    datap[3], datap[2], datap[1], datap[0]);
    return ascii;

  /* XXX: this MULTI_SZ parser is pretty inefficient.  Should be
   *      redone with fewer malloc calls and better string concatenation.
   *      Also, gives lame output when "\0\0" is the string.
   */
#if 0
  case REG_MULTI_SZ:
    ascii_max = sizeof(char)*(len*4+1);
    cur_str_max = sizeof(char)*(len+1);
    cur_str = malloc(cur_str_max);
    cur_ascii = malloc(cur_str_max);
    ascii = malloc(ascii_max);
    if(ascii == NULL || cur_str == NULL || cur_ascii == NULL)
      return NULL;

    /* Reads until it reaches 4 consecutive NULLs, 
     * which is two nulls in unicode, or until it reaches len, or until we
     * run out of buffer.  The latter should never happen, but we shouldn't
     * trust our file to have the right lengths/delimiters.
     */
    asciip = ascii;
    num_nulls = 0;
    str_rem = ascii_max;
    cur_str_rem = cur_str_max;
    cur_str_len = 0;

    for(i=0; (i < len) && str_rem > 0; i++)
    {
      *(cur_str+cur_str_len) = *(datap+i);
      if(*(cur_str+cur_str_len) == 0)
	num_nulls++;
      else
	num_nulls = 0;
      cur_str_len++;

      if(num_nulls == 2)
      {
	ret_err = uni_to_ascii(cur_str, cur_ascii, cur_str_len-1, cur_str_max);
	if(ret_err < 0)
	{
	  /* XXX: should every sub-field error be enumerated? */
	  if(*error_msg == NULL)
	  {
	    tmp_err = strerror(-ret_err);
	    *error_msg = (char*)malloc(90+strlen(tmp_err)+1);
	    if(*error_msg == NULL)
	    {
	      talloc_free(cur_str);
	      talloc_free(cur_ascii);
	      talloc_free(ascii);
	      return NULL;
	    }
	    sprintf(*error_msg, "Unicode conversion failed on at least one "
		    "MULTI_SZ sub-field; printing as binary.  Error: %s",
		    tmp_err);
	  }
	  cur_quoted = quote_buffer(cur_str, cur_str_len-1, 
				    subfield_special_chars);
	}
	else
	  cur_quoted = quote_string(cur_ascii, subfield_special_chars);

	alen = snprintf(asciip, str_rem, "%s", cur_quoted);
	asciip += alen;
	str_rem -= alen;
	talloc_free(cur_quoted);

	if(*(datap+i+1) == 0 && *(datap+i+2) == 0)
	  break;
	else
	{
	  if(str_rem > 0)
	  {
	    asciip[0] = '|';
	    asciip[1] = '\0';
	    asciip++;
	    str_rem--;
	  }
	  memset(cur_str, 0, cur_str_max);
	  cur_str_len = 0;
	  num_nulls = 0;
	  /* To eliminate leading nulls in subsequent strings. */
	  i++;
	}
      }
    }
    *asciip = 0;
    talloc_free(cur_str);
    talloc_free(cur_ascii);
    return ascii;
    break;
#endif

  /* XXX: Dont know what to do with these yet, just print as binary... */
  default:
    /* XXX: It would be really nice if this message somehow included the
     *      name of the current value we're having trouble with, since
     *      stderr/stdout don't always sync nicely.
     */
    fprintf(stderr, "WARNING: Unrecognized registry data type (0x%.8X); quoting as binary.\n", type);
    
  case REG_NONE:
  case REG_RESOURCE_LIST:
  case REG_FULL_RESOURCE_DESCRIPTOR:
  case REG_RESOURCE_REQUIREMENTS_LIST:
  case REG_MULTI_SZ:
  case REG_BINARY:
    return quote_buffer(datap, len, common_special_chars);
    break;
  }

  return NULL;
}
#endif
