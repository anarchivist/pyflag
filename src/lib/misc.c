#include "misc.h"
#include "talloc.h"
#include <time.h>
#include <stdarg.h>
#include <string.h>
#include "stringio.h"

char *format_alloc(int x, ...) {
  char *format;
  int i, c;
  int count = 0;
  va_list ap;
  
  va_start(ap, x);
  do {
    c = va_arg(ap, int);
    count++;
  } while(c);
  va_end(ap);
  
  format = (char *) talloc_size(NULL, count);
  
  va_start(ap, x);
  for(i=0; i<count; i++) {
    format[i] = va_arg(ap, int);
  }
  va_end(ap);
  return format;
}
