#include "libiosubsys.h"

void main() {
  IOOptions opts = CONSTRUCT(IOOptions, IOOptions, add, NULL, NULL, NULL, NULL);
  IOSource io;
  char buf[255];

  CONSTRUCT(IOOptions, IOOptions, add, opts, opts, "filename", "/etc/passwd");
  
  printf("Option filename is %s\n" , opts->get_value(opts, "filename"));

  io = CONSTRUCT(IOSource, IOSource, Con, opts, opts);
  io->read_random(io, buf, 200, 0);

  buf[200]=0;
  printf("contents %s" , buf);
};
