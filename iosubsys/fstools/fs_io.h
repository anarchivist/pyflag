// Option linked list

/* Prototypes for displatcher functions */
IO_INFO *io_open(char *name);
void io_parse_options(IO_INFO *io,char *opts) ;
int io_close(IO_INFO *self);
void io_help(char *name) ;
