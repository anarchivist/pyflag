#include <stdlib.h>

/***********************************************************
 * Linked list for IO subsystem options
 **************************************************/
struct IO_OPT {
  char *option;
  char *value;
  struct IO_OPT *next;
};

typedef struct IO_OPT IO_OPT;

/**********************************************
 * Generic IO Subsystem objects.
 *
 * This is the base class for all IO subsystems.
 **********************************************/
struct IO_INFO {
  /* The name of the subsystem */
  char *name;
  /* Its description */
  char *description;
  /* Total size of the derived class. The one with the above name and description. Note that if the class is extended its size may be longer than sizeof(IO_INFO) */
  int size;
  /* A constructor, this creates a new instance of the object based on the class */
  struct IO_INFO *(*constructor)(struct IO_INFO *class);
  /* Destructor: Responsible for cleaning up and returning memory */
  void (*destructor)(void *self);
  /* A help function describing all parameters to this subsystem */
  void (*help)(void);
  /* The function used to parse out options and initialise the subsystem */
  int (*initialise)(struct IO_INFO *self,IO_OPT *arg);
  /* The random read function */
  int (*read_random)(struct IO_INFO *self, char *buf, int len, off_t offs,
		               const char *comment);
  /* A function used to open the file (may not be needed?) */
  int (*open)(struct IO_INFO *self);
  /* close file function: (may go in the destructor?) */
  int (*close)(struct IO_INFO *self);
  /* indicates if the open method needs to be called. Generally the read_* methods will check this and if its not set, they will call the open functions */
  int ready;
  /* Current seek position */
  off_t fpos;
};

typedef struct IO_INFO IO_INFO;

/* Prototypes for displatcher functions */
IO_INFO *io_open(char *name);
void io_parse_options(IO_INFO *io,char *opts) ;
int io_close(IO_INFO *self);
void io_help(char *name) ;

#define CHECK_OPTION(i,x) !strncasecmp(i->option, #x, strlen(#x))
#define NEW(x) (x *)malloc(sizeof(x))

/* Parses the string for a number. Can interpret the following suffixed:

  k - means 1024 bytes
  M - Means 1024*1024 bytes
  S - Menas 512 bytes (sector size)
*/
long long unsigned int parse_offsets(char *string);
