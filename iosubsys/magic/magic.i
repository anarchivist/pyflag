%module magic
%apply (char *STRING, int LENGTH) { (const void *buffer, size_t length) };
%{
  #include <magic.h>
%}

magic_t   magic_open(int flags);
void   magic_close(magic_t cookie);
const char *magic_buffer(magic_t cookie, const void *buffer, size_t length);
int  magic_load(magic_t cookie, const char *filename);

#define MAGIC_NONE              0x000   /* No flags */
#define MAGIC_DEBUG             0x001   /* Turn on debugging */
#define MAGIC_SYMLINK           0x002   /* Follow symlinks */
#define MAGIC_COMPRESS          0x004   /* Check inside compressed files */
#define MAGIC_DEVICES           0x008   /* Look at the contents of devices */
#define MAGIC_MIME              0x010   /* Return a mime string */
#define MAGIC_CONTINUE          0x020   /* Return all matches */
#define MAGIC_CHECK             0x040   /* Print warnings to stderr */
#define MAGIC_PRESERVE_ATIME    0x080   /* Restore access time on exit */
#define MAGIC_RAW               0x100   /* Don't translate unprintable chars */
#define MAGIC_ERROR             0x200   /* Handle ENOENT etc as real errors */
