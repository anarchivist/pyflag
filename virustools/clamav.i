%module clamav
%include cstring.i
%cstring_output_allocate(const char **virname, NULL);
%apply (char *STRING, int LENGTH) { (const char *buffer, unsigned int length) };


%{

#include <clamav.h>

struct cl_node *loaddbdir(const char *dirname, int *virnum, struct cl_node *root) {
  cl_loaddbdir(dirname, &root, virnum);
  return root;
}

const char *retdbdir(void) {
  return cl_retdbdir();
}

const char *reterror(int clerror) {
  return cl_strerror(clerror);
}

int buildtrie(struct cl_node *root) {
  return cl_buildtrie(root);
}

int scanbuff(const char *buffer, unsigned int length,
	     const char **virname, const struct cl_node *root) {
  return cl_scanbuff(buffer, length, virname, root);
}

int scanfile(const char *filename, const char **virname, const struct cl_node *root, int options) {

  struct cl_limits limits;
  memset(&limits, 0, sizeof(struct cl_limits));
  /* maximal number of files in archive */
  limits.maxfiles = 1000;
  /* maximal archived file size == 10 MB */
  limits.maxfilesize = 10 * 1048576;
  /* maximal recursion level */
  limits.maxreclevel = 5;
  /* maximal compression ratio */
  limits.maxratio = 200;
  /* disable memory limit for bzip2 scanner */
  limits.archivememlim = 0;
  
  return cl_scanfile(filename, virname, NULL, root, &limits, options);
}

int freetrie(struct cl_node *root) {
  cl_freetrie(root);
}

%}

struct cl_node *loaddbdir(const char *dirname, int *virnum, struct cl_node *root);
const char *retdbdir(void);
const char *reterror(int clerror);
int buildtrie(struct cl_node *root);
int scanbuff(const char *buffer, unsigned int length,
	     const char **virname, const struct cl_node *root);
int scanfile(const char *filename, const char **virname, 
	     const struct cl_node *root, int options);
int freetrie(struct cl_node *root);

/* scan options */
#define RAW          0
#define ARCHIVE      1
#define MAIL         2
#define DISABLERAR   4
#define OLE2         8
#define ENCRYPTED    16
