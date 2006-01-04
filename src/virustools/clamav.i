/*
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.75 Date: Sat Feb 12 14:00:04 EST 2005$
# ******************************************************
#
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# *
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
# ******************************************************
*/

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
