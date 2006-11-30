/* Sleuthkit python module */

#include "Python.h"
#include "list.h"
#include "talloc.h"
#include "fs_tools.h"
#include "libfstools.h"

/******************************************************************
 * Helpers and SK integration stuff
 * ***************************************************************/

/* used in walks to determine what to return */
#define SK_FLAGS_INODES	0x1	// inodes in result
#define SK_FLAGS_NAMES	0x2	// names in result

/* structure to track block lists */
struct block {
    DADDR_T addr;
    int size;
    struct list_head list;
};

/* callback functions for dent_walk, populate a file list */
static uint8_t
listdent_walk_callback(FS_INFO *fs, FS_DENT *fs_dent, int flags, void *ptr);
static uint8_t
listdent_walk_callback_dirs(FS_INFO *fs, FS_DENT *fs_dent, int flags, void *ptr);
static uint8_t
listdent_walk_callback_nondirs(FS_INFO *fs, FS_DENT *fs_dent, int flags, void *ptr);

/* callback functions for dent_walk, populate a inode list */
static uint8_t
listdent_walk_callback_inode(FS_INFO *fs, FS_DENT *fs_dent, int flags, void *ptr);
static uint8_t
listdent_walk_callback_inode_dirs(FS_INFO *fs, FS_DENT *fs_dent, int flags, void *ptr);
static uint8_t
listdent_walk_callback_inode_nondirs(FS_INFO *fs, FS_DENT *fs_dent, int flags, void *ptr);

/* callback function for file_walk, populates a block list */
static u_int8_t
getblocks_walk_callback(FS_INFO *fs, DADDR_T addr, char *buf, int size, int flags, char *ptr);

/* lookup an inode from a path */
INUM_T lookup(FS_INFO *fs, char *path);

/******************************************************************
 * SKFS - Sleuthkit Filesystem Python Type
 * ***************************************************************/

typedef struct {
    PyObject_HEAD
	IMG_INFO *img;
	FS_INFO *fs;
} skfs;

static void skfs_dealloc(skfs *self);
static int skfs_init(skfs *self, PyObject *args, PyObject *kwds);
static PyObject *skfs_listdir(skfs *self, PyObject *args, PyObject *kwds);
static PyObject *skfs_open(skfs *self, PyObject *args, PyObject *kwds);
static PyObject *skfs_walk(skfs *self, PyObject *args, PyObject *kwds);
static PyObject *skfs_iwalk(skfs *self, PyObject *args, PyObject *kwds);
static PyObject *skfs_stat(skfs *self, PyObject *args, PyObject *kwds);

static PyMethodDef skfs_methods[] = {
    {"listdir", (PyCFunction)skfs_listdir, METH_VARARGS|METH_KEYWORDS,
     "List directory contents" },
    {"open", (PyCFunction)skfs_open, METH_VARARGS|METH_KEYWORDS,
     "Open a file" },
    {"walk", (PyCFunction)skfs_walk, METH_VARARGS|METH_KEYWORDS,
     "Walk filesystem from the given path" },
    {"iwalk", (PyCFunction)skfs_iwalk, METH_VARARGS|METH_KEYWORDS,
     "Walk filesystem from the given path (return inodes)" },
    {"stat", (PyCFunction)skfs_stat, METH_VARARGS|METH_KEYWORDS,
     "Stat a file" },
    {NULL}  /* Sentinel */
};

static PyTypeObject skfsType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /* ob_size */
    "sk.skfs",                 /* tp_name */
    sizeof(skfs),              /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)skfs_dealloc,  /* tp_dealloc */
    0,                         /* tp_print */
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    0,                         /* tp_compare */
    0,                         /* tp_repr */
    0,                         /* tp_as_number */
    0,                         /* tp_as_sequence */
    0,                         /* tp_as_mapping */
    0,                         /* tp_hash */
    0,                         /* tp_call */
    0,                         /* tp_str */
    0,                         /* tp_getattro */
    0,                         /* tp_setattro */
    0,                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,        /* tp_flags */
    "Sleuthkit Filesystem Object",     /* tp_doc */
    0,	                       /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    skfs_methods,              /* tp_methods */
    0,                         /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)skfs_init,       /* tp_init */
    0,                         /* tp_alloc */
    0,                         /* tp_new */
};

/******************************************************************
 * SKFSWalkIter - Support the skfs.walk iterator
 * ***************************************************************/

/* stores the major elements of FS_DENT */
struct dentwalk {
    char *path;
    INUM_T inode;
    uint8_t ent_type;
    struct list_head list;
};

typedef struct {
    PyObject_HEAD
    skfs *skfs;
    struct dentwalk *walklist;
    int flags;
    int myflags;
} skfs_walkiter;

static void skfs_walkiter_dealloc(skfs_walkiter *self);
static int skfs_walkiter_init(skfs_walkiter *self, PyObject *args, PyObject *kwds);
static PyObject *skfs_walkiter_iter(skfs_walkiter *self);
static PyObject *skfs_walkiter_iternext(skfs_walkiter *self);

static PyTypeObject skfs_walkiterType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /* ob_size */
    "sk.skfs_walkiter",        /* tp_name */
    sizeof(skfs_walkiter),     /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)skfs_walkiter_dealloc, /* tp_dealloc */
    0,                         /* tp_print */
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    0,                         /* tp_compare */
    0,                         /* tp_repr */
    0,                         /* tp_as_number */
    0,                         /* tp_as_sequence */
    0,                         /* tp_as_mapping */
    0,                         /* tp_hash */
    0,                         /* tp_call */
    0,                         /* tp_str */
    0,                         /* tp_getattro */
    0,                         /* tp_setattro */
    0,                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,        /* tp_flags */
    "Sleuthkit Filesystem Walk Iterator Object", /* tp_doc */
    0,	                       /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    PyObject_SelfIter,         /* tp_iter */
    (iternextfunc)skfs_walkiter_iternext, /* tp_iternext */
    0,                         /* tp_methods */
    0,                         /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)skfs_walkiter_init, /* tp_init */
    0,                         /* tp_alloc */
    0,                         /* tp_new */
};

/******************************************************************
 * SKFILE - Sleuthkit File Python Type
 * ***************************************************************/

typedef struct {
    PyObject_HEAD
    PyObject *skfs;
    FS_INODE *fs_inode;
    struct block *blocks;
    char *resdata;
    long long readptr;
    long long size;
} skfile;

static void skfile_dealloc(skfile *self);
static int skfile_init(skfile *self, PyObject *args, PyObject *kwds);
static PyObject *skfile_read(skfile *self, PyObject *args);
static PyObject *skfile_seek(skfile *self, PyObject *args);
static PyObject *skfile_tell(skfile *self);
static PyObject *skfile_blocks(skfile *self);

static PyMethodDef skfile_methods[] = {
    {"read", (PyCFunction)skfile_read, METH_VARARGS,
     "Read data from file" },
    {"seek", (PyCFunction)skfile_seek, METH_VARARGS,
     "Seek within a file" },
    {"tell", (PyCFunction)skfile_tell, METH_NOARGS,
     "Return possition within file" },
    {"blocks", (PyCFunction)skfile_blocks, METH_NOARGS,
     "Return a list of blocks which the file occupies" },
    {NULL}  /* Sentinel */
};

static PyTypeObject skfileType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /* ob_size */
    "sk.skfile",               /* tp_name */
    sizeof(skfile),            /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)skfile_dealloc,/* tp_dealloc */
    0,                         /* tp_print */
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    0,                         /* tp_compare */
    0,                         /* tp_repr */
    0,                         /* tp_as_number */
    0,                         /* tp_as_sequence */
    0,                         /* tp_as_mapping */
    0,                         /* tp_hash */
    0,                         /* tp_call */
    0,                         /* tp_str */
    0,                         /* tp_getattro */
    0,                         /* tp_setattro */
    0,                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,        /* tp_flags */
    "Sleuthkit File Object",   /* tp_doc */
    0,	                       /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    skfile_methods,            /* tp_methods */
    0,                         /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)skfile_init,     /* tp_init */
    0,                         /* tp_alloc */
    0,                         /* tp_new */
};
