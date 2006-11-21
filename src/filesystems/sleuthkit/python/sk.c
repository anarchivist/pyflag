/* Sleuthkit python module for use by pyflag
 * Contains two new types (skfs and skfile).
 * skfs implement an interface somewhat similar to python's 'os' module.
 * skfile implements a file-like object for accessing files through sk.
 */

#include <Python.h>

#include "list.h"
#include "talloc.h"
#include "fs_tools.h"
#include "libfstools.h"

/* Here are a bunch of callbacks and helpers used to give sk a more filesystem
 * like interface */

/* callback function for dent_walk, populates an file list */
static uint8_t listdent_walk_callback(FS_INFO *fs, FS_DENT *fs_dent, int flags, void *ptr) {
    PyObject *list = (PyObject *)ptr;

    /* we dont want to add '.' and '..' */
    if(strcmp(fs_dent->name, ".")==0 || strcmp(fs_dent->name, "..")==0)
        return WALK_CONT;

    PyList_Append(list, PyString_FromString(fs_dent->name));
    return WALK_CONT;
}

struct block {
    DADDR_T addr;
    int size;
    char *resdata;
    struct list_head list;
};

/* callback function for file_walk, populates a block list */
static u_int8_t
getblocks_walk_callback (FS_INFO *fs, DADDR_T addr, char *buf, int size, int flags, char *ptr) {

    struct block *b;
    struct block *blocks = (struct block *) ptr;

    if(size <= 0)
        return WALK_CONT;

    /* create a new block entry */
    b = talloc(blocks, struct block);
    b->resdata = NULL;

    if(flags & FS_FLAG_DATA_RES) {
        // we have resident ntfs data (yuck!)
        b->resdata = (char *)talloc_size(b, size);
        b->size = size;
        memcpy(b->resdata, buf, size);
    } else {
        b->addr = addr;
        b->size = size;
    }

    /* add to the list */
    list_add_tail(&b->list, &blocks->list);
    return WALK_CONT;
}

INUM_T lookup(FS_INFO *fs, char *path) {
    return fs_ifind_path_ret(fs, 0, path);
}

/*
 * Suggested functions:
 * lookup (return inode for a path)
 * ipread (read from inode)
 * istat (return stat info for an inode)
 * pread (read from path)
 * stat (return stat info for an path)
 * isdir (is this a dir)
 * islink (is this a link)
 * isfile (is this a file)
 */

/*****************************************************************
 * Now for the python module stuff 
 * ***************************************************************/

/* The skfs type represents a sleuthkit filesystem object */
typedef struct {
    PyObject_HEAD
	IMG_INFO *img;
	FS_INFO *fs;
} skfs;

static void
skfs_dealloc(skfs *self) {
    if(self->fs)
        self->fs->close(self->fs);
    if(self->img)
        self->img->close(self->img);
}

static int
skfs_init(skfs *self, PyObject *args, PyObject *kwds) {
    char *imgfile=NULL, *imgtype=NULL, *fstype=NULL;

    static char *kwlist[] = {"imgfile", "imgtype", "fstype", NULL};

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "s|ss", kwlist, 
                                     &imgfile, &imgtype, &fstype))
        return -1; 

    /* force raw to prevent incorrect auto-detection of another imgtype */
    if(!imgtype) {
        imgtype = "raw";
    }

    /* initialise the img and filesystem */
	self->img = img_open(imgtype, 1, (const char **)&imgfile);
    if(!self->img)
        return -1;

    /* initialise the filesystem */
	self->fs = fs_open(self->img, 0, fstype);
    if(!self->img)
        return -1;

    return 0;
}

/* return a list of files and directories */
static PyObject *
skfs_listdir(skfs *self, PyObject *args, PyObject *kwds) {
    PyObject *list;
    PyObject *alloc=NULL;
    char *path=NULL;
    INUM_T inode;

    static char *kwlist[] = {"path", "alloc", NULL};

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "s|O", kwlist, 
                                     &path, &alloc))
        return NULL; 

    inode = lookup(self->fs, path);
    if(inode < 0)
        return NULL;

    list = PyList_New(0);
    self->fs->dent_walk(self->fs, inode, FS_FLAG_NAME_ALLOC, listdent_walk_callback, (void *)list);

    return list;
}

static PyMethodDef skfs_methods[] = {
    {"listdir", (PyCFunction)skfs_listdir, METH_VARARGS|METH_KEYWORDS,
     "List directory contents"
    },
    {NULL}  /* Sentinel */
};

static PyTypeObject skfsType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "sk.skfs",                 /*tp_name*/
    sizeof(skfs),              /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)skfs_dealloc,  /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,        /*tp_flags*/
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

/* The skfile type represents a sleuthkit file object */
typedef struct {
    PyObject_HEAD
    PyObject *skfs;
    struct block *blocks;
    off_t readptr;
    FS_INODE *fs_inode;
} skfile;

static void
skfile_dealloc(skfile *self) {
    Py_XDECREF(self->skfs);
    talloc_free(self->blocks);
    self->ob_type->tp_free((PyObject*)self);
}

static int
skfile_init(skfile *self, PyObject *args, PyObject *kwds) {
    char *filename=NULL;
    INUM_T inode=0;
    PyObject *skfs;

    static char *kwlist[] = {"filesystem", "inode", "filename", NULL};

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "O|Ks", kwlist, 
                                    &skfs, &inode, &filename))
        return -1; 

//    if(filename)
//        inode = lookup(filename);

    /* must specify either inode or filename */
    if(filename==NULL && inode <= 0)
        return -1;

    /* can we lookup this inode? */
//    self->fs_inode = self->fs->inode_lookup(self->fs, inode);
//    if(self->fs_inode == NULL)
//        return -1;

    /* store a ref to the skfs */
    Py_INCREF(skfs);
    self->skfs = skfs;

    /* perform a file run and populate the block list */
    self->blocks = talloc(NULL, struct block);
    INIT_LIST_HEAD(&self->blocks->list);
//    self->fs->file_walk(self->skfs->fs, self->fs_inode, 0, 0, 
//                       (FS_FLAG_FILE_AONLY | FS_FLAG_FILE_RECOVER | FS_FLAG_FILE_NOSPARSE),
//                       (FS_FILE_WALK_FN) getblocks_walk_callback, (void *)self->blocks);

    return 0;
}

/* read data from a file */
static PyObject *
skfile_read(skfile *self, PyObject *args) {
    long int size;

    if(!PyArg_ParseTuple(args, "l", &size))
        return NULL; 
}

static PyMethodDef skfile_methods[] = {
    {"read", (PyCFunction)skfile_read, METH_VARARGS,
     "Read data from file"
    },
    {NULL}  /* Sentinel */
};

static PyTypeObject skfileType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "sk.skfile",               /*tp_name*/
    sizeof(skfile),            /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)skfile_dealloc,/*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,        /*tp_flags*/
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

/* these are the module methods */
static PyMethodDef sk_methods[] = {
    {NULL}  /* Sentinel */
};

#ifndef PyMODINIT_FUNC	/* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif
PyMODINIT_FUNC
initsk(void) 
{
    PyObject* m;

    /* create module */
    m = Py_InitModule3("sk", sk_methods,
                       "Sleuthkit module.");

    /* setup skfs type */
    skfsType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&skfsType) < 0)
        return;

    Py_INCREF(&skfsType);
    PyModule_AddObject(m, "skfs", (PyObject *)&skfsType);

    /* setup skfile type */
    skfileType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&skfileType) < 0)
        return;

    Py_INCREF(&skfileType);
    PyModule_AddObject(m, "skfile", (PyObject *)&skfileType);
}
