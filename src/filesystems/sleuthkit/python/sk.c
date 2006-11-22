/* Sleuthkit python module for use by pyflag
 * Contains two new types (skfs and skfile).
 * skfs implement an interface somewhat similar to python's 'os' module.
 * skfile implements a file-like object for accessing files through sk.
 */

#include <Python.h>

#include "sk.h"
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

/* callback function for file_walk, populates a block list */
static u_int8_t
getblocks_walk_callback (FS_INFO *fs, DADDR_T addr, char *buf, int size, int flags, char *ptr) {

    struct block *b;
    skfile *file = (skfile *) ptr;

    if(size <= 0)
        return WALK_CONT;

    if(flags & FS_FLAG_DATA_RES) {
        /* we have resident ntfs data */
        file->resdata = (char *)talloc_size(NULL, size);
        memcpy(file->resdata, buf, size);
    } else {
        /* create a new block entry */
        b = talloc(file->blocks, struct block);
        b->addr = addr;
        b->size = size;
        list_add_tail(&b->list, &file->blocks->list);
    }

    /* add to the list */
    return WALK_CONT;
}

/* lookup an inode from a path */
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

/* Open a file from the skfs */
static PyObject *
skfs_open(skfs *self, PyObject *args, PyObject *kwds) {
    char *path=NULL;
    PyObject *fileargs, *filekwds; 
    skfile *file;

    static char *kwlist[] = {"path", NULL};

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist, &path))
        return NULL; 

    /* create an skfs object to return to the caller */
    fileargs = PyTuple_New(0);
    filekwds = Py_BuildValue("{sOss}", "filesystem", (PyObject *)self, "filename", path);

    file = PyObject_New(skfile, &skfileType);
    skfile_init(file, fileargs, filekwds);
    Py_DECREF(fileargs);
    Py_DECREF(filekwds);
    return (PyObject *)file;
}

static void
skfile_dealloc(skfile *self) {
    Py_XDECREF(self->skfs);
    talloc_free(self->blocks);
    if(self->resdata)
        talloc_free(self->resdata);
    fs_inode_free(self->fs_inode);
    self->ob_type->tp_free((PyObject*)self);
}

static int
skfile_init(skfile *self, PyObject *args, PyObject *kwds) {
    char *filename=NULL;
    INUM_T inode=0;
    PyObject *skfs_obj;
    FS_INFO *fs;

    static char *kwlist[] = {"filesystem", "inode", "filename", NULL};

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "O|Ks", kwlist, 
                                    &skfs_obj, &inode, &filename))
        return -1; 

    fs = ((skfs *)skfs_obj)->fs;

    if(filename)
        inode = lookup(fs, filename);

    /* must specify either inode or filename */
    if(filename==NULL && inode <= 0)
        return -1;

    /* can we lookup this inode? */
    self->fs_inode = fs->inode_lookup(fs, inode);
    if(self->fs_inode == NULL)
        return -1;

    /* store a ref to the skfs */
    Py_INCREF(skfs_obj);
    self->skfs = skfs_obj;

    /* perform a file run and populate the block list */
    self->blocks = talloc(NULL, struct block);
    INIT_LIST_HEAD(&self->blocks->list);
    fs->file_walk(fs, self->fs_inode, 0, 0, 
                 (FS_FLAG_FILE_AONLY | FS_FLAG_FILE_RECOVER | FS_FLAG_FILE_NOSPARSE),
                 (FS_FILE_WALK_FN) getblocks_walk_callback, (void *)self);

    self->resdata = NULL;
    self->readptr = 0;
    return 0;
}

static PyObject *
skfile_read(skfile *self, PyObject *args) {
    char *buf;
    int cur, written;
    PyObject *retdata;
    FS_INFO *fs;
    struct block *b;
    int readlen=-1;

    fs = ((skfs *)self->skfs)->fs;

    if(!PyArg_ParseTuple(args, "|i", &readlen))
        return NULL; 

    /* adjust readlen if size not given or is too big */
    if(readlen < 0 || self->readptr + readlen > self->fs_inode->size)
        readlen = self->fs_inode->size - self->readptr;

    /* special case for NTFS resident data */
    if(self->resdata) {
         retdata = PyString_FromStringAndSize(self->resdata + self->readptr, readlen);
         self->readptr += readlen;
         return retdata;
    }
    
    /* allocate buf, be generous in case data straddles blocks */
    buf = (char *)malloc(readlen + (2 * fs->block_size));
    if(!buf)
        return NULL;

    /* read necessary blocks into buf */
    cur = written = 0;
    list_for_each_entry(b, &self->blocks->list, list) {

        /* we don't need any data in this block, skip */
        if(cur + fs->block_size <= self->readptr) {
            cur += fs->block_size;
            continue;
        }

        /* read block into buf */
        fs_read_block_nobuf(fs, buf+written, fs->block_size, b->addr);
        cur += fs->block_size;
        written += fs->block_size;

        /* are we done yet? */
        if(cur >= self->readptr + readlen)
            break;
    }

    /* copy what we want into the return string */
    retdata = PyString_FromStringAndSize(buf + (self->readptr % fs->block_size), readlen);
    free(buf);

    self->readptr += readlen;
    return retdata;
}

static PyObject *
skfile_seek(skfile *self, PyObject *args) {
    int offset=0;
    int whence=0;

    if(!PyArg_ParseTuple(args, "i|i", &offset, &whence))
        return NULL; 

    switch(whence) {
        case 0:
            self->readptr = offset;
            break;
        case 1:
            self->readptr += offset;
            break;
        case 2:
            self->readptr = self->fs_inode->size + offset;
            break;
        default:
            return NULL;
    }
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
skfile_tell(skfile *self) {
    return PyLong_FromLongLong(self->readptr);
}

static PyObject *
skfile_blocks(skfile *self) {
    struct block *b;
    PyObject *list = PyList_New(0);

    list_for_each_entry(b, &self->blocks->list, list) {
        PyList_Append(list, PyLong_FromUnsignedLongLong(b->addr));
    }
    return list;
}

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