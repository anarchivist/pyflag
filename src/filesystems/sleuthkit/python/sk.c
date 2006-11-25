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

/*
 * Suggested functions:
 * skfs:
 * lookup (return inode for a path)
 * walk (same as os.walk)
 * stat (return stat info for an path)
 * isdir (is this a dir)
 * islink (is this a link)
 * isfile (is this a file)
 * skfile:
 * read (read from path)
 */


/* Here are a bunch of callbacks and helpers used to give sk a more filesystem
 * like interface */

/* TODO: These dent_walks currently DO NOT add NTFS alternate data streams,
 * they will have to be changed (read: made much uglier) to do so */

/* callback function for dent_walk, populates an name list (dirs only) */
static uint8_t listdent_walk_callback_dirs(FS_INFO *fs, FS_DENT *fs_dent, int flags, void *ptr) {
    PyObject *list = (PyObject *)ptr;

    /* we dont want to add '.' and '..' */
    if(strcmp(fs_dent->name, ".")==0 || strcmp(fs_dent->name, "..")==0)
        return WALK_CONT;

    if(fs_dent->ent_type == FS_DENT_DIR)
        PyList_Append(list, PyString_FromString(fs_dent->name));

    return WALK_CONT;
}

/* callback function for dent_walk, populates an name list (nondirs only) */
static uint8_t listdent_walk_callback_nondirs(FS_INFO *fs, FS_DENT *fs_dent, int flags, void *ptr) {
    PyObject *list = (PyObject *)ptr;

    /* we dont want to add '.' and '..' */
    if(strcmp(fs_dent->name, ".")==0 || strcmp(fs_dent->name, "..")==0)
        return WALK_CONT;

    if(fs_dent->ent_type != FS_DENT_DIR)
        PyList_Append(list, PyString_FromString(fs_dent->name));

    return WALK_CONT;
}

/* callback function for dent_walk, populates an name list */
static uint8_t listdent_walk_callback(FS_INFO *fs, FS_DENT *fs_dent, int flags, void *ptr) {
    listdent_walk_callback_dirs(fs, fs_dent, flags, ptr);
    listdent_walk_callback_nondirs(fs, fs_dent, flags, ptr);
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
        file->size = size;
    } else {
        /* create a new block entry */
        b = talloc(file->blocks, struct block);
        b->addr = addr;
        b->size = size;
        list_add_tail(&b->list, &file->blocks->list);
        file->size += size;
    }

    /* add to the list */
    return WALK_CONT;
}

/* lookup an inode from a path */
INUM_T lookup(FS_INFO *fs, char *path) {
    INUM_T ret;
    char *tmp = strdup(path);
    /* this is evil and modifies the path! */
    ret = fs_ifind_path_ret(fs, 0, tmp);
    free(tmp);
    return ret;
}

/*****************************************************************
 * Now for the python module stuff 
 * ***************************************************************/

/* TODO: Set proper exceptions before returning on errors 
 * Double check the types used, sk generally uses uint64_t for 
 * inums, addresses etc */

/************* SKFS ***************/
static void
skfs_dealloc(skfs *self) {
    if(self->fs)
        self->fs->close(self->fs);
    if(self->img)
        self->img->close(self->img);
    self->ob_type->tp_free((PyObject*)self);
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
    char *path=NULL;
    INUM_T inode;
    int flags=0;
    /* these are the boolean options with defaults */
    int alloc=1, unalloc=0;

    static char *kwlist[] = {"path", "alloc", "unalloc", NULL};

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "s|ii", kwlist, 
                                     &path, &alloc, &unalloc))
        return NULL; 

    inode = lookup(self->fs, path);
    if(inode < 0)
        return NULL;

    /* set flags */
    if(alloc)
        flags |= FS_FLAG_NAME_ALLOC;
    if(unalloc)
        flags |= FS_FLAG_NAME_UNALLOC;

    list = PyList_New(0);
    self->fs->dent_walk(self->fs, inode, flags, listdent_walk_callback, (void *)list);

    return list;
}

/* Open a file from the skfs */
static PyObject *
skfs_open(skfs *self, PyObject *args, PyObject *kwds) {
    char *path=NULL;
    INUM_T inode=0;
    int type=0, id=0;
    PyObject *fileargs, *filekwds; 
    skfile *file;

    static char *kwlist[] = {"path", "inode", "type", "id", NULL};

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "|sKii", kwlist, &path, &inode, &type, &id))
        return NULL; 

    /* make sure we at least have a path or inode */
    if(path==NULL && inode==0)
        return NULL;

    /* create an skfile object to return to the caller */
    fileargs = PyTuple_New(0);
    filekwds = Py_BuildValue("{sOsssKsisi}", "filesystem", (PyObject *)self, "path", path,
                                             "inode", inode, "type", type, "id", id);

    file = PyObject_New(skfile, &skfileType);
    skfile_init(file, fileargs, filekwds);
    Py_DECREF(fileargs);
    Py_DECREF(filekwds);
    return (PyObject *)file;
}

/* perform a filesystem walk (like os.walk) */
static PyObject *
skfs_walk(skfs *self, PyObject *args, PyObject *kwds) {
    char *path=NULL;
    PyObject *fileargs, *filekwds; 
    int alloc=1, unalloc=0;
    skfs_walkiter *iter;

    static char *kwlist[] = {"path", "alloc", "unalloc", NULL};

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "s|ii", kwlist, &path, &alloc, &unalloc))
        return NULL; 

    /* create an skfs_walkiter object to return to the caller */
    fileargs = PyTuple_New(0);
    filekwds = Py_BuildValue("{sOsssisi}", "filesystem", (PyObject *)self, "path", path,
                                             "alloc", alloc, "unalloc", unalloc);

    iter = PyObject_New(skfs_walkiter, &skfs_walkiterType);
    skfs_walkiter_init(iter, fileargs, filekwds);
    Py_DECREF(fileargs);
    Py_DECREF(filekwds);
    return (PyObject *)iter;
}

/* perform a filesystem walk (like os.walk) */
static PyObject *
skfs_stat(skfs *self, PyObject *args, PyObject *kwds) {
    PyObject *result;
    PyObject *os;
    char *path=NULL;
    INUM_T inode=0;
    FS_INODE *fs_inode;
    int type=0, id=0;

    static char *kwlist[] = {"path", "inode", "type", "id", NULL};

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "|sKii", kwlist, &path, &inode, &type, &id))
        return NULL; 

    /* make sure we at least have a path or inode */
    if(path==NULL && inode==0)
        return NULL;

    if(path)
        inode = lookup(self->fs, path);

    /* can we lookup this inode? */
    fs_inode = self->fs->inode_lookup(self->fs, inode);
    if(fs_inode == NULL)
        return NULL;

    /* return a real stat_result! */
    /* (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) */
    os = PyImport_ImportModule("os");
    result = PyObject_CallMethod(os, "stat_result", "((iiliiiiiii))", 
                                 fs_inode->mode, fs_inode->addr, 0, fs_inode->nlink, 
                                 fs_inode->uid, fs_inode->gid, fs_inode->size,
                                 fs_inode->atime, fs_inode->mtime, fs_inode->ctime);
    Py_DECREF(os);

    /* release the fs_inode */
    fs_inode_free(fs_inode);

    return result;
}

/* this new object is requred to support the iterator protocol for skfs.walk
 * */
static void 
skfs_walkiter_dealloc(skfs_walkiter *self) {
    Py_XDECREF(self->skfs);
    talloc_free(self->paths);
    self->ob_type->tp_free((PyObject*)self);
}

static int 
skfs_walkiter_init(skfs_walkiter *self, PyObject *args, PyObject *kwds) {
    char *path=NULL;
    PyObject *skfs_obj;
    struct walkpath *root;
    int alloc=1, unalloc=0;

    static char *kwlist[] = {"filesystem", "path", "alloc", "unalloc", NULL};

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "Os|ii", kwlist, 
                                    &skfs_obj, &path, &alloc, &unalloc))
        return -1; 

    /* set flags */
    if(alloc)
        self->flags |= FS_FLAG_NAME_ALLOC;
    if(unalloc)
        self->flags |= FS_FLAG_NAME_UNALLOC;

    /* incref the skfs */
    Py_INCREF(skfs_obj);
    self->skfs = (skfs *)skfs_obj;

    /* Initialise the path stack */
    self->paths = talloc(NULL, struct walkpath);
    INIT_LIST_HEAD(&self->paths->list);

    /* add the root path */
    root = talloc(self->paths, struct walkpath);
    root->path = talloc_strdup(root, path);
    list_add(&root->list, &self->paths->list);

    return 0;
}

static PyObject *skfs_walkiter_iternext(skfs_walkiter *self) {
    PyObject *dirlist, *filelist, *result;
    struct walkpath *wp;
    struct walkpath *tmpwp;
    INUM_T inode;
    char *path;
    int i;

    /* are we done ? */
    if(list_empty(&self->paths->list))
        return NULL;

    /* pop a path from the stack */
    list_next(wp, &self->paths->list, list);
    path = wp->path;

    if(!path)
        return NULL;

    /* special case to prevent '//' paths */
    if(strcmp(path, "/")==0)
        *path = 0;

    /* TODO: is this always an error? maby we need to return an empty tuple
     * and continue? */
    inode = lookup(self->skfs->fs, path);
    if(inode < 0)
        return NULL;

    dirlist = PyList_New(0);
    self->skfs->fs->dent_walk(self->skfs->fs, inode, self->flags, 
                              listdent_walk_callback_dirs, (void *)dirlist);

    filelist = PyList_New(0);
    self->skfs->fs->dent_walk(self->skfs->fs, inode, self->flags, 
                              listdent_walk_callback_nondirs, (void *)filelist);

    /* add dirs to the stack */
    for(i=0; i<PyList_Size(dirlist); i++) {
        tmpwp = talloc(self->paths, struct walkpath);
        tmpwp->path = talloc_asprintf(tmpwp, "%s/%s", path, PyString_AsString(PyList_GetItem(dirlist, i)));
        list_add(&tmpwp->list, &self->paths->list);
    }

    result = Py_BuildValue("(sNN)", path, dirlist, filelist);

    /* now delete this entry from the stack */
    list_del(&wp->list);
    talloc_free(wp);

    return result;
}

/************* SKFILE ***************/
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
    int type=0, id=0;
    PyObject *skfs_obj;
    FS_INFO *fs;

    static char *kwlist[] = {"filesystem", "path", "inode", "type", "id", NULL};

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "O|sKii", kwlist, 
                                    &skfs_obj, &filename, &inode, &type, &id))
        return -1; 

    /* check the type of the filesystem object */
    if(PyObject_TypeCheck(skfs_obj, &skfsType)==0)
        return -1;

    fs = ((skfs *)skfs_obj)->fs;

    /* must specify either inode or filename */
    if(filename==NULL && inode == 0)
        return -1;

    if(filename)
        inode = lookup(fs, filename);

    /* can we lookup this inode? */
    self->fs_inode = fs->inode_lookup(fs, inode);
    if(self->fs_inode == NULL)
        return -1;

    /* store a ref to the skfs */
    Py_INCREF(skfs_obj);
    self->skfs = skfs_obj;

    self->resdata = NULL;
    self->readptr = 0;
    self->size = 0;

    /* perform a file run and populate the block list, use type and id to
     * ensure we follow the correct attribute for NTFS (these default to 0
     * which will give us the default data attribute). size will also be set
     * during the walk */
    self->blocks = talloc(NULL, struct block);
    INIT_LIST_HEAD(&self->blocks->list);
    if(id == 0)
        fs->file_walk(fs, self->fs_inode, type, id, 
                     (FS_FLAG_FILE_AONLY | FS_FLAG_FILE_RECOVER | FS_FLAG_FILE_NOSPARSE | FS_FLAG_FILE_NOID),
                     (FS_FILE_WALK_FN) getblocks_walk_callback, (void *)self);
    else
        fs->file_walk(fs, self->fs_inode, type, id, 
                     (FS_FLAG_FILE_AONLY | FS_FLAG_FILE_RECOVER | FS_FLAG_FILE_NOSPARSE),
                     (FS_FILE_WALK_FN) getblocks_walk_callback, (void *)self);

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
    if(readlen < 0 || self->readptr + readlen > self->size)
        readlen = self->size - self->readptr;

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
            self->readptr = self->size + offset;
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

    /* setup skfs_walkiter type */
    skfs_walkiterType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&skfs_walkiterType) < 0)
        return;

    Py_INCREF(&skfs_walkiterType);
    //PyModule_AddObject(m, "skfs_walkiter", (PyObject *)&skfs_walkiterType);

    /* setup skfile type */
    skfileType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&skfileType) < 0)
        return;

    Py_INCREF(&skfileType);
    PyModule_AddObject(m, "skfile", (PyObject *)&skfileType);
}
