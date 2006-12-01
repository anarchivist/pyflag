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

/* TODO: The dent_walk currently DOES NOT add NTFS alternate data streams,
 * this will have to be changed (read: made much uglier) to do so */

/* callback function for dent_walk used in skfs.walk */
static uint8_t listdent_walk_callback_dent(FS_INFO *fs, FS_DENT *fs_dent, int flags, void *ptr) {
    struct dentwalk *dentlist, *p;
    dentlist = (struct dentwalk *)ptr;

    /* we dont want to add '.' and '..' */
    if(strcmp(fs_dent->name, ".")==0 || strcmp(fs_dent->name, "..")==0)
        return WALK_CONT;

    p = talloc(dentlist, struct dentwalk);
    p->path = talloc_strndup(p, fs_dent->name, fs_dent->name_max - 1);
    p->inode = fs_dent->inode;
    p->ent_type = fs_dent->ent_type;
    list_add_tail(&p->list, &dentlist->list);

    return WALK_CONT;
}

/* callback function for dent_walk used by listdir */
static uint8_t listdent_walk_callback_list(FS_INFO *fs, FS_DENT *fs_dent, int flags, void *ptr) {
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
INUM_T lookup_inode(FS_INFO *fs, char *path) {
    INUM_T ret;
    char *tmp = strdup(path);
    /* this is evil and modifies the path! */
    ret = fs_ifind_path_ret(fs, 0, tmp);
    free(tmp);
    return ret;
}

/* callback for lookup_path */
static uint8_t
lookup_path_cb(FS_INFO * fs, FS_DENT * fs_dent, int flags, void *ptr) {
    struct dentwalk *dent = (struct dentwalk *)ptr;

    if (fs_dent->inode == dent->inode) {
        dent->path = talloc_asprintf(dent, "/%s%s", fs_dent->path, fs_dent->name);
        return WALK_STOP;
    }
    return WALK_CONT;
}

/* lookup path for inode, supply an dentwalk ptr (must be a talloc context),
 * name will be filled in */
int lookup_path(FS_INFO *fs, struct dentwalk *dent) {
    int flags = FS_FLAG_NAME_RECURSE | FS_FLAG_NAME_ALLOC;

    /* special case, the walk won't pick this up */
    if(dent->inode == fs->root_inum) {
        dent->path = talloc_strdup(dent, "/");
        return 0;
    }

    /* there is a walk optimised for NTFS */
    if((fs->ftype & FSMASK) == NTFS_TYPE) {
        if(ntfs_find_file(fs, dent->inode, 0, 0, flags, lookup_path_cb, (void *)dent))
            return 1;
    } else {
        if(fs->dent_walk(fs, fs->root_inum, flags, lookup_path_cb, (void *)dent))
            return 1;
    }
    return 0;
}

/*****************************************************************
 * Now for the python module stuff 
 * ***************************************************************/

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
    tsk_error_reset();
    self->img = img_open(imgtype, 1, (const char **)&imgfile);
    if(!self->img) {
      PyErr_Format(PyExc_IOError, "Unable to open image %s: %s", imgfile, tsk_error_str());
      return -1;
    }

    /* initialise the filesystem */
    tsk_error_reset();
    self->fs = fs_open(self->img, 0, fstype);
    if(!self->fs) {
      PyErr_Format(PyExc_RuntimeError, "Unable to open filesystem in image %s: %s", imgfile, tsk_error_str());
      return -1;
    }

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

    tsk_error_reset();
    inode = lookup_inode(self->fs, path);
    if(inode == 0)
        return PyErr_Format(PyExc_IOError, "Unable to find inode for path %s: %s", path, tsk_error_str());

    /* set flags */
    if(alloc)
        flags |= FS_FLAG_NAME_ALLOC;
    if(unalloc)
        flags |= FS_FLAG_NAME_UNALLOC;

    list = PyList_New(0);

    tsk_error_reset();
    self->fs->dent_walk(self->fs, inode, flags, listdent_walk_callback_list, (void *)list);
    if(tsk_errno) {
      return PyErr_Format(PyExc_IOError, "Unable to list inode %lu: %s", (ULONG)inode, tsk_error_str());
    };

    return list;
}

/* Open a file from the skfs */
static PyObject *
skfs_open(skfs *self, PyObject *args, PyObject *kwds) {
    char *path=NULL;
    INUM_T inode=0;
    int type=0, id=0, ret;
    PyObject *fileargs, *filekwds;
    skfile *file;

    static char *kwlist[] = {"path", "inode", "type", "id", NULL};

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "|sKii", kwlist, &path, &inode, &type, &id))
        return NULL; 

    /* make sure we at least have a path or inode */
    if(path==NULL && inode==0)
        return PyErr_Format(PyExc_SyntaxError, "One of path or inode must be specified, inode cannot be 0");

    /* create an skfile object and return it */
    filekwds = PyDict_New();
    if(path)
        fileargs = Py_BuildValue("(OsKii)", (PyObject *)self, path, inode, type, id);
    else
        fileargs = Py_BuildValue("(OsKii)", (PyObject *)self, "", inode, type, id);

    file = PyObject_New(skfile, &skfileType);
    ret = skfile_init(file, fileargs, filekwds);
    Py_DECREF(fileargs);
    Py_DECREF(filekwds);

    if(ret == -1) return NULL;
    return (PyObject *)file;
}

/* perform a filesystem walk (like os.walk) */
static PyObject *
skfs_walk(skfs *self, PyObject *args, PyObject *kwds) {
    char *path=NULL;
    int alloc=1, unalloc=0, ret;
    int names=1, inodes=0;
    PyObject *fileargs, *filekwds;
    skfs_walkiter *iter;
    INUM_T inode=0;

    static char *kwlist[] = {"path", "inode", "alloc", "unalloc", "names", "inodes", NULL};

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "|sKiiii", kwlist, &path, &inode, 
                                    &alloc, &unalloc, &names, &inodes))
        return NULL; 

    /* create an skfs_walkiter object to return to the caller */
    filekwds = PyDict_New();
    if(path)
        fileargs = Py_BuildValue("(OsKiiii)", (PyObject *)self, path,
                                 inode, alloc, unalloc, names, inodes);
    else
        fileargs = Py_BuildValue("(OsKiiii)", (PyObject *)self, "",
                                 inode, alloc, unalloc, names, inodes);

    iter = PyObject_New(skfs_walkiter, &skfs_walkiterType);
    ret = skfs_walkiter_init(iter, fileargs, filekwds);
    Py_DECREF(fileargs);
    Py_DECREF(filekwds);

    if(ret == -1) return NULL;
    return (PyObject *)iter;
}

/* stat a file */
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
        return PyErr_Format(PyExc_SyntaxError, "One of path or inode must be specified");

    if(path) {
        tsk_error_reset();
        inode = lookup_inode(self->fs, path);
        if(inode == 0)
            return PyErr_Format(PyExc_IOError, "Unable to find inode for path %s: %d: %s", path, (ULONG) inode, tsk_error_str());
    };

    /* can we lookup this inode? */
    tsk_error_reset();
    fs_inode = self->fs->inode_lookup(self->fs, inode);
    if(fs_inode == NULL)
        return PyErr_Format(PyExc_IOError, "Unable to find inode %lu: %s", (ULONG)inode, tsk_error_str());

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
    talloc_free(self->walklist);
    self->ob_type->tp_free((PyObject*)self);
}

static int 
skfs_walkiter_init(skfs_walkiter *self, PyObject *args, PyObject *kwds) {
    char *path=NULL;
    PyObject *skfs_obj;
    struct dentwalk *root;
    int alloc=1, unalloc=0;
    int names=1, inodes=0;
    INUM_T inode;

    static char *kwlist[] = {"filesystem", "path", "inode", "alloc", "unalloc", "names", "inodes", NULL};

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "O|sKiiii", kwlist, &skfs_obj, 
                                    &path, &inode, &alloc, &unalloc, &names, &inodes))
        return -1; 

    /* must have at least inode or path */
    if(inode == 0 && path == NULL) {
        PyErr_Format(PyExc_SyntaxError, "One of filename or inode must be specified");
        return -1;
    };

    /* set flags */
    self->flags = self->myflags = 0;
    if(alloc)
        self->flags |= FS_FLAG_NAME_ALLOC;
    if(unalloc)
        self->flags |= FS_FLAG_NAME_UNALLOC;
    if(names)
        self->myflags |= SK_FLAG_NAMES;
    if(inodes)
        self->myflags |= SK_FLAG_INODES;

    /* incref the skfs */
    Py_INCREF(skfs_obj);
    self->skfs = (skfs *)skfs_obj;

    /* Initialise the path stack */
    self->walklist = talloc(NULL, struct dentwalk);
    INIT_LIST_HEAD(&self->walklist->list);

    /* add the start path */
    root = talloc(self->walklist, struct dentwalk);

    if(inode == 0) {
        tsk_error_reset();
        root->inode = lookup_inode(self->skfs->fs, path);
    } else root->inode = inode;

    if(path == NULL) {
        tsk_error_reset();
        lookup_path(self->skfs->fs, root);
    } else root->path = talloc_strdup(root, path);

    list_add(&root->list, &self->walklist->list);

    return 0;
}

static PyObject *skfs_walkiter_iternext(skfs_walkiter *self) {
    PyObject *dirlist, *filelist, *root, *result;
    struct dentwalk *dw, *dwlist;
    struct dentwalk *dwtmp, *dwtmp2;
    char *tmp;
    int i;

    /* are we done ? */
    if(list_empty(&self->walklist->list))
        return NULL;

    /* pop an item from the stack */
    list_next(dw, &self->walklist->list, list);

    /* initialise our list for this walk */
    dwlist = talloc(self->walklist, struct dentwalk);
    INIT_LIST_HEAD(&dwlist->list);

    /* walk this directory */
    tsk_error_reset();
    self->skfs->fs->dent_walk(self->skfs->fs, dw->inode, self->flags, 
                              listdent_walk_callback_dent, (void *)dwlist);
    if(tsk_errno) {
        PyErr_Format(PyExc_IOError, "Walk error: %s", tsk_error_str());
        talloc_free(dwlist);
        return NULL;
    }

    /* process the list */
    dirlist = PyList_New(0);
    filelist = PyList_New(0);
    list_for_each_entry_safe(dwtmp, dwtmp2, &dwlist->list, list) {

        /* process directories */
        if(dwtmp->ent_type & FS_DENT_DIR) {

            /* place into dirlist */
            if((self->myflags & SK_FLAG_INODES) && (self->myflags & SK_FLAG_NAMES))
                PyList_Append(dirlist, Py_BuildValue("(Ks)", dwtmp->inode, dwtmp->path));
            else if(self->myflags & SK_FLAG_INODES)
                PyList_Append(dirlist, PyLong_FromUnsignedLongLong(dwtmp->inode));
            else if(self->myflags & SK_FLAG_NAMES)
                PyList_Append(dirlist, PyString_FromString(dwtmp->path));

            /* steal it and push onto the directory stack */
            talloc_steal(self->walklist, dwtmp);
            tmp = dwtmp->path;
            if(strcmp(dw->path, "/") == 0)
                dwtmp->path = talloc_asprintf(dwtmp, "/%s", tmp);
            else
                dwtmp->path = talloc_asprintf(dwtmp, "%s/%s", dw->path, tmp);
            talloc_free(tmp);
            list_move(&dwtmp->list, &self->walklist->list);

        } else {
            /* place into filelist */
             if((self->myflags & SK_FLAG_INODES) && (self->myflags & SK_FLAG_NAMES))
                PyList_Append(filelist, Py_BuildValue("(Ks)", dwtmp->inode, dwtmp->path));
            else if(self->myflags & SK_FLAG_INODES)
                PyList_Append(filelist, PyLong_FromUnsignedLongLong(dwtmp->inode));
            else if(self->myflags & SK_FLAG_NAMES)
                PyList_Append(filelist, PyString_FromString(dwtmp->path));
        }
    }

    if((self->myflags & SK_FLAG_INODES) && (self->myflags & SK_FLAG_NAMES))
        root = Py_BuildValue("(Ks)", dw->inode, dw->path);
    else if(self->myflags & SK_FLAG_INODES)
        root = PyLong_FromUnsignedLongLong(dw->inode);
    else if(self->myflags & SK_FLAG_NAMES)
        root = PyString_FromString(dw->path);
    else {
        Py_INCREF(Py_None);
        root = Py_None;
    }

    result = Py_BuildValue("(NNN)", root, dirlist, filelist);

    /* now delete this entry from the stack */
    list_del(&dw->list);
    talloc_free(dw);
    talloc_free(dwlist);

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
    int flags;

    static char *kwlist[] = {"filesystem", "path", "inode", "type", "id", NULL};

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "O|sKii", kwlist, 
                                    &skfs_obj, &filename, &inode, &type, &id))
        return -1; 

    /* check the type of the filesystem object */
    if(PyObject_TypeCheck(skfs_obj, &skfsType) == 0) {
        PyErr_Format(PyExc_TypeError, "filesystem is not an skfs instance");
        return -1;
    }

    fs = ((skfs *)skfs_obj)->fs;

    /* must specify either inode or filename */
    if(filename==NULL && inode == 0) {
        PyErr_Format(PyExc_SyntaxError, "One of filename or inode must be specified");
        return -1;
    };

    if(filename) {
        tsk_error_reset();
        inode = lookup_inode(fs, filename);
        if(inode == 0) {
            PyErr_Format(PyExc_IOError, "Unable to find inode for file %s: %s", filename, tsk_error_str());
            return -1;
        };
    };

    /* can we lookup this inode? */
    tsk_error_reset();
    self->fs_inode = fs->inode_lookup(fs, inode);
    if(self->fs_inode == NULL) {
        PyErr_Format(PyExc_IOError, "Unable to find inode: %s", tsk_error_str());
        return -1;
    };

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

    flags = FS_FLAG_FILE_AONLY | FS_FLAG_FILE_RECOVER | FS_FLAG_FILE_NOSPARSE;
    if(id == 0)
        flags |= FS_FLAG_FILE_NOID;

    self->blocks = talloc(NULL, struct block);
    INIT_LIST_HEAD(&self->blocks->list);
    tsk_error_reset();
    fs->file_walk(fs, self->fs_inode, type, id, flags,
                 (FS_FILE_WALK_FN) getblocks_walk_callback, (void *)self);
    if(tsk_errno) {
        PyErr_Format(PyExc_IOError, "Error reading inode: %s", tsk_error_str());
        return -1;
    };

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
        return PyErr_Format(PyExc_MemoryError, "Out of Memory allocating read buffer.");

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
            return PyErr_Format(PyExc_IOError, "Invalid argument (whence): %d", whence);
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
