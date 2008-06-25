//#include "class.h"
#include "trie.h"
#include <Python.h>
#include "structmember.h"

PyObject *g_index_module;

static void trie_index_dealloc(trie_index *self) {
  if(self->root) {
    talloc_free(self->root);
  };
  self->ob_type->tp_free((PyObject*)self);
}

static int trie_index_init(trie_index *self, PyObject *args, PyObject *kwds) {
  int all_matches = 1;
  int unique=0;
  static char *kwlist[] = {"unique",NULL};

  if(kwds && !PyArg_ParseTupleAndKeywords(args, kwds, "i", kwlist,
					  &unique))
    return -1;

  self->all_matches = all_matches;
  self->root = CONSTRUCT(RootNode, RootNode, Con, NULL);
  if(self->root==NULL)
    return -1;

  if(unique) {
    self->set = PySet_New(NULL);
    if(self->set == NULL) {
      talloc_free(self->root);
      return -1;
    };
  } else self->set = NULL;

  return 0;
}

static PyObject *trie_index_add_word(trie_index *self, PyObject *args) {
    int type;
    int value;
    char *word;
    int length;

    if(!PyArg_ParseTuple(args, "s#ii", &word, &length, &value, &type)) 
        return NULL;

    self->root->super.AddWord((TrieNode)self->root, &word, &length,value,type);

    Py_INCREF(Py_None);
    return Py_None;
};

static PyObject *trie_index_clear_set(trie_index *self, PyObject *args) {
  if(self->set) {
    PySet_Clear(self->set);
  } else 
    return PyErr_Format(PyExc_SystemError, "Indexer not running in unique mode");

  Py_RETURN_NONE;
};

static PyObject *trie_index_reject(trie_index *self, PyObject *args) {
  int key=0;

  if(!PyArg_ParseTuple(args, "i", &key)) 
    return NULL;

  if(!key) return PyErr_Format(PyExc_AttributeError, "You must specify a word id");

  if(self->set) {
    PyObject *pkey = PyLong_FromLong(key);
    PySet_Discard(self->set, pkey);
    
    Py_DECREF(pkey);
  } else
    return PyErr_Format(PyExc_SystemError, "Not running in unique mode");

  Py_RETURN_NONE;
};

static PyObject *name;
static PyObject *trie_index_index_buffer(trie_index *self, PyObject *args) {
  PyObject *data;
  PyObject *result;

  if(!PyArg_ParseTuple(args, "O", &data)) 
    return NULL;
  
  result = PyObject_CallMethodObjArgs(g_index_module, name,
				    data, self, NULL);

  return result;
}


static PyMethodDef trie_index_methods[] = {
    {"add_word", (PyCFunction)trie_index_add_word, METH_VARARGS,
     "Add a word to the trie" },
    {"index_buffer", (PyCFunction)trie_index_index_buffer, METH_KEYWORDS | METH_VARARGS,
     "index the given buffer" },
    {"clear_set", (PyCFunction)trie_index_clear_set, METH_VARARGS,
     "Clears the set cache. The indexer maintains a set of previously reported hits. When a new hit is found to a previously reported hit, we ignore it. This clears the set to allow us to report the same hits again. We primarily use this to ensure we only report one hit per inode. This function takes no arguments"},
    {"reject", (PyCFunction)trie_index_reject, METH_VARARGS,
     "rejects a hit reported by the indexer. This essentially clears that hit from the set and allows it to be re-reported later. We primarily use this to reduce false positives by applying a more complex regex over the results returned from the less compres regex in order to eliminate false positives."},
    {NULL}  /* Sentinel */
};

static PyTypeObject trie_indexType = {
  PyObject_HEAD_INIT(NULL)
  0,                         /* ob_size */
  "index.Index",             /* tp_name */
  sizeof(trie_index),        /* tp_basicsize */
  0,                         /* tp_itemsize */
  (destructor)trie_index_dealloc, /* tp_dealloc */
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
  "Indexer Object",          /* tp_doc */
  0,                         /* tp_traverse */
  0,                         /* tp_clear */
  0,                         /* tp_richcompare */
  0,                         /* tp_weaklistoffset */
  0,                         /* tp_iter */
  0,                         /* tp_iternext */
  trie_index_methods,        /* tp_methods */
  0,                         /* tp_members */
  0,                         /* tp_getset */
  0,                         /* tp_base */
  0,                         /* tp_dict */
  0,                         /* tp_descr_get */
  0,                         /* tp_descr_set */
  0,                         /* tp_dictoffset */
  (initproc)trie_index_init, /* tp_init */
  0,                         /* tp_alloc */
  0,                         /* tp_new */
};

static void trie_iter_dealloc(trie_iter *self) {
  Py_DECREF(self->trie);
  Py_DECREF(self->pydata);
  Py_DECREF(self->match_list);
  self->ob_type->tp_free((PyObject*)self);
};

static int trie_iter_init(trie_iter *self, PyObject *args, PyObject *kwds) {
  static char *kwlist[] = {"data", "trie", NULL};
  PyObject *pydata;
  trie_index *trie;

  if(!PyArg_ParseTupleAndKeywords(args, kwds, "OO", kwlist,
				  &pydata, &trie))
    return -1;

  PyString_AsStringAndSize(pydata, &self->data, &self->len);
  self->i = 0;
  self->pydata = pydata;
  Py_INCREF(pydata);

  Py_INCREF(trie);
  self->trie = trie;

  // Create a match list:
  self->match_list = PyList_New(0);

  return 0;
};

static PyObject *trie_iter_next(trie_iter *self) {
  PyObject *result;

  while(self->i < self->len) {
    char *new_buffer = self->data + self->i;
    int new_length = self->len - self->i;

    if(self->trie->root->super.Match((TrieNode)self->trie->root, new_buffer, 
				     &new_buffer, &new_length, self)) { 

      /** Append temp to the result. Note that match_list is given to
	  result. We create a new match_list for us to use */
      result = Py_BuildValue("iN", self->i, self->match_list);
      self->match_list = PyList_New(0);
      self->i++;
      return result;
    };
    self->i++;
  };

  return PyErr_Format(PyExc_StopIteration, "Done");
};

static PyMethodDef trie_iter_methods[] = {
    {NULL}  /* Sentinel */
};

static PyTypeObject trie_iter_Type = {
    PyObject_HEAD_INIT(NULL)
    0,                         /* ob_size */
    "index.iter",             /* tp_name */
    sizeof(trie_iter),        /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)trie_iter_dealloc, /* tp_dealloc */
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
    "Indexer Iterator",          /* tp_doc */
    0,	                       /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    PyObject_SelfIter,         /* tp_iter */
    trie_iter_next,            /* tp_iternext */
    trie_iter_methods,        /* tp_methods */
    0,                         /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)trie_iter_init, /* tp_init */
    0,                         /* tp_alloc */
    0,                         /* tp_new */
};

static PyMethodDef IndexMethods[] = {
    {NULL, NULL, 0, NULL}
};

#define SET_ENUM_CONSTANT(dict, name)   \
    PyDict_SetItemString(dict, #name, PyInt_FromLong(name))

PyMODINIT_FUNC initindex(void) {

    PyObject *d;
#ifdef __DEBUG_V_
    talloc_enable_leak_report_full();
#endif
    name = PyString_FromString("iter");
    g_index_module = Py_InitModule("index", IndexMethods);
    d = PyModule_GetDict(g_index_module);

    SET_ENUM_CONSTANT(d, WORD_ENGLISH);
    SET_ENUM_CONSTANT(d, WORD_LITERAL);
    SET_ENUM_CONSTANT(d, WORD_EXTENDED);

    trie_indexType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&trie_indexType) < 0)
        return;

    trie_iter_Type.tp_new = PyType_GenericNew;
    if (PyType_Ready(&trie_iter_Type) < 0)
        return;

    Py_INCREF(&trie_indexType);
    PyModule_AddObject(g_index_module, "Index", (PyObject *)&trie_indexType);

    Py_INCREF(&trie_iter_Type);
    PyModule_AddObject(g_index_module, "iter", (PyObject *)&trie_iter_Type);
}
