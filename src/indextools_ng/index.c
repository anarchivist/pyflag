//#include "class.h"
#include "trie.h"
#include <Python.h>
#include "structmember.h"

PyObject *g_index_module;

typedef struct {
  PyObject_HEAD
  RootNode root;
  // A bool to signify if we should get all matches or just the first
  // one.
  int all_matches;
} trie_index;

// The indexer returns an iterator of all the matches:
typedef struct {
  PyObject_HEAD
  trie_index *trie;
  PyObject *pydata;
  char *data;
  int len;
  int i;
} trie_iter;

static void trie_index_dealloc(trie_index *self) {
  if(self->root) {
    talloc_free(self->root);
  };
  self->ob_type->tp_free((PyObject*)self);
}

static int trie_index_init(trie_index *self, PyObject *args, PyObject *kwds) {
  int all_matches = 1;
  static char *kwlist[] = {"all",NULL};

  if(kwds && !PyArg_ParseTupleAndKeywords(args, kwds, "i", kwlist,
					  &all_matches))
    return -1;

  self->all_matches = all_matches;
  self->root = CONSTRUCT(RootNode, RootNode, Con, NULL);

  if(self->root==NULL)
    return -1;

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

static PyObject *trie_index_index_xbuffer(trie_index *self, PyObject *args) {
    char *buffer;
    int length;
    int i;
    PyObject *result, *match_list;

    if(!PyArg_ParseTuple(args, "s#", &buffer, &length)) 
        return NULL;

    result = PyList_New(0);
    match_list = PyList_New(0);

    for(i=0; i<length; i++) {
        char *new_buffer = buffer+i;
        int new_length = length-i;
        PyObject *tmp;

        if(self->root->super.Match((TrieNode)self->root, new_buffer, 
		                            &new_buffer, &new_length, match_list)) {

            /** Append temp to the result. Note that match_list is given to tmp */
            tmp = Py_BuildValue("iN",i,match_list);
            if(PyList_Append(result, tmp)<0) {
	            Py_DECREF(tmp);
	            Py_DECREF(result);
	            return NULL;
            }

	    // If we only need one match we just skip this in the
	    // buffer:
	    if(self->all_matches == 0) {
	      // FIXME- get the longest match - now we get the first match
	      PyObject *first_match = PyList_GetItem(match_list, 0);
	      PyObject *length_obj;
	      if(first_match) {
		length_obj = PyTuple_GetItem(first_match, 1);
		if(length_obj) i+=PyLong_AsLong(length_obj);
	      };
	    };

            Py_DECREF(tmp);

            // Make a new match_list
            match_list=PyList_New(0);
        }
    }

    Py_DECREF(match_list);
    return(result);
}

static PyObject *trie_index_index_buffer(trie_index *self, PyObject *args) {
  PyObject *data;
  
  if(!PyArg_ParseTuple(args, "O", &data)) 
    return NULL;
  
  return PyObject_CallMethod(g_index_module, "iter", "OO",
			     data, self);
}


static PyMethodDef trie_index_methods[] = {
    {"add_word", (PyCFunction)trie_index_add_word, METH_VARARGS,
     "Add a word to the trie" },
    {"index_buffer", (PyCFunction)trie_index_index_buffer, METH_KEYWORDS | METH_VARARGS,
     "index the given buffer" },
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
  return 0;
};

static PyObject *trie_iter_next(trie_iter *self) {
  PyObject *match_list;
  PyObject *result;

  while(self->i < self->len) {
    char *new_buffer = self->data + self->i;
    int new_length = self->len - self->i;

    match_list = PyList_New(0);
    if(self->trie->root->super.Match((TrieNode)self->trie->root, new_buffer, 
				     &new_buffer, &new_length, match_list)) { 
      /** Append temp to the result. Note that match_list is given to tmp */
      result = Py_BuildValue("iN", self->i, match_list);
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
