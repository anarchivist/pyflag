//#include "class.h"
#include <Python.h>
#include "class.h"
#include "trie.h"

static PyObject *add_word(PyObject *self, PyObject *args) {
  int type;
  int value;
  char *word;
  PyObject *pyroot;
  RootNode root;
  int length;

  if(!PyArg_ParseTuple(args, "Os#ii", &pyroot, &word, &length, &value, &type)) 
    return NULL;

  root = PyCObject_AsVoidPtr(pyroot);
  if(!root) 
    return PyErr_Format(PyExc_RuntimeError, "This is not a valid trie node");

  root->super.AddWord((TrieNode)root, word, length,value,type);

  Py_INCREF(Py_None);
  return Py_None;
};

static PyObject *index_buffer(PyObject *self, PyObject *args) {
  char *buffer;
  int length;
  PyObject *pyroot;
  RootNode root;
  unsigned int value;
  int i;
  PyObject *result;

  if(!PyArg_ParseTuple(args, "Os#", &pyroot, &buffer, &length)) 
    return NULL;

  root = PyCObject_AsVoidPtr(pyroot);
  if(!root) 
    return PyErr_Format(PyExc_RuntimeError, "This is not a valid trie node");

  result = PyList_New(0);
  for(i=0; i<length; i++) {
    if(root->super.Match((TrieNode)root, buffer+i, length-i, &value)) {
      PyObject *temp = Py_BuildValue("ii", value, i);

      printf("%u->%u\n",  i, value);
      if(!temp) return NULL;

      /** Append temp to the result */
      if(PyList_Append(result, temp)<0) return NULL;
    };
  };

  return(result);
};

static PyObject *indexer(PyObject *self, PyObject *args) {
  RootNode r = CONSTRUCT(RootNode, RootNode, Con, NULL);

  /** Return an opaque handle to the trie */
  return PyCObject_FromVoidPtr(r, (void (*)(void *))talloc_free);
};

static PyMethodDef IndexMethods[] = {
  { "add_word", add_word, METH_VARARGS,
    "Adds a new word to the trie"},
  { "index_buffer", index_buffer, METH_VARARGS,
    "Indexes the buffer returning an array of hits"},
  {"indexer", indexer, METH_VARARGS,
   "Initialises the indexing library returning a trie handle"},
  {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC initindex(void) {
  (void) Py_InitModule("index", IndexMethods);
}

