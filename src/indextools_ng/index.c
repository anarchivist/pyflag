//#include "class.h"
#include <Python.h>
#include "class.h"
#include "trie.h"

static PyObject *test(PyObject *self, PyObject *args) {
  char *t="hello";
  uint64_t data = 5;

  RootNode r = CONSTRUCT(RootNode, RootNode, Con, NULL);

  r->super.AddWord((TrieNode)r, t+1, strlen(t)-1,data,0);
  printf("Testing...\n");

  

  Py_INCREF(Py_None);
  return(Py_None);
};

static PyMethodDef IndexMethods[] = {
  { "test", test, METH_VARARGS,
    "Tests the bindings"},
  {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC initindex(void) {
  talloc_enable_leak_report_full();

  printf("Starting index\n");
  (void) Py_InitModule("index", IndexMethods);
}

