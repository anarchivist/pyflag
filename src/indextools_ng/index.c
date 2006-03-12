//#include "class.h"
#include <Python.h>
#include "class.h"
#include "trie.h"

static PyObject *test(PyObject *self, PyObject *args) {
  char *t="hello";
  char *t2="hero";
  uint64_t data = 5;
  uint64_t result = 0;
  char *test="aheroic test";

  RootNode r = CONSTRUCT(RootNode, RootNode, Con, NULL);

  r->super.AddWord((TrieNode)r, t, strlen(t),data,0);
  r->super.AddWord((TrieNode)r, t2, strlen(t2),data,0);
  printf("Testing...\n");

  if(r->super.Match((TrieNode)r, test, strlen(test), &result))
    printf("Matched %s - returned %llu\n", test, result);

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

