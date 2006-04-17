/***  This provides python bindings to libnids.

We use libnids to perform our stream reassembly.
***/
#include <Python.h>
#include "class.h"
#include "packet.h"
#include "tcp.h"

#define int_ntoa(x)     inet_ntoa(*((struct in_addr *)&x))

/** This is the callable we will call when we have a completed
    stream 
*/
static PyObject *python_cb=NULL;
static int con_id = 0;

/** These get filled in from py_process_tcp */
static int packet_id;

PyObject *New_Stream_Dict(struct tcp_stream *a_tcp) {
  PyObject *stream = PyDict_New();
  
  if(!stream) return NULL;
  
  /** Store important information about the connection here: */
  if(PyDict_SetItem(stream, PyString_FromString("packets"), PyList_New(0))<0)
    return NULL;

    if(PyDict_SetItem(stream, PyString_FromString("seq"), PyList_New(0))<0)
      return NULL;

    if(PyDict_SetItem(stream, PyString_FromString("length"), PyList_New(0))<0)
      return NULL;

    if(PyDict_SetItem(stream, PyString_FromString("data_offset"), PyList_New(0))<0)
      return NULL;

    if(PyDict_SetItem(stream, PyString_FromString("isn"), PyInt_FromLong(0))<0)
      return NULL;

    if(PyDict_SetItem(stream, PyString_FromString("con_id"), PyInt_FromLong(con_id))<0)
      return NULL;

    con_id++;

    if(PyDict_SetItem(stream, PyString_FromString("src_ip"), PyInt_FromLong(int_ntoa(a_tcp->addr.saddr)))<0)
      return NULL;

    if(PyDict_SetItem(stream, PyString_FromString("src_port"), PyInt_FromLong((a_tcp->addr.source)))<0)
      return NULL;

    if(PyDict_SetItem(stream, PyString_FromString("dest_ip"), PyInt_FromLong(int_ntoa(a_tcp->addr.daddr)))<0)
      return NULL;

    if(PyDict_SetItem(stream, PyString_FromString("dest_port"), PyInt_FromLong((a_tcp->addr.dest)))<0)
      return NULL;

    return stream;
};

/** This adds another packet to the stream object */
int add_packet(PyObject *stream, struct half_stream *hlf) {
  if(PyList_Append(PyDict_GetItem(stream,PyString_FromString("packets")),PyInt_FromLong(packet_id)))
    return 0;

  if(PyList_Append(PyDict_GetItem(stream,PyString_FromString("seq")),PyInt_FromLong(hlf->seq)))
    return 0;

  if(PyList_Append(PyDict_GetItem(stream,PyString_FromString("length")),PyInt_FromLong(hlf->count)))
    return 0;
 
  return 1;
};

PyObject *py_process_tcp(PyObject *self, PyObject *args) {
  char *data;
  int len;
  int link_type;

  if(!PyArg_ParseTuple(args, "s#II",  &data, &len, &packet_id, &link_type)) 
    return NULL;

  printf("Processing packet %u\n", packet_id);
  if(packet_id==8)
    printf("got 8\n");

  process_tcp(data,len);

  /** Currently there is no way for us to know if the callback
      generated an error (since the callback returns void). So here we
      check the exception state of the interpreter explicitely 
  */
  if(PyErr_Occurred()) return NULL;

  Py_INCREF(Py_None);
  return Py_None;
};

PyObject *py_clear_stream_buffers(PyObject *self, PyObject *args) {
  clear_stream_buffers();

  Py_INCREF(Py_None);
  return Py_None;
};

PyObject *set_tcp_callback(PyObject *self, PyObject *args) {
  PyObject *cb;

  if(!PyArg_ParseTuple(args, "O",  &cb)) 
    return NULL;

  if(!PyCallable_Check(cb) && cb!=Py_None)
    return PyErr_Format(PyExc_RuntimeError, "Callback must be callable");
  
  if(python_cb) {
    Py_DECREF(python_cb);
  };

  python_cb = cb;
  Py_INCREF(cb);

  Py_INCREF(Py_None);
  return Py_None;
};

static PyMethodDef NIDSMethods[] = {
  {"process_tcp",  py_process_tcp, METH_VARARGS,
   "Process a tcp packet"},
  {"clear_stream_buffers", py_clear_stream_buffers, METH_VARARGS,
   "Clears all the stream buffers."},
  {"set_tcp_callback", set_tcp_callback, METH_VARARGS,
   "Sets the callback for the TCP streams"},
  /*  {"get_name", get_name, METH_VARARGS,
   "Returns the name of the current node"},
  {"get_range", get_range, METH_VARARGS,
   "Returns the start of an element in the node"},
  */
  {NULL, NULL, 0, NULL}
};

PyObject *proxy(PyObject *self, void *stream) {
  return PyObject_CallFunction(self, "O", stream);
};

void
tcp_callback (struct tcp_stream *a_tcp, void **stream_obj)
{
  PyObject *stream = (PyObject *)*stream_obj;

  if(a_tcp->nids_state == NIDS_JUST_EST) {
    a_tcp->client.collect++; // we want data received by a client
    a_tcp->server.collect++; // and by a server, too

    /** We initialise the python object to collect information about
	this stream 
    */
    *stream_obj = PyList_New(2);
    if(!*stream_obj) return;

    stream=*stream_obj;

    /** The forward stream represents data going from source to destination */
    if(PyList_SetItem(stream, 0,  New_Stream_Dict(a_tcp))<0)
      return;
    
    if(PyList_SetItem(stream, 1,  New_Stream_Dict(a_tcp))<0)
      return;

  } else if(a_tcp->nids_state == NIDS_DATA) {
    struct half_stream *hlf;
    PyObject *half_stream;

    if (a_tcp->client.count_new)   {
      // new data for the client
      hlf = &a_tcp->client; // from now on, we will deal with hlf var,
      half_stream = PyList_GetItem(stream, 0);
    } else {
      hlf = &a_tcp->server; // analogical
      half_stream = PyList_GetItem(stream, 1);
    };
    
    if(!add_packet(half_stream, hlf))
      return;

    if(PyDict_SetItem(half_stream, PyString_FromString("data"), PyString_FromStringAndSize(hlf->data, hlf->count_new))<0)
      return;    

    /*
    if(!PyObject_CallFunction(python_cb, "O",stream)) {
      return;
    };
    */ 

    //write(1,hlf->data,hlf->count_new); // we print the newly arrived data
  } else if(a_tcp->nids_state == NIDS_CLOSE || a_tcp->nids_state == NIDS_RESET || 
	    a_tcp->nids_state == NIDS_EXITING) {
    /** Handle the stream */
    if(python_cb) {
      printf("Got %u for stream\n", a_tcp->nids_state);      
      if(!proxy(python_cb, stream)) {
	//      if(!PyObject_CallFunction(python_cb, "O",stream)) {
	return;
      };
    };
  } else {
    printf("nids_state %u\n", a_tcp->nids_state);
  };
};

static void nids_syslog (int type, int errnum, struct ip *iph, void *data) {
  char *message=NULL;
  struct host *this_host;
  unsigned char flagsand = 255, flagsor = 0;
  int i;
  
  switch (type) {
    
  case NIDS_WARN_IP:
    if (errnum != NIDS_WARN_IP_HDR) {

      message = talloc_asprintf(NULL, "%s, packet (apparently) from ",
				nids_warnings[errnum]);
      
      message = talloc_asprintf_append(message, "%s to ", int_ntoa(iph->ip_src.s_addr));
      message = talloc_asprintf_append(message, "%s", int_ntoa(iph->ip_dst.s_addr));
      
      goto send_message;
    } else {
      message = talloc_asprintf(NULL, "%s\n", nids_warnings[errnum]);

      goto send_message;
    };
    
  case NIDS_WARN_TCP:
    if (errnum != NIDS_WARN_TCP_HDR) {
      message = talloc_asprintf(NULL, "%s, from ", nids_warnings[errnum]);
      message = talloc_asprintf_append(message, "%s:%hu to ", int_ntoa(iph->ip_src.s_addr),
				       ntohs(((struct tcphdr *) data)->source));
      message = talloc_asprintf_append(message, "%s:%hu ", int_ntoa(iph->ip_dst.s_addr),
				       ntohs(((struct tcphdr *) data)->dest));
      
      goto send_message;
    } else {
      message = talloc_asprintf(NULL, "%s, from ", nids_warnings[errnum]);
      message = talloc_asprintf_append(message, "%s to ", int_ntoa(iph->ip_src.s_addr));
      message = talloc_asprintf_append(message, "%s ", int_ntoa(iph->ip_dst.s_addr));
      
      goto send_message;
    };
  default: 
    message = talloc_asprintf(NULL, "Unknown warning number ? %u\n",
			      errnum);
    
    goto send_message;
  }

 send_message:
  printf("%s\n",message);
  talloc_free(message);
};

/** We need to make libnids skip checksum tests on all hosts because
    sometimes there are incorrect 
*/
static struct nids_chksum_ctl checksum ={ 0, 0, NIDS_DONT_CHKSUM };

PyMODINIT_FUNC initlibnids(void) {
  (void) Py_InitModule("libnids", NIDSMethods);

  init_procs();
  tcp_init(nids_params.n_tcp_streams);
  ip_frag_init(nids_params.n_hosts);
  scan_init();
   
  nids_register_chksum_ctl(&checksum, 1);

  nids_params.syslog = nids_syslog;

   nids_register_tcp (tcp_callback);
};
