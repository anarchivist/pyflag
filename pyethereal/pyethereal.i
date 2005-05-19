/*
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.75 Date: Sat Feb 12 14:00:04 EST 2005$
# ******************************************************
#
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# *
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
# ******************************************************
*/
%module pyethereal
%include exception.i

%{
#include "config.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <locale.h>
#include <limits.h>

#include <unistd.h>
#include "wtap.h"
#include "register.h"
#include "epan/epan_dissect.h"
#include "epan/packet.h"

static void
ethereal_fill_in_fdata(frame_data *fdata, int count,
	const struct wtap_pkthdr *phdr, long offset)
{
  fdata->next = NULL;
  fdata->prev = NULL;
  fdata->pfd = NULL;
  fdata->num = count;
  fdata->pkt_len = phdr->len;
  fdata->cap_len = phdr->caplen;
  fdata->file_off = offset;
  fdata->lnk_t = phdr->pkt_encap;
  fdata->abs_secs  = phdr->ts.tv_sec;
  fdata->abs_usecs = phdr->ts.tv_usec;
  fdata->flags.passed_dfilter = 0;
  fdata->flags.visited = 0;
  fdata->flags.marked = 0;
  fdata->flags.ref_time = 0;
}

static int is_initialised=0;

static void ethereal_init() {
  /* Initialise the main ethereal core */
  epan_init(PLUGIN_DIR,register_all_protocols,register_all_protocol_handoffs,
            NULL,NULL,NULL);

  /* init the dissectors data structures */
  init_dissection();
  is_initialised=1;
};

wtap *open_file(char *filename) {
  wtap  *wth;
  int err=0;
  gchar *err_info;

  //Ensure that ethereal is initialised before we try to use it:
  if(!is_initialised) ethereal_init();

  // Open the capture file for reading
  wth = wtap_open_offline(filename, &err, &err_info, FALSE);
  return wth;
};

void free_dissection(epan_dissect_t *edt) {
  if(edt)
    epan_dissect_free(edt);
};

//Pulls the next packet off the file and dissects it.
epan_dissect_t *read_and_dissect_next_packet(wtap *file) {
  int err=0;
  gchar *err_info;
  long data_offset=0;

  while(1) {
    struct wtap_pkthdr *hdr;
    epan_dissect_t *edt = epan_dissect_new(TRUE, TRUE);
    frame_data fd;
    guchar *pd;

    if(!wtap_read(file,&err,&err_info,&data_offset)) return NULL;
    hdr = wtap_phdr(file);
    pd=wtap_buf_ptr(file);

    ethereal_fill_in_fdata(&fd,0,hdr,data_offset);
    //Dissect the packet using the dissector chain. The protocol tree
    //is found in edt.
    dissect_packet(edt,wtap_pseudoheader(file), pd, &fd, NULL);
    return(edt);
  };
};

/*
char *dissector_node_get_value(epan_dissect_t *edt, char *name) {
  while(
};
*/

proto_node *get_first_node(epan_dissect_t *edt) {
  proto_node *node;

   if(!edt) return (NULL);
   node=edt->tree;
   return(node);
};

proto_node *get_next_peer_node(proto_node *node) {
  if(node) {
    return node->next;
  } else {
    return NULL;
  };
};

proto_node *get_child_node(proto_node *node) {
  if(node) {
    return node->first_child;
  } else {
    return NULL;
  };
};

/* This is a recursive function that looks for name in subtree of
   node. We return the found node in found */
gboolean _find_node_by_name(proto_node *node,char *name, proto_node **found) {
  if(!node) return 0;

  if(node->finfo) {
    if(!strcmp(node->finfo->hfinfo->abbrev,name)) { //Found it:
      *found = node;
      return 1;
    }
  };

  //Recurse to child first
  if(node->first_child &&  _find_node_by_name(node->first_child,name,found)) {
    return 1;
  };
  
  //Then to peers
  if(node->next &&  _find_node_by_name(node->next,name,found)) {
    return 1;
  };

  return 0;
};

proto_node *get_node_by_name(epan_dissect_t *edt,char *name) {
  proto_node *result=NULL;
  proto_node *node= edt->tree;
  
  _find_node_by_name(node,name,&result);
  return result;
};

struct field_info *get_field_info(proto_node *node) {
  return node->finfo;
};

char *get_node_rep(proto_node *node) {
  char *result;

  if(!node || !node->finfo) return("");
  result=node->finfo->rep->representation;

  //FIXME - This leaks.
  if(!result) {
    result=(char *)malloc(ITEM_LABEL_LENGTH);
    proto_item_fill_label(node->finfo, result);
  };
  return result;
};

char *get_node_name(proto_node *node){
    if(!node || !node->finfo) return("");

    return node->finfo->hfinfo->abbrev;
};

%}

%exception get_first_node {
  $action
    if(result<0) {
      SWIG_exception(SWIG_IOError,"Invalid Protocol Tree");
    };
}

%exception read_and_dissect_next_packet {
  $action
    if(result==0) {
      SWIG_exception(SWIG_IOError,"Unable to read packets");
    };
}

%exception open_file {
  $action
    if(result==0) {
      SWIG_exception(SWIG_IOError,"Cant open file\n");
    };
}

%pythoncode %{   
class Node:
   """ Node is a class which represents a node in the dissection tree """
   def __init__(self,node):
       """ This base class is instantiated with a swig proto_node
       object, derived classes should get new ways for getting such an
       opaque object"""
       if not node:
           raise IOError("Invalid Node provided")
       self.node=node

   def get_child(self):
       """ Returns the first child of this node as another Node
       object. If we do not have children we return None."""
       result = get_child_node(self.node)
       if not result: return None
       return Node(result)
   
   def __str__(self):
       """ We return Ethereals representation (The text which is printed in the GUI """
       return get_node_rep(self.node)

   def __iter__(self):
       """ We can iterate over all the peers of this node """
       self.current_iter = self.node
       return self

   def next(self):
       if self.current_iter:
           result=Node(self.current_iter)
           self.current_iter = get_next_peer_node(self.current_iter)
           return result
       else:
           raise StopIteration()

   def name(self):
       """ This is the abbrev of this node's field name. """
       return get_node_name(self.node)

class ReadPacket(Node):
    def __init__(self,file):
        """ Gets the next packet from the file.
        
        Note that file must be a wtap object obtained from open_file.
        """
        self.dissector = read_and_dissect_next_packet(file)
        Node.__init__(self,get_first_node(self.dissector))

    def __getitem__(self,name):
       """ We can get a node by using its abbreviation. Note that this
       search is recursive so we can ask the root of the tree if there
       is a certain node in the tree.

       We raise a KeyError exception if we cant find such a node.
       """
       result = get_node_by_name(self.dissector,name)
       if not result:
           raise KeyError("Uable to find node %s" % name)

       return Node(result)
   
    def __del__(self):
        """ Free memory as required """
        free_dissection(self.dissector)

%}

proto_node *get_first_node(epan_dissect_t *edt);
wtap *open_file(char *filename);
epan_dissect_t *read_and_dissect_next_packet(wtap *file);

void free_dissection(epan_dissect_t *edt);
proto_node *get_node_by_name(epan_dissect_t *edt,char *name);
struct field_info *get_field_info(proto_node *node);

proto_node *get_child_node(proto_node *node);
proto_node *get_next_peer_node(proto_node *node);
char *get_node_rep(proto_node *node);
char *get_node_name(proto_node *node);
