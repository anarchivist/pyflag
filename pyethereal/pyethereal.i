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

void proto_tree_print_node(proto_node *node, gpointer data)
{
  gchar *label_ptr;
  gchar label_str[ITEM_LABEL_LENGTH];
	
  if(node->finfo->rep) {
    label_ptr = node->finfo->rep->representation;
  } else {
    label_ptr=label_str;
    proto_item_fill_label(node->finfo, label_str);
  };
  printf("Item %s(%s) \"%s\"\n",node->finfo->hfinfo->name,node->finfo->hfinfo->abbrev,label_ptr);
};

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

proto_node *ethereal_tree_next_node(proto_node *node) 
{
  if(!node) return(NULL);

  //If this is a blank node, we skip it...
  if(!node->finfo) return(ethereal_tree_next_node(node->first_child));

  if(!node->next) {
    return node->first_child;
  } else {
    return node->next;
  };
};

proto_node *get_first_node(epan_dissect_t *edt) {
  proto_node *node;

   if(!edt || !node) return (NULL);
   node=edt->tree;
   return(node);
};

 int print_tree_node(proto_node *node) {
   int data=0;
   
   node = node->first_child;
   while (node != NULL) {
     proto_tree_print_node(node, NULL);
     print_tree_node(node);
     node = node->next;
   }
   return 0;
 };

 int print_tree(epan_dissect_t *edt) {
   int data=0;
   proto_node *node=get_first_node(edt);

   // if(!edt || !node) return (-1);

   do {
     if(node && node->finfo)
       proto_tree_print_node(node, NULL);
   } while(node=ethereal_tree_next_node(node));
 }

/*
int main(int argc, char **argv) 
{
  wtap  *wth;
  char *fname="/tmp/test.pcap";
  epan_dissect_t *edt;
  int data=0;

  ethereal_init();
  wth = open_file(fname);
  
  while(edt=read_and_dissect_next_packet(wth)) {
    proto_tree_children_foreach(edt->tree, proto_tree_print_node, &data);
    free(edt);
  };

};
  					  
int main(int argc, char **argv ) {
  wtap  *wth;
  char *table="pcap";
  int err=0;
  gchar *err_info;
  char err_msg[2048+1];
  char *fname="/tmp/test.pcap";
  long data_offset;
  int id=0;
  int data=0;

  // Initialise the main ethereal core
  epan_init(PLUGIN_DIR,register_all_protocols,register_all_protocol_handoffs,
            NULL,NULL,NULL);

  // init the dissectors data structures
  init_dissection();

  // Open the capture file for reading
  wth = wtap_open_offline(fname, &err, &err_info, FALSE);

  //Read a packet at the time
  while(wtap_read(wth,&err,&err_info,&data_offset)) {
    struct wtap_pkthdr *hdr = wtap_phdr(wth);
    epan_dissect_t *edt = epan_dissect_new(TRUE, TRUE);
    //This gives a pointer to the contents of the file
    guchar *pd=wtap_buf_ptr(wth);
    frame_data fd;

    fill_in_fdata(&fd,id,hdr,data_offset);

    //Dissect the packet using the dissector chain. The protocol tree
    //is found in edt.
    dissect_packet(edt,wtap_pseudoheader(wth), pd, &fd, NULL);

    proto_tree_children_foreach(edt->tree, proto_tree_print_node, &data);

    printf("insert into %s set id='%lu',offset='%lu',length='%lu';\n",table,id,data_offset,hdr->caplen);
    id++;

    epan_dissect_free(edt);
  };  
};
*/
%}

%exception print_tree {
  $action
    if(result<0) {
      SWIG_exception(SWIG_IOError,"Invalid Protocol Tree");
    };
}

%exception get_first_node {
  $action
    if(result<0) {
      SWIG_exception(SWIG_IOError,"Invalid Protocol Tree");
    };
}

proto_node *ethereal_tree_next_node(proto_node *node);
void proto_tree_print_node(proto_node *node, gpointer data);
proto_node *get_first_node(epan_dissect_t *edt);
wtap *open_file(char *filename);
epan_dissect_t *read_and_dissect_next_packet(wtap *file);
int print_tree(epan_dissect_t *tree);
