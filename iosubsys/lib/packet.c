#include "talloc.h"
#include <string.h>
#include "packet.h"
#include "misc.h"
#include <ctype.h>

#ifndef WINDOWS
#include <netinet/in.h>
#endif

/*************************************************** 
               Packet implementation
****************************************************/
Packet Packet_Con(Packet self) {

  /** adjust struct_p to point at the new allocated memory, which must
      be in the class body of derived classes. This is achieved
      through the INIT_STRUCT macro: 
  */
  self->struct_p = (void *)((char *)self + (unsigned long)(self->struct_p));

  return self;
};

int Packet_Write(Packet self, StringIO output) {
  return pack(self->format, self->struct_p, output);
};

int Packet_Read(Packet self, StringIO input) {
  int result;

  /** Store the position in the input stream before we start reading
      it 
  */
  self->start = input->readptr;

  result=unpack(self, self->format, input, self->struct_p);
  //  if(result==-1) DEBUG("Cant read packet %s\n",NAMEOF(self));
  return result;
};

static void Packet_destroy(Packet self) {
  talloc_free(self);
};

/*******************************************************
    This code looks for the node property by name. We traverse all
    children of this node looking for it too.
********************************************************/
struct struct_property_t *get_field_by_name(Packet self, char *name) { 
  struct struct_property_t *i;

  list_for_each_entry(i, &(self->properties.list), list) {
    if(!i->name) break;
    if(!strcmp(i->name, name)) {
      i=talloc_memdup(self, i, sizeof(*i));
      return i;
    };
  };

  return NULL;
};

/** This tries to find the node_name.property_name combination under
    *node. If found, we return a pointer to the node in *node, and a
    pointer to the relevant property in property. We then return
    True. If we cant find it we return False.
*/
int Find_Property(OUT Packet *node, OUT struct struct_property_t **p,
		  char *node_name, char *property_name) 
{
  struct struct_property_t *i;
  
  if(!strcasecmp(NAMEOF(*node) , node_name)) {

    /** Now search for the property_name in that node */
    *p=get_field_by_name(*node, property_name);

    if(!*p) {
      //  DEBUG("Unable to find property %s in node %s\n", property_name, node_name);
      return False;
    };

    return True;

  } else {
 
    /** Try and find the node with the name node_name */
    list_for_each_entry(i, &((*node)->properties.list), list) {
      void *item = *(void **) ((char *)((*node)->struct_p) + i->item);

      if(i->name == NULL) break;

      if(i->field_type == FIELD_TYPE_PACKET && item) {
	*node = (Packet)item;

	/** This field is another node, search it: */
	if(Find_Property(node,p , node_name, property_name))
	  return True;
      };
    };
   
    /** Could not find node under this tree */
    return False;
  };
};

static void Packet_print(Packet self, char *element) {
  char *e=talloc_strdup(self, element);
  char *property;
  struct struct_property_t *p;

  for(property=e; *property; property++) 
    if(*property=='.') {
      *property=0;
      property++;
      break;
    };

  if(Find_Property(&self, &p, e, property)) {
    printf("%s = ", element);
    print_property(self, p);

  };// else DEBUG("Unable to find %s\n", element);

  talloc_free(e);
};

VIRTUAL(Packet, Object)
     VMETHOD(Con) = Packet_Con;
     VMETHOD(Read) = Packet_Read;
     VMETHOD(Write) = Packet_Write;
     VMETHOD(destroy) = Packet_destroy;
     VMETHOD(print) = Packet_print;
END_VIRTUAL

/***************************************
   Some utility functions
*****************************************/
void print_property(Packet self, struct struct_property_t *i) {
  void *item = (void *) ((char *)(self->struct_p) + i->item);
  int size=0;

  if(!i->size) {
    size = *(int *)((char *)(self->struct_p) + i->size_p);
  } else 
    size=i->size;

  switch(i->field_type) {
  case FIELD_TYPE_INT:
    printf("%u", *(unsigned int *)item); break;

  case FIELD_TYPE_INT_X:
    printf("0x%X", *(unsigned int *)item); break;

  case FIELD_TYPE_CHAR:
    printf("%u", *(unsigned char *)item); break;

  case FIELD_TYPE_CHAR_X:
    printf("0x%x", *(unsigned char *)item); break;

  case FIELD_TYPE_SHORT:
    printf("%u", *(uint16_t *)item); break;

  case FIELD_TYPE_SHORT_X:
    printf("0x%x", *(uint16_t *)item); break;

  case FIELD_TYPE_IP_ADDR:
    {
      struct in_addr foo;
      
      foo.s_addr = htonl(*(int *)item);
      printf("%s", inet_ntoa(foo)); break;
    };

  case FIELD_TYPE_STRING:
    {
      int j;
      
      for(j=0; j < size; j++) {
	unsigned char *x = (*(unsigned char **)item)+j;
	if(isprint(*x)){
	  printf("%c", *x);
	} else {
	  printf("\\x%02x", *x);
	};
      };
      break;
    };

  case FIELD_TYPE_STRING_X:
    {
      int j;

      printf("0x");
      for(j=0; j < size; j++) printf("%02x",*((unsigned char *)item+j));
      break;
    };

  default:
    /** Cant handle it */
    break;
  };
};
