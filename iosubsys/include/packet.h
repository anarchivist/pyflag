/*****************************************
    This file implements classes for serialising and unserialising
    data structures from the network in the form of packets.

    NOTE!!!!  - You must initialise the struct in the derived
    classes's VIRTUAL section, and assign a format specifier. eg:

    In .h file:

    struct something {
      uint32 a;
      char *string;
    };

    #define struct_something_format             \
           q(STRUCT_SHORT, STRUCT_SHORT)

    CLASS(TestPacket, Packet)
        struct something packet
    END_CLASS

    In .c file:
 
    VIRTUAL(TestPacket, Packet)
      INIT_STRUCT(packet, struct_something_format);
    END_VIRTUAL

    Now given a stringio input:

    TestPacket t = CONSTRUCT(TestPacket, Packet, super.Con, NULL);

    t->super.Read((Packet)t, input);

    And we can access elements of t:

    t->packet.a and
    t->packet.string

    Similarly we can write it into a stream (after assigning packet
    elements):

    t->packet.a = 5;
    t->super.Write((Packet)t, output);

****************************************/

#ifndef __PACKET_H
#define __PACKET_H

#include "misc.h"
#include "list.h"
#include <stdint.h>
#include "struct.h"

// these are defined as macros in windows and cause problems
#undef stdin
#undef stdout

#define MAXIMUM_PACKET_SIZE 32*1024

enum field_types {
  FIELD_TYPE_INT,
  FIELD_TYPE_INT_X,
  FIELD_TYPE_CHAR,
  FIELD_TYPE_CHAR_X,
  FIELD_TYPE_SHORT,
  FIELD_TYPE_SHORT_X,
  FIELD_TYPE_STRING,
  FIELD_TYPE_STRING_X,
  FIELD_TYPE_IP_ADDR,
  FIELD_TYPE_PACKET
};

struct struct_property_t {
  char *name;
  int field_type;
  
  /** This represents the number of bytes from the begining of the
      struct where this item may be found 
  */
  int item;

  int size;
  
  /** This is the offset of the size member - The member in the struct
      which contains the size. If size above is 0, we consult this to
      determine the size (this is useful in strings etc).
  */
  int size_p;
  struct list_head list;
};


CLASS(Packet,Object)
/** This is the format string describing the packet. See struct.h for
    a full description */
     char *format;

     /** This is the position in the stream where we start reading
	 from. It is filled in automatically by Read using
	 input->readptr.
     */
     int start;

     /** This is the list of all properties in string form so they can
	 be introspected
      */
     struct struct_property_t properties;

     /** This is a pointer to a struct which specified all the fields
	 described in the format string above. Normally you would
	 define the struct, include it in the derived class, and in
	 the constructor initialise this pointer to point to the
	 address of the derived class's struct. This way you can
	 always access the values on the fields, while the base class
	 can serialise and unserialise the data using this pointer 
     */
     void *struct_p;

     /** A constructor which sets out the packet */
     Packet METHOD(Packet,Con);

     /** Write our packet into the StringIO - return number of bytes
	 written. */
     int METHOD(Packet, Write, StringIO output);

     /** Read the packet from the StringIO - returns number of bytes
	 read. */
     int METHOD(Packet, Read, StringIO input);

     /** Locates and prints the value of the requested element. The
         element is a string of the format node_name.property, where
         node_name is the name of the node which might contain it, and
         the property must be defined with NAME_ACCESS in the VIRTUAL
         section. 
     */
     void METHOD(Packet, print, char *element);

     /** Destructor */
     void METHOD(Packet, destroy);
END_CLASS

#define INIT_STRUCT(struct_member_name, struct_format)				\
  ((Packet)this)->struct_p = (void *)((char *)&(this->struct_member_name) \
				      - (char *)(this));		\
  ((Packet)this)->format = struct_format;				\
  INIT_LIST_HEAD(&((Packet)this)->properties.list);

#define __NAME_ACCESS_start(struct_member_name, member, type)	\
  do {									\
    struct struct_property_t *p=talloc(NULL, struct struct_property_t);	\
    p->name=#member;							\
    p->field_type = type;						\
    p->item = (int)(&((typeof(this->struct_member_name) *)0)->member);	\
    p->size = sizeof(this->struct_member_name.member);			

#define __NAME_ACCESS_end(struct_member_name, member, type)		\
  list_add_tail(&(p->list), &((Packet)this)->properties.list);		\
  } while(0)

/** This macro enables access to a struct member by name - size if
    filled automatically from the size of the member
*/
#define NAME_ACCESS(struct_member_name, member, type)	\
  __NAME_ACCESS_start(struct_member_name, member, type);		\
  p->size = sizeof(this->struct_member_name.member);			\
  __NAME_ACCESS_end(struct_member_name, member, type);		  

/** Here we explicitly fill in the size pointer */
#define NAME_ACCESS_SIZE(struct_member_name, member, type, size_member)	\
  __NAME_ACCESS_start(struct_member_name, member, type);		\
  p->size_p = (int)(&((typeof(this->struct_member_name) *)0)->size_member); \
  p->size = 0;								\
  __NAME_ACCESS_end(struct_member_name, member, type);		  
  
void print_property(Packet self, struct struct_property_t *i);
int Find_Property(OUT Packet *node, OUT struct struct_property_t **p,
		  char *node_name, char *property_name) ;

#endif
