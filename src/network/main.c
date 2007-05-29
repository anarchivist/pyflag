#include <stdio.h>
#include "struct.h"
#include <stdint.h>
#include "packet.h"
#include "misc.h"
#include "network.h"
#include <stdlib.h>
#include <fcntl.h>

/** Prints the entire contents of the tree */
void print_tree(Packet self) {
  struct struct_property_t *i;

  printf("listing node %s:\n", NAMEOF(self));

  list_for_each_entry(i, &(self->properties.list), list) {
    void *item = *(void **) ((char *)(self->struct_p) + i->item);

    if(i->name == NULL) break;

    if(i->field_type == FIELD_TYPE_PACKET && item) {
      print_tree((Packet)item);
    } else {
      printf("   %s = ", i->name);
      print_property(self,i);
      printf("\n");
    };

  };
};

int main(int argc, char **argv) {
  Root root;
  char buf[1500];
  StringIO input=CONSTRUCT(StringIO, StringIO, Con, NULL);
  int fd,len;

  if(argc<5) {
    printf("usage %s filename offset length link_type\n", argv[0]);
    exit(-1);
  };

  fd=open(argv[1], O_RDONLY);
  lseek(fd, atol(argv[2]),SEEK_SET);
  len=read(fd, buf, atol(argv[3]));
  close(fd);

  CALL(input, write, buf,len );
  CALL(input, seek, 0, SEEK_SET);

#include "init.c"

  root=CONSTRUCT(Root, Packet, super.Con, NULL);
  root->link_type = atol(argv[4]);
  root->super.Read((Packet)root, input);

  print_tree((Packet)root);

  root->super.print((Packet)root, "tcp.src_port");

  printf("\n");

  return 0;
};
