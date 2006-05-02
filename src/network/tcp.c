/************************************************************
    This file implements a stream reassembler for use with
    pyflag.
*************************************************************/
#include "tcp.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static int con_id=0;

TCPStream TCPStream_Con(TCPStream self, struct tuple4 *addr) {
  memcpy(&self->addr, addr, sizeof(*addr));

  INIT_LIST_HEAD(&(self->list));

  self->con_id = con_id;
  con_id++;

  INIT_LIST_HEAD(&(self->queue.list));

  return self;
};

void TCPStream_add(TCPStream self, IP ip) {
  struct skbuff *new = talloc(self, struct skbuff);
  struct skbuff *i;
  TCP tcp=(TCP)ip->packet.payload;

  /** This is the location after which we insert the new structure */
  struct list_head *candidate = &(self->queue.list);

  /** Take over the packet */
  new->packet = ip;
  new->root = 
  talloc_steal(new, ip);

  /** Record the most recent id we handled */
  self->max_packet_id = ip->id;

  /** Now we add the new packet in the queue at the right place. We
      traverse the list and find the last position where the sequence
      number is still smaller than our sequence number. For example
      suppose we needed to add s7 to this list:

      head s1   s4   s6   s8  s10

      We would start off with candidate = head, and increase candidate
      to s1, s4 and s6 in turn. But s8 would cause us to break.

      Then we add s7 after s6.
  */
  list_for_each_entry(i, &(self->queue.list), list) {
    TCP list_tcp = (TCP)i->packet->packet.payload;

    if(tcp->packet.header.seq >= list_tcp->packet.header.seq) {
      candidate = &(i->list);
    } else break;
  };

  /** Now add the new skbuff after the candidate */
  list_add(&(new->list), candidate);

  /** We now check to see if we can remove any packets from the queue
      by sending them to the callback.

      We check to see if the first packet in the queue has the
      expected sequence number.
  */
  while(!list_empty(&(self->queue.list))) {
    struct skbuff *first;
    TCP tcp;

    list_next(first, &(self->queue.list), list);
    tcp = (TCP)first->packet->packet.payload;
    
    /** Have we processed the entire packet before? it could be a
	retransmission we can drop it
    */
    if(self->next_seq >= tcp->packet.header.seq + tcp->packet.data_len ) {
      list_del(&(first->list));
      talloc_free(first);
      continue;
    };

    /** Does this packet have some data for us? */
    if(self->next_seq >= tcp->packet.header.seq) {
      int diff = self->next_seq - tcp->packet.header.seq;

      /** Adjust the data payload of the packet by the difference */
      tcp->packet.data+=diff;
      tcp->packet.data_len-=diff;

      /** Call our callback with this */
      self->state = PYTCP_DATA;
      if(self->callback) self->callback(self, first->packet);
      
      /** Adjust the expected sequence number */
      self->next_seq += tcp->packet.data_len;

      list_del(&(first->list));
      talloc_free(first);
      continue;
    };

    /** If we get here we can not process any more off the queue at
	this time. 
    */
    break;
  };

};

/** Flush all the queues into the callback */
void TCPStream_flush(TCPStream self) {
  /** FIXME: For now ignore outstanding packets: in future add nulls
      in
  */
  self->state = PYTCP_DESTROY;
  if(self->callback) self->callback(self, NULL);
};

VIRTUAL(TCPStream, Object)
     VMETHOD(Con) = TCPStream_Con;
     VMETHOD(add) = TCPStream_add;
     VMETHOD(flush) = TCPStream_flush;
END_VIRTUAL

TCPHashTable TCPHashTable_Con(TCPHashTable self) {
  int i;
  
  /** Create list heads for our hash table */
  for(i=0;i<TCP_STREAM_TABLE_SIZE; i++) {
    self->table[i] = talloc(self, struct TCPStream);
    INIT_LIST_HEAD(&(self->table[i]->list));
  };

  return self;
};

static u_int mkhash (const struct tuple4 *addr) {
  u_int src=addr->saddr;
  u_short sport=addr->source;
  u_int dest=addr->daddr;
  u_short dport=addr->dest;
  u_int res = 0;
  int i;
  u_char data[12];
  u_int *data_i = (u_int *)data;
  *(u_int *) (data) = src;
  *(u_int *) (data + 4) = dest;
  *(u_short *) (data + 8) = sport;
  *(u_short *) (data + 10) = dport;
  for (i = 0; i < 3; i++)
    res += data_i[i];

  return res % (TCP_STREAM_TABLE_SIZE);
};

TCPStream TCPHashTable_find_stream(TCPHashTable self, IP ip) {
  TCP tcp=(TCP)ip->packet.payload;
  u_int forward_hash, reverse_hash;
  struct tuple4 forward,reverse;
  TCPStream i,j;

  /** If we did not get a TCP packet, we fail */
  //  if(!tcp || !ISINSTANCE(tcp,TCP)) {
  if(!tcp || strcmp(NAMEOF(tcp),"TCP")) {
    return NULL;
  };
  
  forward.saddr  = ip->packet.header.saddr;
  forward.daddr  = ip->packet.header.daddr;
  forward.source = tcp->packet.header.source;
  forward.dest   = tcp->packet.header.dest;
  forward_hash = mkhash(&forward);

  /** Now try to find the forward stream in our hash table */
  list_for_each_entry(i, &(self->table[forward_hash]->list), list) {
    if(!memcmp(&(i->addr),&forward, sizeof(forward))) {
      return i;
    };
  };
  
  /** If we get here we dont have a forward (or reverse stream)
      so we need to make a forward/reverse stream pair.
  */
  reverse.saddr  = ip->packet.header.daddr;
  reverse.daddr  = ip->packet.header.saddr;
  reverse.source = tcp->packet.header.dest;
  reverse.dest   = tcp->packet.header.source;
  reverse_hash = mkhash(&reverse);

  /** Build a forward stream */
  i = CONSTRUCT(TCPStream, TCPStream, Con, self, &forward);
  i->callback = self->callback;
  i->data = self->data;
  list_add_tail(&(self->table[forward_hash]->list), &(i->list));

  /** Now a reverse stream */
  j = CONSTRUCT(TCPStream, TCPStream, Con, self, &reverse);
  j->callback = self->callback;
  j->data = self->data;
  list_add_tail(&(self->table[reverse_hash]->list), &(j->list));

  /** Make the streams point to each other */
  i->reverse = j;
  j->reverse = i;

  return i;
};

/** We expire connections that we do not see packets from in
    MAX_PACKETS_EXPIRED. We do a check every 10*MAX_PACKETS_EXPIRED
    packets 
*/
static void check_for_expired_packets(TCPHashTable self, int id) {
  TCPStream i,j;
  int k;

  for(k=0; k<TCP_STREAM_TABLE_SIZE; k++) {
    list_for_each_entry_safe(i,j, &(self->table[k]->list),list) {
      if(i->max_packet_id + MAX_PACKETS_EXPIRED < id) {
	i->flush(i);
	i->reverse->flush(i->reverse);

	list_del(&(i->list));
	list_del(&(i->reverse->list));
	
	talloc_free(i->reverse);
	talloc_free(i);
      };
    };
  };
};

int TCPHashTable_process_tcp(TCPHashTable self, IP ip) {
  TCPStream i = self->find_stream(self,ip);
  TCP tcp = (TCP)ip->packet.payload;

  /** Error - Cant create or find suitable stream */
  if(!i) return 0;

  /** This is a new connection */
  if(i->state == PYTCP_NONE) {
    /** The next sequence number we expect */
    i->next_seq = tcp->packet.header.seq+1;
    i->state = PYTCP_JUST_EST;
    
    /** Notify the callback of the establishment of the new connection */
    i->callback(i, ip);

    i->state = PYTCP_DATA;
  };

  /** check the flags of the connection to see if its terminated
  if(tcp->packet.header.fin || tcp->packet.header.rst) {
    i->state = PYTCP_CLOSE;
  };
  */

  /** Add the new IP packet to the stream queue */
  i->add(i, ip);

  self->packets_processed++;
  if(self->packets_processed > 10*MAX_PACKETS_EXPIRED) {
    check_for_expired_packets(self,ip->id);
    self->packets_processed=0;
  };

  return 1;
};

VIRTUAL(TCPHashTable, Object)
     VMETHOD(Con) = TCPHashTable_Con;
     VMETHOD(find_stream) = TCPHashTable_find_stream;
     VMETHOD(process) = TCPHashTable_process_tcp;
END_VIRTUAL

/** An automatic destructor to be called to flush out the stream. */
static int DiskStreamIO_flush(void *self) {
  DiskStreamIO this=(DiskStreamIO)self;
  int fd;

  fd=open(this->filename, O_APPEND | O_WRONLY);
  if(fd) {
    write(fd, this->super.data, this->super.size);
    close(fd);
  };

  return 0;
};

DiskStreamIO DiskStreamIO_Con(DiskStreamIO self, char *filename) {
  int fd;

  /** Check to see if we can create the required file: */
  fd=creat(filename, 0777);
  if(fd>=0) {
    /** It worked: */
    close(fd);

    /** Call our base classes constructor */
    self->__super__->Con((StringIO)self);

    self->filename = talloc_strdup(self, filename);

    /** Ensure that we get flushed out when we get destroyed */
    talloc_set_destructor(self, DiskStreamIO_flush);

    return self;
  } else {
    /** We failed: */

    talloc_free(self);

    return NULL;
  };
};

int DiskStreamIO_write(StringIO self, char *data, int len) {
  DiskStreamIO this=(DiskStreamIO)self;
  int written;

  /** Write the data to our base class */
  written=this->__super__->write(self, data, len);

  /** If we are too large, we flush to disk: */
  if(self->size > MAX_DISK_STREAM_SIZE) {
    int fd;

    fd=open(this->filename, O_APPEND | O_WRONLY);
    if(!fd) return -1;

    write(fd, self->data, self->size);

    this->written+=self->size;
    close(fd);

    self->truncate(self, 0);
  };

  return written; 
};

/** Returns the current offset in the file where the current file
    pointer is. */
int DiskStreamIO_get_offset(DiskStreamIO self) {
  return self->super.size + self->written;
};

VIRTUAL(DiskStreamIO, StringIO)
     VMETHOD(Con) = DiskStreamIO_Con;
     VMETHOD(get_offset) = DiskStreamIO_get_offset;
     VMETHOD(super.write) = DiskStreamIO_write;
END_VIRTUAL
