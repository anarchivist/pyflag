/************************************************************
    This file implements a stream reassembler for use with
    pyflag.
*************************************************************/
#include "tcp.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static int con_id=1;

/** 
    We keep count of the total number of streams we are currenrtly
    keeping track of.
*/
static int _total_streams=0;

TCPStream TCPStream_Con(TCPStream self, struct tuple4 *addr, int con_id) {
  memcpy(&self->addr, addr, sizeof(*addr));

  self->con_id = con_id;
  con_id++;

  INIT_LIST_HEAD(&(self->queue.list));
  _total_streams++;

  return self;
};

/** Pad with zeros up to the first stored packet, and process it */
void pad_to_first_packet(TCPStream self) {
  struct skbuff *first;
  TCP tcp;
  int pad_length;
  char *new_data;
  
  list_next(first, &(self->queue.list), list);
  tcp = (TCP)first->packet->packet.payload;
  
  pad_length = tcp->packet.header.seq - self->next_seq;
  if(pad_length > 50000) {
    //printf("Needing to pad excessively, dropping data...\n");
    self->next_seq = tcp->packet.header.seq;
    return;
  };
  
  if(pad_length>0) {
    new_data = talloc_size(tcp, tcp->packet.data_len + pad_length);
    memset(new_data, 0, pad_length);
    memcpy(new_data+pad_length, tcp->packet.data, tcp->packet.data_len);
    
    tcp->packet.data_len+=pad_length;
    tcp->packet.data = new_data;

    //printf("Forced to pad by %d bytes in stream %d\n",pad_length, self->con_id);
  } else if(pad_length<0) {
    tcp->packet.data_len -= -pad_length;
    tcp->packet.data += -pad_length;

    if(tcp->packet.data_len<0) {
      tcp->packet.data_len=0;
      tcp->packet.data=NULL;
    };
  };
  
  self->next_seq+=tcp->packet.data_len;
  
  /** Call our callback with this */
  if(self->callback) self->callback(self, first->packet);
  
  list_del(&(first->list));
  talloc_free(first);
};


void TCPStream_add(TCPStream self, IP ip) {
  struct skbuff *new = talloc(self, struct skbuff);
  struct skbuff *i;
  TCP tcp=(TCP)ip->packet.payload;
  int count=0;
  struct list_head *candidate;

  /** If there is no data in there we move on */
  if(tcp->packet.data_len==0) {
    talloc_free(ip);
    return;
  }

  /** This is the location after which we insert the new structure */
  candidate = &(self->queue.list);

  /** Take over the packet */
  new->packet = ip;

  talloc_steal(new, ip);

  /** Record the most recent id we handled */
  self->max_packet_id = ip->id;

  /** The total size of both directions */
  self->total_size += tcp->packet.data_len + self->reverse->total_size;
  self->reverse->total_size = self->total_size;

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
      count++;
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

    /** If the list gets too large, we need to flush the data out to
	the callback. This could be because we have missed a packet
	permanently for example. We pad the data with 0 to make it
	work. 

	We do this by checking if the sequence number of the last
	packet is further than window ahead of the first packet in the
	list.
    */
    if(self->state == PYTCP_DATA){
      struct skbuff *first,*last;
      /** This is the last packet stored */
      TCP tcp_last,tcp;

      list_prev(last, &(self->queue.list), list);
      tcp_last = (TCP)last->packet->packet.payload;
      
      list_next(first, &(self->queue.list), list);
      tcp = (TCP)first->packet->packet.payload;

      while(!list_empty(&(self->queue.list)) && 
	    tcp->packet.header.window + tcp->packet.header.seq 
	    < tcp_last->packet.header.seq) {
	pad_to_first_packet(self);
	
	list_next(first, &(self->queue.list), list);

	// If the skbuff does not contain a packet we leave - this
	// should not happen but does??
	if(!first || !first->packet) break;
	tcp = (TCP)first->packet->packet.payload;
      };
    }; 

    /** If we get here we can not process any more off the queue at
	this time. 
    */
    break;
  };
};

/** Pads any left over data in self with zeros. Results in all
    outstanding packets being flushed and removed from the packet
    list.
 */
void pad_data(TCPStream self) {
  while(!list_empty(&(self->queue.list))) {
    pad_to_first_packet(self);
  };
};

/** Flush all the queues into the callback */
int TCPStream_flush(void * this) {
  TCPStream self=(TCPStream)this;

  if(self->direction!=TCP_FORWARD) 
    return 0;

  /** For each stream we pad out the remaining data */
  pad_data(self);

  /** Now we signal to the cb that the stream is destroyed */
  self->state = PYTCP_DESTROY;
  if(self->callback) self->callback(self, NULL);

  /** and we remove it from its lists */
  list_del(&(self->list));
  list_del(&(self->global_list));

  /** Now do the reverse stream */
  pad_data(self->reverse);

  self->reverse->state = PYTCP_DESTROY;
  if(self->reverse->callback)
    self->reverse->callback(self->reverse, NULL);

  list_del(&(self->reverse->list));
  list_del(&(self->reverse->global_list));

  // Keep count of our streams
  _total_streams-=2;

  return 0;
};

VIRTUAL(TCPStream, Object)
     VMETHOD(Con) = TCPStream_Con;
     VMETHOD(add) = TCPStream_add;
END_VIRTUAL

TCPHashTable TCPHashTable_Con(TCPHashTable self, int initial_con_id) {
  int i;

  self->con_id = initial_con_id;
  
  /** Create list heads for our hash table */
  for(i=0;i<TCP_STREAM_TABLE_SIZE; i++) {
    self->table[i] = talloc(self, struct TCPStream);
    INIT_LIST_HEAD(&(self->table[i]->list));
  };

  // This list keeps all streams in order:
  self->sorted = talloc(self, struct TCPStream);
  INIT_LIST_HEAD(&(self->sorted->global_list));
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
  /** The below should work but does not because __TCP is defined in 2
      different shared objects reassemble.so and dissect.so. We are
      likely to receive a class created from dissect.so here but __TCP
      refers to our (reassemble.so) version.

      Any ideas of how to fix this???
   */
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
      /** When we find a stream, we remove it from its place in the
	  list and put it at the top of the list - this keeps the list
	  ordered wrt the last seen time 
      */
      if(1 || i->total_size > MINIMUM_STREAM_SIZE) {
	list_del(&(i->global_list));
	list_add(&(i->global_list), &(self->sorted->global_list));
      };

      if(1 || i->reverse->total_size > MINIMUM_STREAM_SIZE) {
	list_del(&(i->reverse->global_list));
	list_add(&(i->reverse->global_list), &(self->sorted->global_list));
      };
      return i;
    };
  };
  
  reverse.saddr  = ip->packet.header.daddr;
  reverse.daddr  = ip->packet.header.saddr;
  reverse.source = tcp->packet.header.dest;
  reverse.dest   = tcp->packet.header.source;
  reverse_hash = mkhash(&reverse);

  /** Now try to find the reverse stream in our hash table */
  list_for_each_entry(i, &(self->table[reverse_hash]->list), list) {
    if(!memcmp(&(i->addr),&reverse, sizeof(reverse))) {
      /** Readjust the order of the global list */
      if(1 || i->total_size > MINIMUM_STREAM_SIZE) {
	list_del(&(i->global_list));
	list_add(&(i->global_list), &(self->sorted->global_list));
      };

      if(1 || i->reverse->total_size > MINIMUM_STREAM_SIZE) {
	list_del(&(i->reverse->global_list));
	list_add(&(i->reverse->global_list), &(self->sorted->global_list));
	return i->reverse;
      };
    };
  };  

  /** If we get here we dont have a forward (or reverse stream)
      so we need to make a forward/reverse stream pair.
  */
  /** Build a forward stream */
  i = CONSTRUCT(TCPStream, TCPStream, Con, self, &forward, self->con_id++);
  i->callback = self->callback;
  i->data = self->data;
  i->direction = TCP_FORWARD;
  list_add_tail(&(i->list),&(self->table[forward_hash]->list));
  list_add(&(i->global_list),&(self->sorted->global_list));

  /** Now a reverse stream */
  j = CONSTRUCT(TCPStream, TCPStream, Con, i, &reverse, self->con_id++);
  j->callback = self->callback;
  j->data = self->data;
  j->direction = TCP_REVERSE;
  list_add_tail(&(j->list),&(self->table[reverse_hash]->list));
  list_add(&(j->global_list),&(self->sorted->global_list));

  /** Make the streams point to each other */
  i->reverse = j;
  j->reverse = i;

  /** When the streams are destroyed we flush them */
  talloc_set_destructor(i, TCPStream_flush);

  return i;
};

/** We expire connections that we do not see packets from in
    MAX_PACKETS_EXPIRED. We do a check every 10*MAX_PACKETS_EXPIRED
    packets 
*/
static void check_for_expired_packets(TCPHashTable self, int id) {
  TCPStream i;
  int k;

  for(k=0; k<TCP_STREAM_TABLE_SIZE; k++) {
    list_for_each_entry(i, &(self->table[k]->list),list) {
      if(i->direction == TCP_FORWARD && 
	 i->max_packet_id + MAX_PACKETS_EXPIRED < id) {
	talloc_free(i);
	break;
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
    /** The next sequence number we expect. Note that the syn packet
       increments the seq number by 1 even though it has a length of
       zero.
    */
    if(tcp->packet.header.syn)
      i->next_seq = tcp->packet.header.seq+1;
    else i->next_seq = tcp->packet.header.seq;
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

  /** If we are keeping track of too many streams we need to expire
      them:
  **/
  if(_total_streams>MAX_NUMBER_OF_STREAMS) {
    TCPStream x;

    list_for_each_entry_prev(x, &(self->sorted->global_list), global_list) {
      if(x->direction == TCP_FORWARD) {
	//printf("Total streams exceeded %u - proceesing %u, freeing %u\n", 
	//       _total_streams, i->con_id, x->con_id);
    	talloc_free(x);
	// Freeing the above will remove at least 2 streams from the
	// list, which means its no longer safe to recurse over it!!!
	break;
      };
    };
  };

  self->packets_processed++;
  if(self->packets_processed > 2*MAX_PACKETS_EXPIRED) {
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

/** Create a new file, or if it already exists, open the file for writing.
    Note - caller must close fd when done to ensure no fds are leaked.
*/
static int get_working_fd(DiskStreamIO this) {
  int fd;

  if(!this->created) {
    /** Check to see if we can create the required file: */
    fd=creat(this->filename, 0777);
    this->created = 1;
  } else {
    fd=open(this->filename, O_APPEND | O_WRONLY);
  };

  return fd;
};

/** An automatic destructor to be called to flush out the stream. */
static int DiskStreamIO_flush(void *self) {
  DiskStreamIO this=(DiskStreamIO)self;
  int fd;

  if(this->super.size==0) return 0;

  fd=get_working_fd(this);
  if(fd>=0) {
    write(fd, this->super.data, this->super.size);
    close(fd);
  };

  return 0;
};

DiskStreamIO DiskStreamIO_Con(DiskStreamIO self, char *filename) {
  /** Call our base classes constructor */
  self->__super__->Con((StringIO)self);
  
  self->filename = talloc_strdup(self, filename);

  /** Ensure that we get flushed out when we get destroyed */
  talloc_set_destructor(self, DiskStreamIO_flush);

  return self;
};

int DiskStreamIO_write(StringIO self, char *data, int len) {
  DiskStreamIO this=(DiskStreamIO)self;
  int written;

  /** Write the data to our base class */
  written=this->__super__->write(self, data, len);

  /** If we are too large, we flush to disk: */
  if(self->size > MAX_DISK_STREAM_SIZE) {
    int fd=get_working_fd(this);
    
    if(fd==-1) return fd;

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
