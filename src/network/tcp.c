/************************************************************
    This file implements a stream reassembler for use with
    pyflag.
*************************************************************/
#include "tcp.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


struct reassembler_configuration_t reassembler_configuration = {
   .max_packets_expired  = 10000,
   .max_number_of_streams=  1000,
   .minimum_stream_size  =   100,
   .max_outstanding_skbuffs = 100000,

   // The below are global accounting
   .total_outstanding_skbuffs=0,
   .total_streams=0,

   // This is used to collect stats about the number of python
   // connection objects allocated
   .stream_connection_objects=0
};

TCPStream TCPStream_Con(TCPStream self, struct tuple4 *addr, int con_id) {
  memcpy(&self->addr, addr, sizeof(*addr));

  self->con_id = con_id;
  con_id++;

  INIT_LIST_HEAD(&(self->queue.list));
  reassembler_configuration.total_streams++;

  return self;
};

/** Pad with zeros up to the first stored packet, and process it */
void pad_to_first_packet(TCPStream self) {
  struct skbuff *first;
  TCP tcp;
  int pad_length;
  char *new_data;
  
  list_next(first, &(self->queue.list), list);
  tcp = (TCP)find_packet_instance(first->packet->obj, "TCP");
  
  pad_length = tcp->packet.header.seq - self->next_seq;
  if(pad_length > 50000 || pad_length < -50000) {
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
    tcp->packet.header.seq += -pad_length;

    if(tcp->packet.data_len<0) {
      tcp->packet.data_len=0;
      tcp->packet.data=NULL;
    };
  };
  
  self->next_seq+=tcp->packet.data_len;
  
  /** Call our callback with this */
  self->state = PYTCP_DATA;
  if(self->callback) self->callback(self, first->packet);
  
  list_del(&(first->list));
  talloc_free(first);
};

/** This gets called whenever an skbuff is destroyed to clean up the
    object contained within 
*/
int destroy_object(void *buff) {
  struct skbuff *new = (struct skbuff *)buff;
  reassembler_configuration.total_outstanding_skbuffs--;
  Py_DECREF(new->packet);
  return 0;
};

void TCPStream_add(TCPStream self, PyPacket *packet) {
  IP ip = (IP)find_packet_instance(packet->obj, "IP");
  struct skbuff *new;
  struct skbuff *i;
  TCP tcp;
  int count=0;
  struct list_head *candidate;

  if(!ip) return;
  tcp=(TCP)ip->packet.payload;

  /** If there is no data in there we move on */
  if(tcp->packet.data_len==0) {
    if(self->callback) {
      self->state = PYTCP_RETRANSMISSION;
      self->callback(self, packet);
    };

    // We no longer need the object - call its destructor:
    //Py_DECREF(packet);
    return;
  }

  new = talloc(self, struct skbuff);
  reassembler_configuration.total_outstanding_skbuffs++;
   
  /** This is the location after which we insert the new structure */
  candidate = &(self->queue.list);

  /** Take over the packet */
  Py_INCREF(packet);
  new->packet = packet;

  /** Set the destructor function which should be called when the
      skbuff is destroyed: 
  */
  talloc_set_destructor((void*)new, destroy_object);

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
    TCP list_tcp = (TCP)find_packet_instance(i->packet->obj, "TCP");

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
    tcp = (TCP)find_packet_instance(first->packet->obj, "TCP");

    /** Have we processed the entire packet before? it could be a
	retransmission we can drop it
    */
    if(self->next_seq >= tcp->packet.header.seq + tcp->packet.data_len ) {
      /** Call our callback with this */
      self->state = PYTCP_RETRANSMISSION;
      if(self->callback) self->callback(self, first->packet);

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

      /** 
	  We need to adjust the sequence numbers by this amount. This
	  is the same as if the retransmitted packet delivers extra
	  data from the end of the previous packet. Here is an
	  example:

	  Packet A: Seq x len y
	  Packet B: Seq x len y+z

	  Packet B retransmits packet A and add z more bytes to Packet
	  A. In this case we call the callback with packet A, and
	  expect seq x+y. When packet B arrives, we trim y bytes off
	  its data and increase its sequence number to x+y so its as
	  if packet B was:
	  
	  Packet B: Seq x+y len z

	  This means we favour old packets. (See Ptacek and Newshams paper)
      */
      tcp->packet.header.seq += diff;

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
    if(self->state == PYTCP_DATA || self->state == PYTCP_RETRANSMISSION){
      struct skbuff *first,*last;
      /** This is the last packet stored */
      TCP tcp_last,tcp;

      list_prev(last, &(self->queue.list), list);
      tcp_last = (TCP)find_packet_instance(last->packet->obj, "TCP");
      
      list_next(first, &(self->queue.list), list);
      tcp = (TCP)find_packet_instance(first->packet->obj, "TCP");

      while(!list_empty(&(self->queue.list)) && 
	    tcp->packet.header.window + tcp->packet.header.seq 
	    < tcp_last->packet.header.seq) {
	pad_to_first_packet(self);
	
	list_next(first, &(self->queue.list), list);

	// If the skbuff does not contain a packet we leave - this
	// should not happen but does??
	if(!first || !first->packet) break;
	tcp = (TCP)find_packet_instance(first->packet->obj, "TCP");
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
int TCPStream_flush(void *this) {
  TCPStream self=(TCPStream)this;

  if(self->direction!=TCP_FORWARD) 
    return 0;

  /** For each stream we pad out the remaining data */
  pad_data(self);

  /** Now do the reverse stream. Note that we need to pad reverse
      stream _before_ we call destroy so it has a chance to do
      something.
  */
  pad_data(self->reverse);

  /** Now we signal to the cb that the stream is destroyed */
  self->state = PYTCP_DESTROY;
  if(self->callback) self->callback(self, NULL);

  /** and we remove it from its lists */
  list_del(&(self->list));
  list_del(&(self->global_list));

  // Call destroy on the reverse stream - FIXME: This is unneeded in
  // the current implementation because the previous destroy removes
  // the python objects.
  self->reverse->state = PYTCP_DESTROY;
  if(self->reverse->callback)
    self->reverse->callback(self->reverse, NULL);

  list_del(&(self->reverse->list));
  list_del(&(self->reverse->global_list));

  // Keep count of our streams
  reassembler_configuration.total_streams-=2;

  return 0;
};

VIRTUAL(TCPStream, Object)
     VMETHOD(Con) = TCPStream_Con;
     VMETHOD(add) = TCPStream_add;
END_VIRTUAL

/** The UDPStream implementation is simpler - we dont keep any packet
    queues and just dump them into the stream in the order they are
    encountered. 
*/
void UDPStream_add(TCPStream self, PyPacket *packet) {
  IP ip = (IP)find_packet_instance(packet->obj, "IP");
  if(!ip) return;

  /** Call our callback with this */
  self->state = PYTCP_DATA;
  if(self->callback) self->callback(self, packet);
  
  return;
};

VIRTUAL(UDPStream, TCPStream)
     VMETHOD(super.add) = UDPStream_add;
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
  
  // Initialise the list head so it can be used to pass the callback
  // non-ip packets:
  self->sorted->hash = self;
  self->sorted->state = PYTCP_NON_TCP;

  return self;
};

static u_int32_t mkhash (const struct tuple4 *addr) {
  int *data = (int *)addr;
  u_int32_t res=0;
  int i;

  for (i = 0; i < sizeof(struct tuple4) / sizeof(int); i++)
    res += data[i];

  return res % (TCP_STREAM_TABLE_SIZE);
};

TCPStream TCPHashTable_find_stream(TCPHashTable self, IP ip) {
  TCP tcp;
  u_int32_t forward_hash, reverse_hash;
  struct tuple4 forward,reverse;
  TCPStream i,j;
  int udp_packet=0;
  int tcp_packet=0;

  if(!ip) return NULL;

  tcp =(TCP)ip->packet.payload;

  /** If we did not get a TCP packet, we fail */
  /** The below should work but does not because __TCP is defined in 2
      different shared objects reassemble.so and dissect.so. We are
      likely to receive a class created from dissect.so here but __TCP
      refers to our (reassemble.so) version. Thats why we fall back to
      compare strings instead.

      FIXME: A possible optimization would be to create a class hash
      which we can use instead of a string comparison.
   */
  if(ISNAMEINSTANCE(tcp,"TCP")) {
    tcp_packet = 1;
  } else if(ISNAMEINSTANCE(tcp,"UDP")) {
    udp_packet = 1;
  } else return NULL;
  
  forward.saddr  = ip->packet.header.saddr;
  forward.daddr  = ip->packet.header.daddr;
  forward.source = tcp->packet.header.source;
  forward.dest   = tcp->packet.header.dest;
  forward.pad    = 0;
  forward_hash = mkhash(&forward);

  /** Now try to find the forward stream in our hash table */
  list_for_each_entry(i, &(self->table[forward_hash]->list), list) {
    if(!memcmp(&(i->addr),&forward, sizeof(forward))) {
      /** When we find a stream, we remove it from its place in the
	  list and put it at the top of the list - this keeps the list
	  ordered wrt the last seen time 
      */
      if(1 || i->total_size > reassembler_configuration.minimum_stream_size) {
	list_del(&(i->global_list));
	list_add(&(i->global_list), &(self->sorted->global_list));
      };

      if(1 || i->reverse->total_size > reassembler_configuration.minimum_stream_size) {
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
  reverse.pad    = 0;
  reverse_hash = mkhash(&reverse);

  /** Now try to find the reverse stream in our hash table */
  list_for_each_entry(i, &(self->table[reverse_hash]->list), list) {
    if(!memcmp(&(i->addr),&reverse, sizeof(reverse))) {
      /** Readjust the order of the global list */
      if(1 || i->total_size > reassembler_configuration.minimum_stream_size) {
	list_del(&(i->global_list));
	list_add(&(i->global_list), &(self->sorted->global_list));
      };

      if(1 || i->reverse->total_size > reassembler_configuration.minimum_stream_size) {
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
  if(udp_packet) {
    i = (TCPStream)CONSTRUCT(UDPStream, TCPStream, super.Con, self, &forward, self->con_id++);
  } else {
    i = CONSTRUCT(TCPStream, TCPStream, Con, self, &forward, self->con_id++);
  };
  i->callback = self->callback;
  i->hash = self;
  i->direction = TCP_FORWARD;
  list_add_tail(&(i->list),&(self->table[forward_hash]->list));
  list_add(&(i->global_list),&(self->sorted->global_list));

  /** Now a reverse stream */
  if(udp_packet) {
    j = (TCPStream)CONSTRUCT(UDPStream, TCPStream, super.Con, i, &reverse, self->con_id++);
  } else {
    j = CONSTRUCT(TCPStream, TCPStream, Con, i, &reverse, self->con_id++);
  };

  j->callback = self->callback;
  j->hash = self;
  j->direction = TCP_REVERSE;
  list_add_tail(&(j->list),&(self->table[reverse_hash]->list));
  list_add(&(j->global_list),&(self->sorted->global_list));

  /** Make the streams point to each other */
  i->reverse = j;
  j->reverse = i;

  /** When the streams are destroyed we flush them */
  talloc_set_destructor((void *)i, TCPStream_flush);

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
	 i->max_packet_id + reassembler_configuration.max_packets_expired < id) {
	talloc_free(i);
	break;
      };
    };
  };
};

static void TCPHashTable_flush(TCPHashTable self) {
  TCPStream i;
  int k;

  for(k=0; k<TCP_STREAM_TABLE_SIZE; k++) {
    list_for_each_entry(i, &(self->table[k]->list),list) {
      if(i->direction == TCP_FORWARD) { 
	talloc_free(i);
	// We need to break here because the list is no longer
	// consistant (we may remove 2 items from it).
	break;
      };
    };
  };
};

// Expires the older stream
static void expire_oldest_stream(TCPHashTable self) 
{
   TCPStream x;
   
   list_for_each_entry_prev(x, &(self->sorted->global_list), global_list) {
      if(x->direction == TCP_FORWARD) {
	//printf("Total streams exceeded %u - proceesing %u, freeing %u\n", 
	//       _total_streams, i->con_id, x->con_id);
    	talloc_free(x);
	 // Freeing the above will remove at least 2 streams from the
	 // list, which means its no longer safe to recurse over it!!!
	return;
      };
   };   
};

int TCPHashTable_process(TCPHashTable self, PyPacket *packet) {
  IP ip = (IP)find_packet_instance(packet->obj, "IP");
  TCPStream i;
  TCP tcp;

  // Packet is not an IP packet - We need to call the CB directly:
  if(!ip)  goto non_ip;

  i = self->find_stream(self,ip);

  /** Error - Cant create or find suitable stream */
  if(!i) goto non_ip;

  tcp = (TCP)ip->packet.payload;

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
    i->callback(i, packet);

    i->state = PYTCP_DATA;
  };

  /** check the flags of the connection to see if its terminated
  if(tcp->packet.header.fin || tcp->packet.header.rst) {
    i->state = PYTCP_CLOSE;
  };
  */

  /** Add the new IP packet to the stream queue */
  i->add(i, packet);

  /** If we are keeping track of too many streams we need to expire
      them:
  **/
   if(reassembler_configuration.total_streams > reassembler_configuration.max_number_of_streams ||
     reassembler_configuration.total_outstanding_skbuffs > reassembler_configuration.max_outstanding_skbuffs) {
     expire_oldest_stream(self);
  };

  self->packets_processed++;
  if(self->packets_processed > 2*reassembler_configuration.max_packets_expired) {
    check_for_expired_packets(self,ip->id);
    self->packets_processed=0;
  };

  return 1;

 non_ip:
  self->sorted->state = PYTCP_NON_TCP;
  if(self->callback)
    self->callback(self->sorted, packet);
  
  return 0;
};

VIRTUAL(TCPHashTable, Object)
     VMETHOD(Con) = TCPHashTable_Con;
     VMETHOD(find_stream) = TCPHashTable_find_stream;
     VMETHOD(process) = TCPHashTable_process;
     VMETHOD(flush) = TCPHashTable_flush;
END_VIRTUAL
