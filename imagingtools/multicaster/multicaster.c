#include "multicaster.h"

/* Sends the provided data buffer of length block_size to the socket
   given by out_fd. block_size is given in bytes.

  key is a 16 byte hash of the shared secret. It is appended to the
  data and an md5 sum is done of the entire data packet.
*/
void send_packet( unsigned short int block_size, unsigned int block_id,
		  char *data, int length, char type,int out_fd,char *key) 
{
  int total_length=block_size + sizeof(struct data_header) + 16;
  char *buffer=(char *)malloc(total_length);
  struct data_header *header=(struct data_header *)buffer;
  MD5_CTX md5;
  
  header->type=type;
  header->block_size=block_size;
  header->block_id=block_id;
  header->length=length;
  memcpy(buffer+sizeof(*header),data,block_size);
  memcpy(buffer+total_length-16,key,16);
  
  //Calculate the md5 sum by summing over the data with the secret key appended
  MD5Init(&md5);
  MD5Update(&md5,buffer,total_length);

  //Trash the secret key with the new hash
  MD5Final(buffer+total_length-16,&md5);

  if(send(out_fd,buffer,total_length,0)<total_length) {
    free(buffer);
    RAISE(E_IOERROR,NULL,"Unable to send packet");
  };

  free(buffer);
};

/* This function receives a packet on the socket.

from - this is a pointer to a string. If provided (i.e. not null), we
   compare the address of the remote end to this string and raise an
   E_IOERROR if it does not match. If from points to a null pointer,
   we return the address of the remote end in from.

*/
int recv_packet(unsigned short int  *block_size, unsigned int *block_id, 
		char **from,
		char *data,unsigned short int *data_length, 
		char *type, int in_fd, char *key) 
{ 
  int length=*block_size + sizeof(struct data_header) + 16;
  char *buffer; 
  char hash[16]; 
  struct data_header *header; 
  MD5_CTX md5;
  struct sockaddr_in from_addr;
  int from_size=sizeof(from_addr);

  if(!*block_size) length=MAX_BLOCKSIZE;
  buffer=(char *)malloc(length);
  header=(struct data_header *)buffer;

  length=recvfrom(in_fd,buffer,length,0,(struct sockaddr *)&from_addr,&from_size);
  
  //Should we check the source of the packet?
  if(from) {
    char *remote_ip = inet_ntoa(from_addr.sin_addr);
    
    //Does it match the provided IP?
    if(*from && strcmp(*from,remote_ip)) {
      RAISE(E_IOERROR,NULL,"Packet did not arrive from expected IP %s (%s)",*from,remote_ip);
      //Should we return an IP for it?
    } else if(!*from) {
      printf("Received a connection from %s\n",remote_ip);
      fflush(stdout);
      *from=strdup(remote_ip);
    };
  };
    
  if(length<0) {
    RAISE(E_IOERROR,NULL,"Recv Error");
  };
  
  //Check the md5 sum to ensure its ok:
  //Save hash somewhere:
  memcpy(hash,buffer+length-16,16);
  //Overwrite the hash with the key:
  memcpy(buffer+length-16,key,16);
  
  //Calculate the md5 sum by summing over the data with the secret key appended
  MD5Init(&md5);
  MD5Update(&md5,buffer,length);
  
  //Trash the secret key with the new hash
  MD5Final(buffer+length-16,&md5);
  
  //Is this the same as before:
  if(memcmp(buffer+length-16,hash,16)!=0)
    RAISE(E_IOERROR,NULL,"Packet has incorrect hash");
  
  *type=header->type;

  
  //Now process the packet according to its type
  switch(header->type) {
    //Regular packet (carries normal data)
  case 'r':
    if(*block_size && *block_size != header->block_size) {
      RAISE(E_IOERROR,NULL,"Packet does not have expected block size: Got %u, Expected %u",header->block_size,*block_size);
    } else  *block_size=header->block_size;
    if(*block_size<header->length) 
      RAISE(E_IOERROR,NULL,"Packet data length longer than block size!!!");
    
    *data_length=header->length;
    *block_id=header->block_id;
    //Now we copy the data to the buffer:
    memcpy(data,buffer+sizeof(*header),*data_length);
    return(*block_size);
    break;
    
    //Terminate command
  case 't':
    RAISE(E_GENERIC,(void *)"t","Terminate");
    break;
  
    //Status query command
  case 's':
    RAISE(E_GENERIC,(void *)"s","Status");
    break;

  default:
    RAISE(E_IOERROR,NULL,"Unknown packet type %c",header->type);
  };
  //Never reached
  return(0);
};

int connect_socket(char *addr, unsigned int port,int multicast) 
{
  int fd=socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP);
  struct sockaddr_in sin;
  struct hostent *host;

  if(fd<0) RAISE(E_IOERROR,NULL,"Unable to get socket");
  sin.sin_family = AF_INET;
  sin.sin_port = htons(port);
  /*  host= gethostbyname(addr);
  memcpy(&sin.sin_addr.s_addr,host->h_addr_list[0],
	 sizeof(sin.sin_addr.s_addr));
  */
  sin.sin_addr.s_addr=inet_addr(addr);

  if(multicast) {
    struct ip_mreq req;

    req.imr_multiaddr.s_addr=sin.sin_addr.s_addr;
    req.imr_interface.s_addr=htonl(INADDR_ANY);
    setsockopt(fd,IPPROTO_IP, IP_ADD_MEMBERSHIP, &req, sizeof(req));
  };

  if(connect(fd,(struct sockaddr *)&sin,sizeof(sin))!=0) 
    RAISE(E_IOERROR,NULL,"Connection error: %s",strerror(errno));
  
  return(fd);
};

int bind_socket(unsigned int port,char *multicast_addr)
{
  int fd;
  struct sockaddr_in s;

  fd = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if(fd<0) RAISE(E_IOERROR,NULL,"Cant create socket");

  if(setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &s, sizeof (s))<0) 
    RAISE(E_IOERROR,NULL,"Set Sockopt failed");
  
  s.sin_family=AF_INET;
  s.sin_addr.s_addr=INADDR_ANY;
  s.sin_port=htons(port);
  
  if(multicast_addr) {
    struct ip_mreq req;
    struct hostent *host=gethostbyname(multicast_addr);
    struct sockaddr_in multi_s; 
    multi_s.sin_family=AF_INET;
    multi_s.sin_port=htons(port);
 
    memcpy(&req.imr_multiaddr.s_addr,host->h_addr_list[0],
	   sizeof(req.imr_multiaddr.s_addr));
    
    multi_s.sin_addr.s_addr=req.imr_multiaddr.s_addr;
    req.imr_interface.s_addr=INADDR_ANY;
    
    if(bind(fd,(struct sockaddr *)&multi_s,sizeof(multi_s))<0)
      RAISE(E_IOERROR,NULL,"Unable to bind to port %u",port);
    
    setsockopt(fd,IPPROTO_IP, IP_ADD_MEMBERSHIP, &req, sizeof(req));
  } else if(bind(fd,(struct sockaddr *)&s,sizeof(s))<0)
    RAISE(E_IOERROR,NULL,"Unable to bind to port %u",port);

  return(fd);
};

char *md5sum(char *key) {
  char *buffer=(char *)malloc(16);
  MD5_CTX md5;
  
  MD5Init(&md5);
  MD5Update(&md5,key,strlen(key));
  
  //Trash the secret key with the new hash
  MD5Final(buffer,&md5);

  return(buffer);
};


//Adds a block number to the outstanding list. If there is no space in
//the list, we drop the block on the floor... we count on future
//packets to trigger the addition again.
void add_to_outstanding(int *outstanding,int number) {
  int i;

  //  printf("added %u\n",number);
  for(i=0;i<OUTSTANDING_SIZE;i++) {
    if(outstanding[i]==0 || outstanding[i]==number) {
      outstanding[i]=number;
      return;
    };
  };
};
