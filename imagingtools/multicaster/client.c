#include "multicaster.h"

//searches the outstanding list to find a block number and removes it. Returns -1 if the block was not found
int delete_from_outstanding(int *outstanding,int number) {
  int i;

  for(i=0; i<OUTSTANDING_SIZE; i++) {
    if(outstanding[i]==number) {
      //      printf("removed %u\n",number);
      outstanding[i]=0;
      return 0;
    };
  };
  return(-1);
};

/* This function receives a packet and writes it to the disk. 
fd is the socket
file_fd is the open fd for the output file.
blocksize is the expected blocksize (could be zero if the caller does not know - this will be updated to the correct value then).
key is the expected key.

raises E_GENERIC if server requested termination.
*/
int recv_block(int fd, int file_fd, unsigned short int *blocksize, int *blockid, 
	       char **from,
	       char *key) 
{
  off_t offset;
  char buff[MAX_BLOCKSIZE];
  char type;
  unsigned short int length;

  recv_packet(blocksize,blockid,from,buff,&length,&type,fd,key);

  offset=*blockid * *blocksize;
  if(lseek(file_fd,offset,SEEK_SET)<0) 
    RAISE(E_IOERROR,NULL,"Seek error %s",strerror(errno));
  if(write(file_fd,buff,length)<length)
    RAISE(E_IOERROR,NULL,"Write error %s",strerror(errno));

  return(*blocksize);
};

void client(struct config_t config) {
  int outstanding[OUTSTANDING_SIZE];
  unsigned short int blocksize=0;
  int blockid=0;
  int current_block=0;
  int fd=bind_socket(config.client_listening_port,config.multicast_addr);
  //  int fd=bind_socket(config.client_listening_port,"0.0.0.0");
  int file_fd;
  int req_fd=0;
  
  if(!config.out_filename) RAISE(E_IOERROR,NULL,"No filename set to write to");

  file_fd=creat(config.out_filename,S_IRWXU);
  if(file_fd<0) RAISE(E_IOERROR,NULL,"Unable to create ouput file %s",config.out_filename);

  memset(outstanding,0,sizeof(outstanding));
  //current_block is the last block that was received. If we get a new
  //block which is higher than current_block, we mark all the blocks
  //in between as outstanding, and increment current_block to the new
  //found block. This way we alway keep track of which blocks are
  //outstanding.

  while(1) {
    int len;

    TRY{
      TRY {
	len=recv_block(fd,file_fd,&blocksize,&blockid,&config.server_addr,config.key);
	if(config.server_addr && !req_fd) 
	  req_fd=connect_socket(config.server_addr,config.server_listening_port,0);
	//This will raise E_GENERIC if there is a terminatable error with the connection.
      } EXCEPT(E_GENERIC) {
	if(((char *)except_obj)[0] == 't')	break;
	if(((char *)except_obj)[0] == 's') {
	  printf("Got status packet - sending outstanding list\n");
	  send_packet(sizeof(outstanding),0,(char *)outstanding,
		      sizeof(outstanding),'r',req_fd,config.key);
	  continue;
	};
      };
      //If there was an E_IOERROR we just ignore it and read the next packet...
    } EXCEPT(E_IOERROR) {
      continue;
    };

    if(blockid>current_block+1) {
      int i;
      for(i=current_block+1;i<blockid;i++)
	add_to_outstanding(outstanding,i);
      //Send the server a request packet for the outstanding packets:
      TRY {
	//	printf("Sending request packet\n");
	if(!req_fd) 
	  req_fd=connect_socket(config.server_addr,config.server_listening_port,0);
	send_packet(sizeof(outstanding),0,(char *)outstanding,
		    sizeof(outstanding),'r',req_fd,config.key);
      }  EXCEPT(E_IOERROR) {
	PASS;
      };
    } else if(blockid<=current_block && 
	      delete_from_outstanding(outstanding,blockid)<0) {
      //      printf("Retransmitted block %u",blockid);
    };

    if(blockid>current_block)
      current_block=blockid;

    if(!(current_block  % 100)) {
      printf("Received %llu Mbytes so far\r",((long long int)current_block) * BLOCKSIZE/1024/1024);
    };
  };

  printf("Connection terminated by server request. Transfered %u blocks\n",current_block);
  
  //Work out how many outstanding blocks there were at end of process:
  {
    int i;

    for(i=0; i<sizeof(outstanding)/sizeof(*outstanding);i++) 
      if(outstanding[i]>0)
	printf("Block %u is still outstanding.\n",outstanding[i]);
  };
};
