#include "multicaster.h"

static int global_channel_delay=50000;
static double initial_start=1;
static int packets_sent=0;

void send_block(int fd,int file_fd,int block_number, int block_size,char *key) {
  off_t offset= block_number * block_size;
  char buff[block_size];
  int res;

  if(lseek(file_fd,offset,SEEK_SET)<0) 
    RAISE(E_IOERROR,NULL,"Seek error %s",strerror(errno));
  
  res=read(file_fd,buff,block_size);
  if(res<=0) {
    RAISE(E_IOERROR,NULL,"Read error %s",strerror(errno));
  };

  send_packet(block_size,block_number,buff,res,'r',fd,key);
  usleep(global_channel_delay);
  packets_sent++;
};

//Returns 1 if a packet was processed, or -1 if timeout has been
//reached and no packet was found. Raises an E_IOERROR if there was a
//select error.
int check_for_transmissions(int listen_fd,int file_fd,int fd,struct config_t config) {
    int outstanding[OUTSTANDING_SIZE];
    int total_outstanding[OUTSTANDING_SIZE];
    unsigned short int outstanding_size = sizeof(outstanding);
    fd_set fds;
    struct timeval tv;
    int ret,len,blockid;
    int i,count=0;
    int outstanding_updated=0;

    memset(&total_outstanding,0,sizeof(total_outstanding));

    while(1) {
      FD_ZERO(&fds);
      FD_SET(listen_fd, &fds);
      tv.tv_sec=0;
      tv.tv_usec=config.timeout;
      ret=select(listen_fd+1, &fds, NULL,NULL,&tv);
      
      if(ret==-1) RAISE(E_IOERROR,NULL,"Select error");
      if(ret) {
	int i;
	char type;
	unsigned short int length;
	
	len=recv_packet(&outstanding_size,&blockid,NULL,(char *)outstanding,&length,&type,listen_fd,config.key);
	for(i=0;i<outstanding_size/sizeof(*outstanding);i++) {
	  if(outstanding[i]>0) {
	    outstanding_updated=1;
	    add_to_outstanding(total_outstanding,outstanding[i]);
	  };
	};
	//Timeout occured - quit reading and do the retransmissions
      } else {
	if(outstanding_updated) {
	  break;
	};
	global_channel_delay-=packets_sent*initial_start;
	if(global_channel_delay<0) global_channel_delay=0;
	//	printf("Global %u\n",global_channel_delay);
	return(-1);
      };
    };

    //Send all the restransmitted packets...
    for(i=0;i<outstanding_size/sizeof(*outstanding);i++) {
      if(total_outstanding[i]>0) {
	count++;
      };
    };

    printf("Retransmitted %u packets out of %u\n",count,packets_sent);

    //When we retransmit packets, its usually because the channel is
    //saturated - pumping more data into the channel just makes
    //things worse. The best course of action in this case is to
    //back off a little to let the channel recover.
    global_channel_delay += (-((double)packets_sent-count)/packets_sent+0.5)*1000;
    if(global_channel_delay<0) global_channel_delay=0;
    packets_sent=0;
    initial_start=0.01;

    printf("Global channel delay = %u\n",global_channel_delay);

    //Nothing to do here...
    if(count==0) return(1);
    
    for(i=0;i<outstanding_size/sizeof(*outstanding);i++) {
      if(total_outstanding[i]>0) {
	send_block(fd,file_fd,total_outstanding[i],BLOCKSIZE,config.key);
      };
    };

    return(1);
};

void server(struct config_t config) {
  //Bind a listening socket for retransmission requests.
  int listen_fd=bind_socket(config.server_listening_port,NULL);
  int block_count=0;

  int fd=connect_socket(config.multicast_addr,config.client_listening_port,1);
  int file_fd;
  
  if(!config.in_filename) RAISE(E_IOERROR,NULL,"No filename set to read from");

  file_fd=open(config.in_filename,O_RDONLY);
  if(file_fd<0) RAISE(E_IOERROR,NULL,"Unable to open file %s",config.in_filename);

  for(block_count=0;;block_count++) {
    //After each packet that we send, we check to see if there are
    //packets available for us to read in the retransmission request
    //socket, and if so we service those packets. Note that we do not
    //block here at all.
    check_for_transmissions(listen_fd,file_fd,fd,config);
    TRY{
      send_block(fd,file_fd,block_count,BLOCKSIZE,config.key);
    } EXCEPT(E_IOERROR) {
      //      printf("%s\n",except_str);
      break;
    };

    if(!(block_count % 100)) {
      //Send status request to see what clients are up to...
      send_packet(0,0,NULL,0,'s',fd,config.key);
      printf("Sent %llu Mbytes so far\r",((long long int)block_count) * BLOCKSIZE/1024/1024);
    };
  };

  printf("Sent %u blocks, Waiting 5 seconds for retransmission requests\n",block_count-1);

  //Now we wait for a little while to receive retransmission packets, just in case.
  config.timeout=5e6;
  while(1) {
    sleep(2);

    //Send some status query commands - to solicit requests
    send_packet(0,0,NULL,0,'s',fd,config.key);
    send_packet(BLOCKSIZE,block_count++,"",0,'r',fd,config.key);

    //Listen for requests
    if(check_for_transmissions(listen_fd,file_fd,fd,config)<0) break;
  };

  //Now terminate the client by request:
  send_packet(0,0,NULL,0,'t',fd,config.key);
};
