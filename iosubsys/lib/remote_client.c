/* This program launches the server and attaches stdout/stdin to the
   two file descriptors. */

#include "remote.h"
#include <sys/socket.h>
#include <sys/types.h>

#define BUFSIZE 8192
#ifndef CYGWIN
#define O_BINARY 0
#endif

//These socket pairs are used to communicate with the remote end
void child_exit() {
  wait4(0,NULL,0,NULL);
  exit(0);
};

void remote_open_server(struct remote_handle *hndle,char **argv)
{
  //Use SSH rather than direct connection
  if(!hndle->port) {
    //Double pipe for comms from client to server
    if(socketpair(AF_UNIX,SOCK_STREAM,0,hndle->paircs)<0) {
      RAISE(E_IOERROR,NULL,"Unable to create sockets\n");
    };

    //Double pipe for comms from server to client
    if(socketpair(AF_UNIX,SOCK_STREAM,0,hndle->pairsc)<0) {
      RAISE(E_IOERROR,NULL,"Unable to create sockets\n");
    };
  
    signal(SIGCHLD,child_exit);
    
    hndle->pid=fork();
    if(hndle->pid<0) perror("fork");
    //Child redirects stdin/out to the socket pair
    if(!hndle->pid) {
      close(hndle->pairsc[1]);
      dup2(hndle->pairsc[0],1);
      close(hndle->paircs[0]);
      dup2(hndle->paircs[1],0);
      
      execvp(argv[0],argv);
      RAISE(E_IOERROR,NULL,"Unable to execve %s\n",argv[0]);
    };
  } else {
    int fd;
    struct sockaddr_in s;
    int size=sizeof(s);
    struct hostent *ip;
    
    fd = socket (PF_INET, SOCK_STREAM, 0);
    if(fd<0) RAISE(E_IOERROR,NULL,"Cant create socket");

    ip=gethostbyname(hndle->host);

    s.sin_family=AF_INET;
    s.sin_port=htons(hndle->port);
			
    memcpy(&s.sin_addr.s_addr,ip->h_addr_list[0],
	   sizeof(s.sin_addr.s_addr));	    

    if(connect(fd,(struct sockaddr *)&s,size)<0) 
      RAISE(E_IOERROR,NULL,"Unable to connect to %s",hndle->host);
    
    hndle->paircs[0]=fd;
    hndle->pairsc[1]=fd;
  };
};

void remote_read_response(struct remote_handle *hndle,char **buf,int *length)
{
  int len,packetsize=0;
  int total_len;
  int status;
  char *idx;

  *buf=(char *)malloc(BUFSIZE);
  
  if(*buf==NULL) RAISE(E_NOMEMORY,NULL,"Cant malloc for read\n");
  len=read(hndle->pairsc[1],*buf,BUFSIZE);
  if(len<=0) RAISE(E_IOERROR,NULL,"Can not read from socket pair\n");
  total_len=len;
  
  (*buf)[len]=0;
  if(sscanf(*buf,"%u",&packetsize)!=1) RAISE(E_IOERROR,"Error returned from server: \"%s\"\n",*buf);
  
  //Grow the buffer to accept the packet
  *buf=realloc(*buf,packetsize);
  while(total_len<packetsize) {
    len=read(hndle->pairsc[1],*buf+total_len,packetsize-total_len);
    if(len==0) RAISE(E_IOERROR,NULL,"Packet sent is too short: %u instead of %u\n",total_len,packetsize);
    if(len<0) RAISE(E_IOERROR,NULL,"Unable to read from socketpair\n");
      total_len+=len;
  };

  //Work out the return status:
  if(sscanf(*buf,"%u,%u:",length,&status)<2)
    RAISE(E_IOERROR,NULL,"Error in parsing server reply: %s",*buf);
  
  if(status>500) {
    RAISE(E_IOERROR,NULL,"Server returned an error: %s",*buf);
  };

  //Move the data back to the start of the buffer, trashing the servers reply:
  idx=index(*buf,':')+1;
  *length-=(idx-*buf);
  memmove(*buf,idx,*length);
};

void remote_read_data(struct remote_handle *hndle,long long unsigned int offset, char **data, unsigned int *length)
{
  char tmp[BUFSIZE];
  int len;

  len=snprintf(tmp,BUFSIZE-1,"%llu,%u",offset,*length);
  //Send request:
  write(hndle->paircs[0],tmp,len);
  //Get response
  remote_read_response(hndle,data,length);

  //  printf("Got response %s\n",*data);
};

void test_harness(struct remote_handle *hndle,char *filename) {
  int fd1;
  long long unsigned int offset;
  int count=0;
  int read_size;
  char *data1,*data2;
  int length;

  fd1=open(filename,O_RDONLY|O_BINARY);
  
  while(1) {
    count++;
    offset= 1+(rand() % 1000000);
    read_size = 1+(rand() % 1000000);

    data1=(char *)malloc(read_size+1024);
    
    lseek(fd1,offset,SEEK_SET);
    //Let read_size adjust in case its too big for this file.
    read_size=read(fd1,data1,read_size);
    length=read_size;
    remote_read_data(hndle,offset,&data2,&length);
    if(length!=read_size) 
      printf("Could not read as many bytes as I need: read %u@%llu, wanted %u\n",length,offset,read_size);

    if(!memcmp(data1,data2,read_size)) {
      printf("Passed test %u,  read %u bytes from offset %llu\n",count,read_size,offset);
    } else {
      printf("Failed test %u: %u@%llu : %s\n############\n%s\n",count,length,offset,data1,data2);
    };

    free(data1);
    free(data2);
  };
};

/*
int main() {
  char *argv[8];

  argv[0]="ssh";
  argv[1]="localhost";
  argv[2]="/home/mic/junkcode/remote/remote_server";
  argv[3]="/var/tmp/test_image.dd";
  argv[4]=0;

  remote_open_server(argv);

  test_harness(argv[3]);
  return 0;
};
*/
