#include "remote.h"

/* This function sends an error reply to the client. It can formulate
   a more detailed explanation of the error */
void send_error(int outfd,const char *message, ...)
{
  va_list ap;
  char *data=NULL;
  char tmp[BUFFERSIZE];
  int len,tmplen;

  va_start(ap, message);
  len=vasprintf(&data,message, ap);
  va_end(ap);

  if(len<0) RAISE(E_NOMEMORY,NULL,"Error, unable to vasprinf");
  tmplen = snprintf(tmp,BUFFERSIZE-1,"%010u,",len+10);
  write(outfd,tmp,tmplen);
  write(outfd,data,len);
  free(data);
};

/* This function sends a reply to the client. */
void send_data(int outfd,const char *data,int len)
{
  char *buffer=(char *)malloc(len+100);
  int tmplen;
  const char *format="%010u,200:";
  const int length_of_format=15;

  if(buffer==NULL) RAISE(E_NOMEMORY,NULL,"Malloc error");
  tmplen = snprintf(buffer,BUFFERSIZE-1,format,len+length_of_format);
  memcpy(buffer+length_of_format,data,len);
  //  printf("Sending %s to client",buffer);
  write(outfd,buffer,len+length_of_format);
  free(buffer);
};

int main(int argc, char **argv) {
  char inbuf[BUFFERSIZE];
  int len;
  char *buffer;
  int infd=0;
  int outfd=1;
  char *filename = argv[1];
  int fd;
  long long unsigned int offset;
  unsigned int length;
  unsigned int port=0;

  if(argc<2) RAISE(E_GENERIC,NULL,"Usage: %s filename\n",argv[0]);

  //The user wants us to listen on TCP port rather than use stdin/out
  if(argc==3) {
    port=atoi(argv[2]);
    
    //FIXME - implement a simple tcp server here...
    
  };

  fd=open(filename,O_RDONLY);
  if(fd<0) {
    RAISE(E_IOERROR,NULL,"Unable to open %s",filename);
  }; 

  while(1) {
    struct timeval tv;
    fd_set rfds;

    FD_ZERO(&rfds);
    FD_SET(infd, &rfds);

    /* Wait up to five seconds. */
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    
    if(select(1+infd, &rfds, NULL, NULL, &tv)<=0)
      //Inactivity for 5 seconds, terminating:
      exit(0);

    len=read(infd,inbuf,BUFFERSIZE-1);
    if(len==0) exit(0);
    if(len<0) RAISE(E_IOERROR,NULL,"Cant read from filedescriptor\n",infd);
    inbuf[len]=0;

    len=sscanf(inbuf,"%llu,%u",&offset,&length);
    if(len<2) {
      send_error(outfd,"501: Only matched %d args in input\n",len);
      continue;
    };

    //Get the data back to the client:
    lseek(fd,offset,SEEK_SET);
    buffer=(char *)malloc(length);
    if(buffer==NULL) send_error(outfd,"505: Unable to malloc");

    len=read(fd,buffer,length);
    send_data(outfd,buffer,len);
    free(buffer);
  };

};
