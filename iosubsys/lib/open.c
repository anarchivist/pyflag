//A test file for iosource hooker.

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
  int fd;
  char buf[100];

  fd=open("/tmp/test.txt",O_CREAT|O_RDWR , S_IRWXU);
  write(fd,"Hello\n",6);
  lseek(fd,0,SEEK_SET);
  read(fd,buf,6);
  buf[6]=0;
  printf("File containes %s\n",buf);
  close(fd);

  exit(1);
}
