
#ifndef __COMMON_H
#define __COMMON_H

#ifdef __WIN32__
  typedef struct {
	  unsigned int dwLowDateTime;
    unsigned int dwHighDateTime;
  } FILETIME;

  typedef unsigned int DWORD;
  typedef unsigned short int WORD;
  typedef unsigned char BYTE;
  typedef unsigned int UINT32;

# pragma pack (1)

#endif // _WIN32
#endif // __COMMON_H
