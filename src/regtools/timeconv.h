#include <time.h>

typedef unsigned int DWORD;
typedef unsigned short int WORD;
typedef unsigned char BYTE;
typedef unsigned int UINT32;

# pragma pack (1)

typedef struct {
  unsigned int dwLowDateTime;
  unsigned int dwHighDateTime;
} FILETIME;

time_t fileTimeToUnixTime( const FILETIME *filetime, DWORD *remainder );
char * fileTimeToAscii (const FILETIME *filetime);
struct tm * fileTimeToStructTM (const FILETIME *filetime);

