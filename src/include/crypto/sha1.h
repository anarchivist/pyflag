typedef struct {
  unsigned long state[5];
  unsigned long count[2];
  unsigned char buffer[64];
} SHA_CTX;

void SHA1_Transform(unsigned long state[5], unsigned char buffer[64]);
int SHA1_Init(SHA_CTX* context);
int SHA1_Update(SHA_CTX* context, unsigned char* data, unsigned int len);
int SHA1_Final(unsigned char digest[20], SHA_CTX* context);
