/************************************************************************
   This is an implementation of the rc4 encryption algorithm.
************************************************************************/
#include "rc4.h"

RC4 RC4_Con(RC4 self, unsigned char *key, int len) {
  unsigned int k,i,j;

  /** Initialisation */
  for(i=0, k=0; i<=255;i++) {
    self->Sbox[i]=i;
  };

  /** Key schedule */
  self->j = 0;
  self->i = 0;

  for(i=0,j=0; i<=255; i++) {
    j = (j + self->Sbox[i] + key[i % len]) % 256;
    k = self->Sbox[i];
    self->Sbox[i] = self->Sbox[j];
    self->Sbox[j] = k;
  }

  return self;
};

/** Pull the next character from the PRNG */
unsigned char RC4_getc(RC4 self) {
  unsigned int k;

  self->i = (self->i + 1) % 256;
  self->j = (self->j + self->Sbox[self->i]) % 256;

  k = self->Sbox[self->i];
  self->Sbox[self->i] = self->Sbox[self->j];
  self->Sbox[self->j] = k;


  return self->Sbox[(self->Sbox[self->i] + self->Sbox[self->j]) % 256];

};

void RC4_crypt(RC4 self, unsigned char *data, int len) {
  int i;

  for(i=0; i<len; i++) {
    data[i] ^= self->getchar(self);
  };
};

VIRTUAL(RC4, Object)
     VMETHOD(Con) = RC4_Con;
     VMETHOD(crypt) = RC4_crypt;
     VMETHOD(getchar) = RC4_getc;
END_VIRTUAL
