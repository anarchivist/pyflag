/************************************************************************
   This is an implementation of the rc4 encryption algorithm.
************************************************************************/
#ifndef __RC4_H
#define __RC4_H

#include "class.h"
#include "misc.h"

CLASS(RC4, Object)
     unsigned char Sbox[256];
     int i,j;

     RC4 METHOD(RC4, Con, unsigned char *key, int len);
     unsigned char METHOD(RC4, getchar);

     /** This changes the data in place */
     void METHOD(RC4, crypt, unsigned char *data, int len);
END_CLASS

#define SIZE_OF_IV 4
#define MIN_KEY_SIZE BUFF_SIZE

// This initialises the key with a new IV
void rc4_init_key(char *key, int *key_len);

#endif
