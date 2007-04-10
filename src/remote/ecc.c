/** This is an implementation of ECC
 
This program implements the ECIES public key encryption scheme based on the
NIST B163 elliptic curve and the XTEA block cipher. The code was written
as an accompaniment for an article published in phrack #63 and is released to
the public domain.
*/

#include <string.h>
#include <fcntl.h>
#include "ecc.h"
#include "pki.h"
#include <stdint.h>
#include <arpa/inet.h>
#include <unistd.h>

#define DEV_RANDOM "/dev/urandom"

#define FATAL(s) MACRO( perror(s); exit(255) )

/** This is an implementation of XTEA which is required to do the hash
    of the ecc key into the 16 bit keyspace. 
*/

void XTEA_init_key(uint32_t *k, const char *key)
{
  k[0] = CHARS2INT(key + 0); k[1] = CHARS2INT(key + 4);
  k[2] = CHARS2INT(key + 8); k[3] = CHARS2INT(key + 12);
}

/* the XTEA block cipher */
void XTEA_encipher_block(char *data, const uint32_t *k)
{
  uint32_t sum = 0, delta = 0x9e3779b9, y, z;
  int i;
  y = CHARS2INT(data); z = CHARS2INT(data + 4);
  for(i = 0; i < 32; i++) {
    y += ((z << 4 ^ z >> 5) + z) ^ (sum + k[sum & 3]);
    sum += delta;
    z += ((y << 4 ^ y >> 5) + y) ^ (sum + k[sum >> 11 & 3]);
  }
  INT2CHARS(data, y); INT2CHARS(data + 4, z);
}

/* modified(!) Davies-Meyer construction.*/
void XTEA_davies_meyer(char *out, const char *in, int ilen)
{
  uint32_t k[4];
  char buf[8];
  int i;
  memset(out, 0, 8);
  while(ilen--) {
    XTEA_init_key(k, in);
    memcpy(buf, out, 8);
    XTEA_encipher_block(buf, k);
    for(i = 0; i < 8; i++)
      out[i] ^= buf[i];
    in += 16;
  }
}


/* the following type will represent bit vectors of length (DEGREE+MARGIN) */
typedef uint32_t bitstr_t[NUMWORDS];

typedef bitstr_t exp_t;

/* this type will represent field elements */
typedef bitstr_t elem_t;

     /* some basic bit-manipulation routines that act on these vectors follow */
#define bitstr_getbit(A, idx) ((A[(idx) / 32] >> ((idx) % 32)) & 1)
#define bitstr_setbit(A, idx) MACRO( A[(idx) / 32] |= 1 << ((idx) % 32) )
#define bitstr_clrbit(A, idx) MACRO( A[(idx) / 32] &= ~(1 << ((idx) % 32)) )

#define bitstr_clear(A) MACRO( memset(A, 0, sizeof(bitstr_t)) )
#define bitstr_copy(A, B) MACRO( if(A!=B) memcpy(A, B, sizeof(bitstr_t)) )
#define bitstr_swap(A, B) MACRO( bitstr_t h; \
  bitstr_copy(h, A); bitstr_copy(A, B); bitstr_copy(B, h) )
#define bitstr_is_equal(A, B) (! memcmp(A, B, sizeof(bitstr_t)))

void get_random_exponent(exp_t exp);
void bitstr_import(bitstr_t x, const char *s);

static int bitstr_is_clear(const bitstr_t x)
{
  int i;
  for(i = 0; i < NUMWORDS && ! *x++; i++);
  return i == NUMWORDS;
}

/* return the number of the highest one-bit + 1 */
static int bitstr_sizeinbits(const bitstr_t x)
{
  int i;
  uint32_t mask;
  for(x += NUMWORDS, i = 32 * NUMWORDS; i > 0 && ! *--x; i -= 32);
  if (i)
    for(mask = 1 << 31; ! (*x & mask); mask >>= 1, i--);
  return i;
}

/* left-shift by 'count' digits */
static void bitstr_lshift(bitstr_t A, const bitstr_t B, int count)
{
  int i, offs = 4 * (count / 32);
  memmove((void*)A + offs, B, sizeof(bitstr_t) - offs);
  memset(A, 0, offs);
  if (count %= 32) {
    for(i = NUMWORDS - 1; i > 0; i--)
      A[i] = (A[i] << count) | (A[i - 1] >> (32 - count));
    A[0] <<= count;
  }
}

/* (raw) import from a byte array */
void bitstr_import(bitstr_t x, const char *s)
{
  int i;
  for(x += NUMWORDS, i = 0; i < NUMWORDS; i++, s += 4)
    *--x = CHARS2INT(s);
}

/* (raw) export to a byte array */
static void bitstr_export(char *s, const bitstr_t x)
{
  int i;
  for(x += NUMWORDS, i = 0; i < NUMWORDS; i++, s += 4)
    INT2CHARS(s, (*--x));
}

/* the reduction polynomial */
elem_t poly;

#define field_set1(A) MACRO( A[0] = 1; memset(A + 1, 0, sizeof(elem_t) - 4) )

static int field_is1(const elem_t x)
{
  int i;
  if (*x++ != 1) return 0;
  for(i = 1; i < NUMWORDS && ! *x++; i++);
  return i == NUMWORDS;
}

/* field addition */
static void field_add(elem_t z, const elem_t x, const elem_t y)  
{
  int i;
  for(i = 0; i < NUMWORDS; i++)
    *z++ = *x++ ^ *y++;
}

#define field_add1(A) MACRO( A[0] ^= 1 )

/* field multiplication */
static void field_mult(elem_t z, const elem_t x, const elem_t y)
{
  elem_t b;
  int i, j;
  /* assert(z != y); */
  bitstr_copy(b, x);
  if (bitstr_getbit(y, 0))
    bitstr_copy(z, x);
  else
    bitstr_clear(z);
  for(i = 1; i < DEGREE; i++) {
    for(j = NUMWORDS - 1; j > 0; j--)
      b[j] = (b[j] << 1) | (b[j - 1] >> 31);
    b[0] <<= 1;
    if (bitstr_getbit(b, DEGREE))
      field_add(b, b, poly);
    if (bitstr_getbit(y, i))
      field_add(z, z, b);
  }
}

/* field inversion */
static void field_invert(elem_t z, const elem_t x)
{
  elem_t u, v, g, h;
  int i;
  bitstr_copy(u, x);
  bitstr_copy(v, poly);
  bitstr_clear(g);
  field_set1(z);
  while (! field_is1(u)) {
    i = bitstr_sizeinbits(u) - bitstr_sizeinbits(v);
    if (i < 0) {
      bitstr_swap(u, v); bitstr_swap(g, z); i = -i;
    }
    bitstr_lshift(h, v, i);
    field_add(u, u, h);
    bitstr_lshift(h, g, i);
    field_add(z, z, h);
  }
}

/******************************************************************************/

/* The following routines do the ECC arithmetic. Elliptic curve points
   are represented by pairs (x,y) of elem_t. It is assumed that curve
   coefficient 'a' is equal to 1 (this is the case for all NIST binary
   curves). Coefficient 'b' is given in 'coeff_b'.  '(base_x, base_y)'
   is a point that generates a large prime order group.             */

elem_t coeff_b, base_x, base_y;

#define point_is_zero(x, y) (bitstr_is_clear(x) && bitstr_is_clear(y))
#define point_set_zero(x, y) MACRO( bitstr_clear(x); bitstr_clear(y) )
#define point_copy(x1, y1, x2, y2) MACRO( bitstr_copy(x1, x2); \
                                          bitstr_copy(y1, y2) )

/* double the point (x,y) */
static void point_double(elem_t x, elem_t y)      
{
  if (! bitstr_is_clear(x)) {
    elem_t a;
    field_invert(a, x);
    field_mult(a, a, y);
    field_add(a, a, x);
    field_mult(y, x, x);
    field_mult(x, a, a);
    field_add1(a);        
    field_add(x, x, a);
    field_mult(a, a, x);
    field_add(y, y, a);
  }
  else
    bitstr_clear(y);
}

/* add two points together (x1, y1) := (x1, y1) + (x2, y2) */
static void point_add(elem_t x1, elem_t y1, const elem_t x2, const elem_t y2)
{
  if (! point_is_zero(x2, y2)) {
    if (point_is_zero(x1, y1))
      point_copy(x1, y1, x2, y2);
    else {
      if (bitstr_is_equal(x1, x2)) {
	if (bitstr_is_equal(y1, y2))
	  point_double(x1, y1);
	else 
	  point_set_zero(x1, y1);
      }
      else {
	elem_t a, b, c, d;
	field_add(a, y1, y2);
	field_add(b, x1, x2);
	field_invert(c, b);
	field_mult(c, c, a);
	field_mult(d, c, c);
	field_add(d, d, c);
	field_add(d, d, b);
	field_add1(d);
	field_add(x1, x1, d);
	field_mult(a, x1, c);
	field_add(a, a, d);
	field_add(y1, y1, a);
	bitstr_copy(x1, d);
      }
    }
  }
}

/******************************************************************************/
exp_t base_order;

/* point multiplication via double-and-add algorithm */
static void point_mult(elem_t x, elem_t y, const exp_t exp)
{
  elem_t X, Y;
  int i;
  point_set_zero(X, Y);
  for(i = bitstr_sizeinbits(exp) - 1; i >= 0; i--) {
    point_double(X, Y);
    if (bitstr_getbit(exp, i))
      point_add(X, Y, x, y);
  }
  point_copy(x, y, X, Y);
}

#ifndef WINDOWS
/* draw a random value 'exp' with 1 <= exp < n */
void get_random_exponent(exp_t exp)
{
  char buf[4 * NUMWORDS];
  int fh, r, s;
  do {
    if ((fh = open(DEV_RANDOM, O_RDONLY)) < 0)
      return;
    for(r = 0; r < 4 * NUMWORDS; r += s)
      if ((s = read(fh, buf + r, 4 * NUMWORDS - r)) <= 0)
	return;
    if (close(fh) < 0)
      return;
    bitstr_import(exp, buf);
    for(r = bitstr_sizeinbits(base_order) - 1; r < NUMWORDS * 32; r++)
      bitstr_clrbit(exp, r);
  } while(bitstr_is_clear(exp));
}

#else

#include <wincrypt.h>

static HCRYPTPROV hProvider=0;

/* draw a random value 'exp' with 1 <= exp < n */
void get_random_exponent(exp_t exp)
{
  char buf[4 * NUMWORDS];
  int r;

  if(!hProvider) {
    if(!CryptAcquireContext(&hProvider, 0, 0, PROV_RSA_FULL, 
			    CRYPT_VERIFYCONTEXT))
      DEBUG("Unable to initialise PRNG\n");
  };

  

  do {
    CryptGenRandom(hProvider, sizeof(buf), buf);

    bitstr_import(exp, buf);
    for(r = bitstr_sizeinbits(base_order) - 1; r < NUMWORDS * 32; r++)
      bitstr_clrbit(exp, r);
  } while(bitstr_is_clear(exp));
}

#endif



/* a non-standard KDF */
static void ECIES_kdf(char *k1, const elem_t Zx,
	       const elem_t Rx, const elem_t Ry)
{
  int bufsize = (3 * (4 * NUMWORDS) + 1 + 15) & ~15;
  char buf[bufsize];
  memset(buf, 0, bufsize);
  bitstr_export(buf, Zx);
  bitstr_export(buf + 4 * NUMWORDS, Rx);
  bitstr_export(buf + 8 * NUMWORDS, Ry);
  buf[12 * NUMWORDS] = 0; XTEA_davies_meyer(k1, buf, bufsize / 16);
  buf[12 * NUMWORDS] = 1; XTEA_davies_meyer(k1 + 8, buf, bufsize / 16);
}

/* check if y^2 + x*y = x^3 + *x^2 + coeff_b holds */
static int is_point_on_curve(const elem_t x, const elem_t y)
{
  elem_t a, b;
  if (point_is_zero(x, y))
    return 1;
  field_mult(a, x, x);
  field_mult(b, a, x);
  field_add(a, a, b);
  field_add(a, a, coeff_b);
  field_mult(b, y, y);
  field_add(a, a, b);
  field_mult(b, x, y);
  return bitstr_is_equal(a, b);
}

/* check that a given elem_t-pair is a valid point on the curve != 'o' */
static int ECIES_embedded_public_key_validation(const elem_t Px, 
						const elem_t Py)
{
  return (bitstr_sizeinbits(Px) > DEGREE) || (bitstr_sizeinbits(Py) > DEGREE) ||
    point_is_zero(Px, Py) || ! is_point_on_curve(Px, Py) ? -1 : 1;
};

/** This function comes up with a session key in key, and a challenge
    which will be copied into challenge. The key is derivable from the
    challenge if you know the private key. Therefore the challenge is
    suitable to send directly. 
*/
void ecc_make_key(char key[16], char challenge[SIZEOF_CHALLENGE]) {
  elem_t Rx, Ry, Zx, Zy;
  exp_t k;

  do {
    /** Get a random seed for the session key */
    get_random_exponent(k);

    /** Read in the public keys */
    bitstr_import(Zx, Pubx);
    bitstr_import(Zy, Puby);

    /** Find a point on the curve */
    point_mult(Zx, Zy, k);
    
    /* cofactor h = 2 on B163 */
    point_double(Zx, Zy);    

    /** Make sure the point is not zero */
  } while(point_is_zero(Zx, Zy));

  point_copy(Rx, Ry, base_x, base_y);

  /** Find another point on the curve */
  point_mult(Rx, Ry, k);

  /** Work out the session key */
  ECIES_kdf(key, Zx, Rx, Ry);

  /** We need to send the other end Rx and Ry: */
  bitstr_export(challenge, Rx);
  bitstr_export(challenge + 4 * NUMWORDS, Ry);
};

/** This function retrieves the session key in key based on decrypting
    challenge using the private key.
 */
int ecc_get_key(char key[16], char challenge[sizeof(elem_t)*2], char private_key[sizeof(elem_t)]) {
  elem_t Rx, Ry, Zx, Zy;
  exp_t d;

  bitstr_import(Rx, challenge);
  bitstr_import(Ry, challenge + 4 * NUMWORDS);
  if (ECIES_embedded_public_key_validation(Rx, Ry) < 0)
    return 0;
  bitstr_import(d, private_key);
  point_copy(Zx, Zy, Rx, Ry);
  point_mult(Zx, Zy, d);
  point_double(Zx, Zy);                   /* cofactor h = 2 on B163 */
  if (point_is_zero(Zx, Zy))
    return 0;

  ECIES_kdf(key, Zx, Rx, Ry);
  return 1;
};

void ecc_init(void) {
  bitstr_import(poly, POLY);
  bitstr_import(coeff_b, COEFF_B);
  bitstr_import(base_x, BASE_X);
  bitstr_import(base_y, BASE_Y);
  bitstr_import(base_order, BASE_ORDER);
};
