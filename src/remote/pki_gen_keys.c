/* 
   This program builds new public/private key pairs for pyflag. It
   outputs pki.h which includes keys as well as constants.
*/
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <netinet/in.h>
#include "ecc.h"

#define DEV_RANDOM "/dev/urandom"

#define FATAL(s) MACRO( perror(s); exit(255) )

/******************************************************************************/

#define DEGREE 163                      /* the degree of the field polynomial */
#define MARGIN 3                                          /* don't touch this */
#define NUMWORDS ((DEGREE + MARGIN + 31) / 32)

   /* the following type will represent bit vectors of length (DEGREE+MARGIN) */
typedef uint32_t bitstr_t[NUMWORDS];

     /* some basic bit-manipulation routines that act on these vectors follow */
#define bitstr_getbit(A, idx) ((A[(idx) / 32] >> ((idx) % 32)) & 1)
#define bitstr_setbit(A, idx) MACRO( A[(idx) / 32] |= 1 << ((idx) % 32) )
#define bitstr_clrbit(A, idx) MACRO( A[(idx) / 32] &= ~(1 << ((idx) % 32)) )

#define bitstr_clear(A) MACRO( memset(A, 0, sizeof(bitstr_t)) )
#define bitstr_copy(A, B) MACRO( memcpy(A, B, sizeof(bitstr_t)) )
#define bitstr_swap(A, B) MACRO( bitstr_t h; \
  bitstr_copy(h, A); bitstr_copy(A, B); bitstr_copy(B, h) )
#define bitstr_is_equal(A, B) (! memcmp(A, B, sizeof(bitstr_t)))

/* this type will represent field elements */
typedef bitstr_t elem_t;

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
static void bitstr_import(bitstr_t x, const char *s)
{
  int i;
  for(x += NUMWORDS, i = 0; i < NUMWORDS; i++, s += 4)
    *--x = CHARS2INT(s);
}


/* import from a hex string */
static int bitstr_parse(bitstr_t x, const char *s)
{
  int len;
  if ((s[len = strspn(s, "0123456789abcdefABCDEF")]) ||
      (len > NUMWORDS * 8))
    return -1;
  bitstr_clear(x);
  x += len / 8;
  if (len % 8) {
    sscanf(s, "%08x", x);
    *x >>= 32 - 4 * (len % 8);
    s += len % 8;
    len &= ~7;
  }
  for(; *s; s += 8)
    sscanf(s, "%08x", --x);
  return len;
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

static void field_add(elem_t z, const elem_t x, const elem_t y)    /* field addition */
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

static void field_invert(elem_t z, const elem_t x)                /* field inversion */
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


static void point_double(elem_t x, elem_t y)               /* double the point (x,y) */
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

typedef bitstr_t exp_t;

static exp_t base_order;

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

                               /* draw a random value 'exp' with 1 <= exp < n */
static void get_random_exponent(exp_t exp)
{
  char buf[4 * NUMWORDS];
  int fh, r, s;
  do {
    if ((fh = open(DEV_RANDOM, O_RDONLY)) < 0)
      FATAL(DEV_RANDOM);
    for(r = 0; r < 4 * NUMWORDS; r += s)
      if ((s = read(fh, buf + r, 4 * NUMWORDS - r)) <= 0)
	FATAL(DEV_RANDOM);
    if (close(fh) < 0)
      FATAL(DEV_RANDOM);
    bitstr_import(exp, buf);
    for(r = bitstr_sizeinbits(base_order) - 1; r < NUMWORDS * 32; r++)
      bitstr_clrbit(exp, r);
  } while(bitstr_is_clear(exp));
}

#define ECIES_OVERHEAD (8 * NUMWORDS + 8)

void print_as_hex(const bitstr_t x) {
  int i,j;
  for(x += NUMWORDS, i = 0; i < NUMWORDS; i++) {
    uint32_t value=htonl((*--x));
    for( j=0; j<32; j+=8) 
      printf("\\x%02x", (value >> j) & 0xff );
  };
};

#define DEFINE(x,y)   printf("#define %s \"", #y );	\
  print_as_hex(x); printf("\"\n");

static void ECIES_generate_key_pair()
{
  elem_t x, y;
  exp_t k;
  get_random_exponent(k);
  point_copy(x, y, base_x, base_y);
  point_mult(x, y, k);

  DEFINE(x, Pubx);
  DEFINE(y,Puby);
  DEFINE(k, Priv);
}

int main()
{
  /* the coefficients for B163 */
  bitstr_parse(poly, "800000000000000000000000000000000000000c9");
  DEFINE(poly, POLY);

  bitstr_parse(coeff_b, "20a601907b8c953ca1481eb10512f78744a3205fd");
  DEFINE(coeff_b, COEFF_B);

  bitstr_parse(base_x, "3f0eba16286a2d57ea0991168d4994637e8343e36");
  DEFINE(base_x, BASE_X);

  bitstr_parse(base_y, "0d51fbc6c71a0094fa2cdd545b11c5c0c797324f1");
  DEFINE(base_y, BASE_Y);

  bitstr_parse(base_order, "40000000000000000000292fe77e70c12a4234c33");
  DEFINE(base_order, BASE_ORDER);

  ECIES_generate_key_pair();
  return 0;
}
