#ifndef __ECC_H
#define __ECC_H

/******************************************************************************/
/* the degree of the field polynomial */
#define DEGREE 163

/* don't touch this */
#define MARGIN 3

#define NUMWORDS ((DEGREE + MARGIN + 31) / 32)

#define SIZEOF_CHALLENGE 4*NUMWORDS*2

/** This function retrieves the session key in key based on decrypting
    challenge using the private key. This function is only available
    in the controller (who has the private key).
 */
int ecc_get_key(char key[16], char challenge[SIZEOF_CHALLENGE], 
		char private_key[SIZEOF_CHALLENGE/2]);
void ecc_make_key(char key[16], char challenge[SIZEOF_CHALLENGE]);

void ecc_init(void);

#define MACRO(A) do { A; } while(0)
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define CHARS2INT(ptr) ntohl(*(uint32_t*)(ptr))
#define INT2CHARS(ptr, val) MACRO( *(uint32_t*)(ptr) = htonl(val) )

#endif
