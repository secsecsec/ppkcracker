#ifndef PUTTY_COMMON_H
#define PUTTY_COMMON_H

#include <stddef.h>		       /* for size_t */
#include <string.h>		       /* for memcpy() */
#include <stdio.h>

/* #define MALLOC_LOG  do this if you suspect putty of leaking memory */
#define smalloc(z) safemalloc(z,1)
#define snmalloc safemalloc
#define srealloc(y,z) saferealloc(y,z,1)
#define snrealloc saferealloc
#define sfree safefree

void *safemalloc(size_t, size_t);
void *saferealloc(void *, size_t, size_t);
void safefree(void *);

/*
 * Direct use of smalloc within the code should be avoided where
 * possible, in favour of these type-casting macros which ensure
 * you don't mistakenly allocate enough space for one sort of
 * structure and assign it to a different sort of pointer.
 */
#define snew(type) ((type *)snmalloc(1, sizeof(type)))
#define snewn(n, type) ((type *)snmalloc((n), sizeof(type)))
#define sresize(ptr, n, type) \
    ((type *)snrealloc((sizeof((type *)0 == (ptr)), (ptr)), (n), sizeof(type)))

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

typedef struct Filename Filename;

#ifndef lenof
#define lenof(x) ( (sizeof((x))) / (sizeof(*(x))))
#endif

#ifndef min
#define min(x,y) ( (x) < (y) ? (x) : (y) )
#endif
#ifndef max
#define max(x,y) ( (x) > (y) ? (x) : (y) )
#endif

#define GET_32BIT_LSB_FIRST(cp) \
  (((unsigned long)(unsigned char)(cp)[0]) | \
  ((unsigned long)(unsigned char)(cp)[1] << 8) | \
  ((unsigned long)(unsigned char)(cp)[2] << 16) | \
  ((unsigned long)(unsigned char)(cp)[3] << 24))

#define PUT_32BIT_LSB_FIRST(cp, value) ( \
  (cp)[0] = (unsigned char)(value), \
  (cp)[1] = (unsigned char)((value) >> 8), \
  (cp)[2] = (unsigned char)((value) >> 16), \
  (cp)[3] = (unsigned char)((value) >> 24) )

#define GET_16BIT_LSB_FIRST(cp) \
  (((unsigned long)(unsigned char)(cp)[0]) | \
  ((unsigned long)(unsigned char)(cp)[1] << 8))

#define PUT_16BIT_LSB_FIRST(cp, value) ( \
  (cp)[0] = (unsigned char)(value), \
  (cp)[1] = (unsigned char)((value) >> 8) )

#define GET_32BIT_MSB_FIRST(cp) \
  (((unsigned long)(unsigned char)(cp)[0] << 24) | \
  ((unsigned long)(unsigned char)(cp)[1] << 16) | \
  ((unsigned long)(unsigned char)(cp)[2] << 8) | \
  ((unsigned long)(unsigned char)(cp)[3]))

#define GET_32BIT(cp) GET_32BIT_MSB_FIRST(cp)

#define PUT_32BIT_MSB_FIRST(cp, value) ( \
  (cp)[0] = (unsigned char)((value) >> 24), \
  (cp)[1] = (unsigned char)((value) >> 16), \
  (cp)[2] = (unsigned char)((value) >> 8), \
  (cp)[3] = (unsigned char)(value) )

#define PUT_32BIT(cp, value) PUT_32BIT_MSB_FIRST(cp, value)

#define GET_16BIT_MSB_FIRST(cp) \
  (((unsigned long)(unsigned char)(cp)[0] << 8) | \
  ((unsigned long)(unsigned char)(cp)[1]))

#define PUT_16BIT_MSB_FIRST(cp, value) ( \
  (cp)[0] = (unsigned char)((value) >> 8), \
  (cp)[1] = (unsigned char)(value) )

#define SSH_CIPHER_IDEA		1
#define SSH_CIPHER_DES		2
#define SSH_CIPHER_3DES		3
#define SSH_CIPHER_BLOWFISH	6

typedef unsigned int uint32;
typedef uint32 word32;

struct ssh2_userkey {
    const struct ssh_signkey *alg;     /* the key algorithm */
    void *data;			       /* the key data */
    char *comment;		       /* the key comment */
};

/* The maximum length of any hash algorithm used in kex. (bytes) */
#define SSH2_KEX_MAX_HASH_LEN (32) /* SHA-256 */

extern int base64_decode_atom(char *atom, unsigned char *out);
extern int base64_lines(int datalen);
extern void base64_encode_atom(unsigned char *data, int n, char *out);
extern void base64_encode(FILE *fp, unsigned char *data, int datalen, int cpl);

/* ssh2_load_userkey can return this as an error */
extern struct ssh2_userkey ssh2_wrong_passphrase;
#define SSH2_WRONG_PASSPHRASE (&ssh2_wrong_passphrase)

enum {
    SSH_KEYTYPE_UNOPENABLE,
    SSH_KEYTYPE_UNKNOWN,
    SSH_KEYTYPE_SSH1, SSH_KEYTYPE_SSH2,
    SSH_KEYTYPE_OPENSSH, SSH_KEYTYPE_SSHCOM
};

#endif
