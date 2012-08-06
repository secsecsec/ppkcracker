/* Modified in July 2012 by Dhiru Kholia <dhiru at openwall.com> to be
 * standalone and compilable.
 *
 * p-ppk-crack v0.5 made by michu@neophob.com — PuTTY private key cracker
 *
 * Source code based on putty svn version, check
 * http://chiark.greenend.org.uk/~sgtatham/putty/licence.html. */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <limits.h>
#include "ssh.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

typedef struct Filename {
    char path[4096];
} Filename;

#define PASSPHRASE_MAXLEN 512

void safefree(void *ptr)
{
    if (ptr) {
#ifdef MALLOC_LOG
        if (fp)
            fprintf(fp, "free(%p)\n", ptr);
#endif
#ifdef MINEFIELD
        minefield_c_free(ptr);
#else
        free(ptr);
#endif
    }
#ifdef MALLOC_LOG
    else if (fp)
        fprintf(fp, "freeing null pointer - no action taken\n");
#endif
}

char header[40], *b, *encryption, *comment, *mac;
const char *error = NULL;
int i, is_mac, old_fmt;
char alg[8];
int cipher, cipherblk;
unsigned char *public_blob, *private_blob;
unsigned char *public_blobXX, *private_blobXX;
int public_blob_len, private_blob_len;

void *safemalloc(size_t n, size_t size)
{
    void *p;

    if (n > INT_MAX / size) {
        p = NULL;
    } else {
        size *= n;
        if (size == 0) size = 1;
#ifdef MINEFIELD
        p = minefield_c_malloc(size);
#else
        p = malloc(size);
#endif
    }

    if (!p) {
        char str[200];
#ifdef MALLOC_LOG
        sprintf(str, "Out of memory! (%s:%d, size=%d)",
                mlog_file, mlog_line, size);
        fprintf(fp, "*** %s\n", str);
        fclose(fp);
#else
        strcpy(str, "Out of memory!");
#endif
    }
#ifdef MALLOC_LOG
    if (fp)
        fprintf(fp, "malloc(%d) returns %p\n", size, p);
#endif
    return p;
}

static char *read_body(FILE * fp)
{
	char *text;
	int len;
	int size;
	int c;

	size = 128;
	text = (char*)malloc(size);
	len = 0;
	text[len] = '\0';

	while (1) {
		c = fgetc(fp);
		if (c == '\r' || c == '\n') {
			c = fgetc(fp);
			if (c != '\r' && c != '\n' && c != EOF)
				ungetc(c, fp);
			return text;
		}
		if (c == EOF) {
			return NULL;
		}
		if (len + 1 >= size) {
			size += 128;
			// text = sresize(text, size, char);
		}
		text[len++] = c;
		text[len] = '\0';
	}
}


static unsigned char *read_blob(FILE * fp, int nlines, int *bloblen)
{
	unsigned char *blob;
	char *line;
	int linelen, len;
	int i, j, k;

	/* We expect at most 64 base64 characters, ie 48 real bytes, per line. */
	blob = (unsigned char*)malloc(48 * nlines);
	len = 0;
	for (i = 0; i < nlines; i++) {
		line = read_body(fp);
		if (!line) {
			sfree(blob);
			return NULL;
		}
		linelen = strlen(line);
		if (linelen % 4 != 0 || linelen > 64) {
			sfree(blob);
			sfree(line);
			return NULL;
		}
		for (j = 0; j < linelen; j += 4) {
			k = base64_decode_atom(line + j, blob + len);
			if (!k) {
				return NULL;
			}
			len += k;
		}
	}
	*bloblen = len;
	return blob;
}


static int read_header(FILE * fp, char *header)
{
	int len = 39;
	int c;

	while (len > 0) {
		c = fgetc(fp);
		if (c == '\n' || c == '\r' || c == EOF)
			return 0;		       /* failure */
		if (c == ':') {
			c = fgetc(fp);
			if (c != ' ')
				return 0;
			*header = '\0';
			return 1;		       /* success! */
		}
		if (len == 0)
			return 0;		       /* failure */
		*header++ = c;
		len--;
	}
	return 0;			       /* failure */
}


int verbose=0;

int init_LAME(const Filename *filename) {
	FILE *fp;

	encryption = comment = mac = NULL;
	public_blob = private_blob = NULL;

	fp = fopen(filename->path, "rb" );
	if (!fp) {
		error = "can't open file";
		goto error;
	}

	/* Read the first header line which contains the key type. */
	if (!read_header(fp, header))
		goto error;
	if (0 == strcmp(header, "PuTTY-User-Key-File-2")) {
		old_fmt = 0;
	} else if (0 == strcmp(header, "PuTTY-User-Key-File-1")) {
		/* this is an old key file; warn and then continue */
		// old_keyfile_warning();
		old_fmt = 1;
	} else {
		error = "not a PuTTY SSH-2 private key";
		goto error;
	}
	error = "file format error";
	if ((b = read_body(fp)) == NULL)
		goto error;
	/* Select key algorithm structure. */
	if (!strcmp(b, "ssh-rsa"))
		strcpy(alg, "ssh-rsa");
    	else if (!strcmp(b, "ssh-dss"))
		strcpy(alg, "ssh-dss");

	/* Read the Encryption header line. */
	if (!read_header(fp, header) || 0 != strcmp(header, "Encryption"))
		goto error;
	if ((encryption = read_body(fp)) == NULL)
		goto error;
	if (!strcmp(encryption, "aes256-cbc")) {
		cipher = 1;
		cipherblk = 16;
	} else if (!strcmp(encryption, "none")) {
		cipher = 0;
		cipherblk = 1;
	} else {
		sfree(encryption);
		goto error;
	}

	/* Read the Comment header line. */
	if (!read_header(fp, header) || 0 != strcmp(header, "Comment"))
		goto error;
	if ((comment = read_body(fp)) == NULL)
		goto error;

	/* Read the Public-Lines header line and the public blob. */
	if (!read_header(fp, header) || 0 != strcmp(header, "Public-Lines"))
		goto error;
	if ((b = read_body(fp)) == NULL)
		goto error;
	i = atoi(b);
	sfree(b);
	if ((public_blob = read_blob(fp, i, &public_blob_len)) == NULL)
		goto error;

	/* Read the Private-Lines header line and the Private blob. */
	if (!read_header(fp, header) || 0 != strcmp(header, "Private-Lines"))
		goto error;
	if ((b = read_body(fp)) == NULL)
		goto error;
	i = atoi(b);
	sfree(b);
	if ((private_blob = read_blob(fp, i, &private_blob_len)) == NULL)
		goto error;

	/* Read the Private-MAC or Private-Hash header line. */
	if (!read_header(fp, header))
		goto error;
	if (0 == strcmp(header, "Private-MAC")) {
		if ((mac = read_body(fp)) == NULL)
			goto error;
		is_mac = 1;
	} else if (0 == strcmp(header, "Private-Hash") && old_fmt) {
		if ((mac = read_body(fp)) == NULL)
			goto error;
		is_mac = 0;
	} else
		goto error;

	fclose(fp);
	fp = NULL;
	return 0;

error:
	if (fp)
		fclose(fp);
	if (comment)
		sfree(comment);
	if (encryption)
		sfree(encryption);
	if (mac)
		sfree(mac);
	if (public_blob)
		sfree(public_blob);
	if (private_blob)
		sfree(private_blob);
	return 1;
}

void SHA_Simple(void *p, int len, unsigned char *output)
{
    SHA_CTX ctx;

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, p, len);
    SHA1_Final(output, &ctx);
}

struct ssh2_userkey *LAME_ssh2_load_userkey(char *passphrase, const char **errorstr)
{
	struct ssh2_userkey *ret;
	int passlen = passphrase ? strlen(passphrase) : 0;
	const char *error = NULL;
	ret = NULL;			       /* return NULL for most errors */
	/*
	* Decrypt the private blob.
	*/
	if (cipher) {
		unsigned char key[40];
		SHA_CTX s;

		if (!passphrase)
			goto error;
		if (private_blob_len % cipherblk)
			goto error;

		SHA1_Init(&s);
		SHA1_Update(&s, (void*)"\0\0\0\0", 4);
		SHA1_Update(&s, passphrase, passlen);
		SHA1_Final(key + 0, &s);
		SHA1_Init(&s);
		SHA1_Update(&s, (void*)"\0\0\0\1", 4);
		SHA1_Update(&s, passphrase, passlen);
		SHA1_Final(key + 20, &s);
		AES_KEY akey;
	        unsigned char iv[32];
    		memset(iv, 0, 32);
        	memset(&akey, 0, sizeof(AES_KEY));
	        if(AES_set_decrypt_key(key, 256, &akey) < 0) {
			fprintf(stderr, "AES_set_derypt_key failed!\n");
		}
		AES_cbc_encrypt(private_blob, private_blob, private_blob_len, &akey, iv, AES_DECRYPT);
	}

	/*
	* Verify the MAC.
	*/
	{
		char realmac[41];
		unsigned char binary[20];
		unsigned char *macdata;
		int maclen;
		int free_macdata;

		if (old_fmt) {
			/* MAC (or hash) only covers the private blob. */
			macdata = private_blob;
			maclen = private_blob_len;
			free_macdata = 0;
		} else {
			unsigned char *p;
			int namelen = strlen(alg);
			int enclen = strlen(encryption);
			int commlen = strlen(comment);
			maclen = (4 + namelen +
				4 + enclen +
				4 + commlen +
				4 + public_blob_len +
				4 + private_blob_len);
			macdata = snewn(maclen, unsigned char);
			p = macdata;
#define DO_STR(s,len) PUT_32BIT(p,(len));memcpy(p+4,(s),(len));p+=4+(len)
			DO_STR(alg, namelen);
			DO_STR(encryption, enclen);
			DO_STR(comment, commlen);
			DO_STR(public_blob, public_blob_len);
			DO_STR(private_blob, private_blob_len);

			free_macdata = 1;
		}

		if (is_mac) {
			SHA_CTX s;
			unsigned char mackey[20];
			unsigned int length = 20;
			HMAC_CTX ctx;
			char header[] = "putty-private-key-file-mac-key";

			SHA1_Init(&s);
			SHA1_Update(&s, header, sizeof(header)-1);
			if (cipher && passphrase)
				SHA_Update(&s, passphrase, passlen);
			SHA1_Final(mackey, &s);

			HMAC_Init(&ctx, mackey, 20, EVP_sha1());
			HMAC_Update(&ctx, macdata, maclen);
			HMAC_Final(&ctx, binary, &length);


			//hmac_sha1_simple(mackey, 20, macdata, maclen, binary);

			memset(mackey, 0, sizeof(mackey));
			memset(&s, 0, sizeof(s));
		} else {
			SHA_Simple(macdata, maclen, binary);
		}

		if (free_macdata) {
			memset(macdata, 0, maclen);
			sfree(macdata);
		}

		for (i = 0; i < 20; i++)
			sprintf(realmac + 2 * i, "%02x", binary[i]);

		if (strcmp(mac, realmac)) {
			/* An incorrect MAC is an unconditional Error if the key is
			* unencrypted. Otherwise, it means Wrong Passphrase. */
			if (cipher) {
				error = "wrong passphrase";
				//ret = SSH2_WRONG_PASSPHRASE;
			} else {
				error = "MAC failed";
				ret = NULL;
			}
			goto error;
		}
	}
	sfree(mac);

	/*
	* Create and return the key.
	*/
	ret = snew(struct ssh2_userkey);
error:
	if (errorstr)
		*errorstr = error;
	return ret;
}

FILE *f_open(const Filename *filename, char const *mode, int is_private)
{
    if (!is_private) {
        return fopen(filename->path, mode);
    } else {
        int fd;
        fd = open(filename->path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0)
            return NULL;
        return fdopen(fd, mode);
    }
}



/* ----------------------------------------------------------------------
 * A function to determine the type of a private key file. Returns
 * 0 on failure, 1 or 2 on success.
 */
#define rsa_signature "SSH PRIVATE KEY FILE FORMAT 1.1\n"

int key_type(const Filename *filename)
{
    FILE *fp;
    char buf[32];
    const char putty2_sig[] = "PuTTY-User-Key-File-";
    const char sshcom_sig[] = "---- BEGIN SSH2 ENCRYPTED PRIVAT";
    const char openssh_sig[] = "-----BEGIN ";
    int i;

    fp = f_open(filename, "r", FALSE);
    if (!fp)
	return SSH_KEYTYPE_UNOPENABLE;
    i = fread(buf, 1, sizeof(buf), fp);
    fclose(fp);
    if (i < 0)
	return SSH_KEYTYPE_UNOPENABLE;
    if (i < 32)
	return SSH_KEYTYPE_UNKNOWN;
    if (!memcmp(buf, rsa_signature, sizeof(rsa_signature)-1))
	return SSH_KEYTYPE_SSH1;
    if (!memcmp(buf, putty2_sig, sizeof(putty2_sig)-1))
	return SSH_KEYTYPE_SSH2;
    if (!memcmp(buf, openssh_sig, sizeof(openssh_sig)-1))
	return SSH_KEYTYPE_OPENSSH;
    if (!memcmp(buf, sshcom_sig, sizeof(sshcom_sig)-1))
	return SSH_KEYTYPE_SSHCOM;
    return SSH_KEYTYPE_UNKNOWN;	       /* unrecognised or EOF */
}

int ssh2_userkey_encrypted(const Filename *filename, char **commentptr)
{
    FILE *fp;
    char header[40], *b, *comment;
    int ret;

    if (commentptr)
	*commentptr = NULL;

    fp = f_open(filename, "rb", FALSE);
    if (!fp)
	return 0;
    if (!read_header(fp, header)
	|| (0 != strcmp(header, "PuTTY-User-Key-File-2") &&
	    0 != strcmp(header, "PuTTY-User-Key-File-1"))) {
	fclose(fp);
	return 0;
    }
    if ((b = read_body(fp)) == NULL) {
	fclose(fp);
	return 0;
    }
    sfree(b);			       /* we don't care about key type here */
    /* Read the Encryption header line. */
    if (!read_header(fp, header) || 0 != strcmp(header, "Encryption")) {
	fclose(fp);
	return 0;
    }
    if ((b = read_body(fp)) == NULL) {
	fclose(fp);
	return 0;
    }

    /* Read the Comment header line. */
    if (!read_header(fp, header) || 0 != strcmp(header, "Comment")) {
	fclose(fp);
	sfree(b);
	return 1;
    }
    if ((comment = read_body(fp)) == NULL) {
	fclose(fp);
	sfree(b);
	return 1;
    }

    if (commentptr)
	*commentptr = comment;

    fclose(fp);
    if (!strcmp(b, "aes256-cbc"))
	ret = 1;
    else
	ret = 0;
    sfree(b);
    return ret;
}

int base64_decode_atom(char *atom, unsigned char *out)
{
    int vals[4];
    int i, v, len;
    unsigned word;
    char c;

    for (i = 0; i < 4; i++) {
        c = atom[i];
        if (c >= 'A' && c <= 'Z')
            v = c - 'A';
        else if (c >= 'a' && c <= 'z')
            v = c - 'a' + 26;
        else if (c >= '0' && c <= '9')
            v = c - '0' + 52;
        else if (c == '+')
            v = 62;
        else if (c == '/')
            v = 63;
        else if (c == '=')
            v = -1;
        else
            return 0;                  /* invalid atom */
        vals[i] = v;
    }

    if (vals[0] == -1 || vals[1] == -1)
        return 0;
    if (vals[2] == -1 && vals[3] != -1)
        return 0;

    if (vals[3] != -1)
        len = 3;
    else if (vals[2] != -1)
        len = 2;
    else
        len = 1;

    word = ((vals[0] << 18) |
            (vals[1] << 12) | ((vals[2] & 0x3F) << 6) | (vals[3] & 0x3F));
    out[0] = (word >> 16) & 0xFF;
    if (len > 1)
        out[1] = (word >> 8) & 0xFF;
    if (len > 2)
        out[2] = word & 0xFF;
    return len;
}

int main(int argc, char **argv)
{
	char pw[1024];
	FILE *fp;
	int i;

	int type, realtype;
	char *comment;
	Filename filename;

	int needs_pass = 0;
	struct ssh2_userkey *newkey2 = NULL;
	const char *errmsg = NULL;

	// printf( "%s - made by michu@neophob.com - PuTTY private key cracker\n", argv[0]);

	if (argc < 2) {
		printf( "Usage: %s [PuTTY-Private-Key-File]\n", argv[0]);
		printf( "Example:\n");
		printf( " $ john -stdout -incremental | %s id_dsa\n",argv[0]);
		printf( " $ %s id_dsa < dictionary\n", argv[0]);
		printf( "\n");
		exit(1);
	}

	/*
	* check if file exist
	*/
	if ((fp = fopen(argv[1], "r")) == NULL) {
		printf( "Error: Cannot open %s.\n", argv[1]);
		return 2;
	}
	fclose(fp);

	strcpy(filename.path, argv[1]);

	//src: winpgen.c
	type = realtype = key_type(&filename);
	if (type != SSH_KEYTYPE_SSH1 && type != SSH_KEYTYPE_SSH2) {
		fprintf(stderr, "Error: Couldn't load private key (%s)\n", filename.path);
		return 2;
	}

	if (type != SSH_KEYTYPE_SSH1 && type != SSH_KEYTYPE_SSH2) {
		realtype = type;
		//type = import_target_type(type);
	}

	comment = NULL;
	if (realtype == SSH_KEYTYPE_SSH2) {
		if (verbose==1) printf("file type: SSH_KEYTYPE_SSH2\n");
		needs_pass = ssh2_userkey_encrypted(&filename, &comment);
	}
	if (verbose==1) printf("needs_pass: %i\n",needs_pass);

	if (needs_pass==0) {
		printf("this private key doesn't need a passphrase - exit now!\n");
		return 0;
	}

	if (init_LAME(&filename)==1) {
		printf("error, not valid private key!\n");
		return 1;
	}
	// printf("len: %i/%i\n", public_blob_len, private_blob_len);
	private_blobXX=(unsigned char*)malloc(private_blob_len);
	public_blobXX=(unsigned char*)malloc(public_blob_len);

	memcpy(private_blobXX, private_blob, private_blob_len);
	memcpy(public_blobXX, public_blob, public_blob_len);


	while (fgets(pw, 1024, stdin) != NULL) {

		for (i = 0; i < 1024 && pw[i] != 10 && pw[i] != 13; i++);
		pw[i] = 0;

		if (type == SSH_KEYTYPE_SSH1) {
			fprintf(stderr, "SSH1 key type not supported!\n");
			return 3;
		} else { //SSH_KEYTYPE_SSH2
			if (realtype == type) {
				newkey2 = LAME_ssh2_load_userkey((char*) pw, &errmsg);
			}
			if (!newkey2) {
				if (verbose == 1) printf("UNKNOWN ERROR: %s\n", errmsg);
			} else {
				printf("Passphrase Found: <%s>\n", pw);
				return 0;
			}
		}
		memcpy(private_blob, private_blobXX, private_blob_len);
		memcpy(public_blob, public_blobXX, public_blob_len);

	}

	printf("\n\nDamn, couldn't not find the passphrase!\n");
	if (comment)	sfree(comment);
	if (encryption)	sfree(encryption);
	if (mac)	sfree(mac);
	if (public_blob)	sfree(public_blob);
	if (private_blob)	sfree(private_blob);
	if (private_blobXX) sfree(private_blobXX);

	return 0;
}
