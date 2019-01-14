#ifndef __HASHLIB_H
#define __HASHLIB_H   1

#include <fcntl.h>
#include <misclib.h> // custom lib
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

extern unsigned char *get_md5(char *, size_t) __nonnull ((1)) __wur;
extern unsigned char *get_md5_r(char *, size_t, unsigned char **) __nonnull ((1,3)) __wur;
extern unsigned char *get_md5_file(char *) __nonnull ((1)) __wur;
extern unsigned char *get_md5_file_r(char *, unsigned char **) __nonnull ((1,2)) __wur;

extern unsigned char *get_sha1(char *, size_t) __nonnull ((1)) __wur;
extern unsigned char *get_sha1_r(char *, size_t, unsigned char **) __nonnull ((1,3)) __wur;
extern unsigned char *get_sha1_file(char *) __nonnull ((1)) __wur;
extern unsigned char *get_sha1_file_r(char *, unsigned char **) __nonnull ((1,2)) __wur;

extern unsigned char *get_sha256(char *, size_t) __nonnull ((1)) __wur;
extern unsigned char *get_sha256_r(char *, size_t, unsigned char **) __nonnull ((1,3)) __wur;
extern unsigned char *get_sha256_file(char *) __nonnull ((1)) __wur;
extern unsigned char *get_sha256_file_r(char *, unsigned char **) __nonnull ((1,2)) __wur;

extern unsigned char *get_sha384(char *, size_t) __nonnull ((1)) __wur;
extern unsigned char *get_sha384_r(char *, size_t, unsigned char **) __nonnull ((1,3)) __wur;
extern unsigned char *get_sha384_file(char *) __nonnull ((1)) __wur;
extern unsigned char *get_sha384_file_r(char *, unsigned char **) __nonnull ((1,2)) __wur;

extern unsigned char *get_sha512(char *, size_t) __nonnull ((1)) __wur;
extern unsigned char *get_sha512_r(char *, size_t, unsigned char **) __nonnull ((1,3)) __wur;
extern unsigned char *get_sha512_file(char *) __nonnull ((1)) __wur;
extern unsigned char *get_sha512_file_r(char *, unsigned char **) __nonnull ((1,2)) __wur;

extern uint32_t *get_crc32(char *) __nonnull ((1)) __wur;
extern uint32_t *get_crc32_r(char *, uint32_t *) __nonnull ((1,2)) __wur;
extern uint32_t *get_crc32_file(char *) __nonnull ((1)) __wur;
extern uint32_t *get_crc32_file_r(char *, uint32_t *) __nonnull ((1,2)) __wur;

extern void destroy_digest(unsigned char **) __nonnull ((1));

#endif // __HASHLIB
