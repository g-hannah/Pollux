#include <fcntl.h>
#include <hashlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <unistd.h>

unsigned char			*d = NULL;
uint32_t			*CRC = NULL;
static unsigned int		dlen;
static EVP_MD_CTX		*ctx = NULL;
static uint32_t			crc_table[256];

static void __hashlib_clean(void);
static void __gen_crc32_table(void);

static void
__attribute__ ((constructor)) __hashlib_init(void)
{
	atexit(__hashlib_clean);
	if (!(d = (unsigned char *)calloc(256, sizeof(unsigned char))))
	  { fprintf(stderr, "[libhashlib.so]: __hashlib_init() > calloc()\n"); exit(0xff); }
	if (!(CRC = (uint32_t *)malloc(sizeof(uint32_t)*1)))
	  { fprintf(stderr, "[libhashlib.so]: __hashlib_init() > malloc()\n"); exit(0xff); }
	__gen_crc32_table();
}

static void
__hashlib_clean(void)
{
	if (d != NULL) { free(d); d = NULL; }
	if (CRC != NULL) { free(CRC); CRC = NULL; }
	if (ctx != NULL) { EVP_MD_CTX_destroy(ctx); ctx = NULL; }
}

static void
__gen_crc32_table(void)
{
	static int		i, bit;
	static uint32_t		r, polynomial = 0xedb88320;

	for (i = 0; i < 256; ++i)
	  {
		r = i;
		for (bit = 0; bit < 8; ++bit)
		  {
			if (r & 1)
			  {
				r = ((r >> 1) ^ polynomial);
			  }
			else
			  {
				r = (r >> 1);
			  }
		  }
		crc_table[i] = r;
	  }
}

unsigned char *
get_md5(char *data, size_t len)
{
	static int		_errno;

	if ((ctx = EVP_MD_CTX_create()) == NULL)
		goto _err;
	if (1 != EVP_DigestInit_ex(ctx, EVP_md5(), NULL))
		goto _err;
	if (1 != EVP_DigestUpdate(ctx, (unsigned char *)data, len))
		goto _err;
	if (1 != EVP_DigestFinal_ex(ctx, d, &dlen))
		goto _err;
	EVP_MD_CTX_destroy(ctx);
	ctx = NULL;
	return(d);

	_err:
	_errno = errno;
	if (ctx != NULL) EVP_MD_CTX_destroy(ctx);
	ctx = NULL;
	errno = _errno;
	return(NULL);
}

unsigned char *
get_md5_r(char *data, size_t len, unsigned char **digest)
{
	static int			_errno;

	if ((ctx = EVP_MD_CTX_create()) == NULL)
		goto _err;
	if (1 != EVP_DigestInit_ex(ctx, EVP_md5(), NULL))
		goto _err;
	if ((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_md5()))) == NULL)
		goto _err;
	if (1 != EVP_DigestUpdate(ctx, (unsigned char *)data, len))
		goto _err;
	if (1 != EVP_DigestFinal_ex(ctx, *digest, &dlen))
		goto _err;

	EVP_MD_CTX_destroy(ctx);
	ctx = NULL;
	return(*digest);

	_err:
	_errno = errno;
	if (ctx != NULL) EVP_MD_CTX_destroy(ctx);
	ctx = NULL;
	if (*digest != NULL) OPENSSL_free(*digest);
	errno = _errno;
	return(NULL);
}
unsigned char *
get_md5_file(char *fname)
{
	static struct stat	statb;
	static unsigned char	*BLK = NULL;
	static size_t		toread;
	static ssize_t		n;
	static int		fd, _errno;
	
	memset(&statb, 0, sizeof(statb));
	if ((ctx = EVP_MD_CTX_create()) == NULL)
		goto _err;
	if (1 != EVP_DigestInit_ex(ctx, EVP_md5(), NULL))
		goto _err;
	if (lstat(fname, &statb) < 0)
		goto _err;
	if (!(BLK = (unsigned char *)calloc((EVP_MAX_MD_SIZE+1), sizeof(unsigned char))))
		goto _err;
	toread = statb.st_size;
	if ((fd = open(fname, O_RDONLY)) < 0)
		goto _err;
	while (toread > 0)
	  {
		if ((n = read_n(fd, (char *)BLK, EVP_MAX_MD_SIZE)) < 0)
			goto _err;
		BLK[n] = 0;
		if (1 != EVP_DigestUpdate(ctx, BLK, n))
			goto _err;
		toread -= n;
	  }

	if (1 != EVP_DigestFinal_ex(ctx, d, &dlen))
		goto _err;

	EVP_MD_CTX_destroy(ctx);
	ctx = NULL;
	if (BLK != NULL) { free(BLK); BLK = NULL; }
	close(fd);
	return(d);

	_err:
	_errno = errno;
	if (ctx != NULL) { EVP_MD_CTX_destroy(ctx); }
	if (BLK != NULL) { free(BLK); BLK = NULL; }
	close(fd);
	errno = _errno;
	return(NULL);
}

unsigned char *
get_md5_file_r(char *fname, unsigned char **digest)
{
	static struct stat	statb;
	static unsigned char	*BLK = NULL;
	static size_t		toread;
	static ssize_t		n;
	static int		fd, _errno;
	
	memset(&statb, 0, sizeof(statb));
	if ((ctx = EVP_MD_CTX_create()) == NULL)
		goto _err;
	if (1 != EVP_DigestInit_ex(ctx, EVP_md5(), NULL))
		goto _err;
	if ((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_md5()))) == NULL)
		goto _err;
	if (lstat(fname, &statb) < 0)
		goto _err;
	if (!(BLK = (unsigned char *)calloc((EVP_MAX_MD_SIZE+1), sizeof(unsigned char))))
		goto _err;
	toread = statb.st_size;
	if ((fd = open(fname, O_RDONLY)) < 0)
		goto _err;
	while (toread > 0)
	  {
		if ((n = read_n(fd, (char *)BLK, EVP_MAX_MD_SIZE)) < 0)
			goto _err;
		BLK[n] = 0;
		if (1 != EVP_DigestUpdate(ctx, BLK, n))
			goto _err;
		toread -= n;
	  }

	if (1 != EVP_DigestFinal_ex(ctx, *digest, &dlen))
		goto _err;

	EVP_MD_CTX_destroy(ctx);
	ctx = NULL;
	if (BLK != NULL) { free(BLK); BLK = NULL; }
	close(fd);
	return(*digest);

	_err:
	_errno = errno;
	if (ctx != NULL) { EVP_MD_CTX_destroy(ctx); ctx = NULL; }
	if (BLK != NULL) { free(BLK); BLK = NULL; }
	if (*digest != NULL) { OPENSSL_free(*digest); *digest = NULL; }
	close(fd);
	errno = _errno;
	return(NULL);
}


unsigned char *
get_sha1(char *data, size_t len)
{
	static int			_errno;

	if ((ctx = EVP_MD_CTX_create()) == NULL)
		goto _err;
	if (1 != EVP_DigestInit_ex(ctx, EVP_sha1(), NULL))
		goto _err;
	if (1 != EVP_DigestUpdate(ctx, (unsigned char *)data, len))
		goto _err;
	if (1 != EVP_DigestFinal_ex(ctx, d, &dlen))
		goto _err;
	EVP_MD_CTX_destroy(ctx);
	ctx = NULL;
	return(d);

	_err:
	_errno = errno;
	if (ctx != NULL)
		EVP_MD_CTX_destroy(ctx);
	errno = _errno;
	return(NULL);
}

unsigned char *
get_sha1_r(char *data, size_t len, unsigned char **digest)
{
	static int			_errno;

	if ((ctx = EVP_MD_CTX_create()) == NULL)
		goto _err;
	if (1 != EVP_DigestInit_ex(ctx, EVP_sha1(), NULL))
		goto _err;
	if ((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha1()))) == NULL)
		goto _err;
	if (1 != EVP_DigestUpdate(ctx, (unsigned char *)data, len))
		goto _err;
	if (1 != EVP_DigestFinal_ex(ctx, *digest, &dlen))
		goto _err;
	EVP_MD_CTX_destroy(ctx);
	ctx = NULL;
	return(*digest);

	_err:
	_errno = errno;
	if (*digest != NULL) OPENSSL_free(*digest);
	*digest = NULL;
	if (ctx != NULL) EVP_MD_CTX_destroy(ctx);
	ctx = NULL;
	errno = _errno;
	return(NULL);
}

unsigned char *
get_sha1_file(char *fname)
{
	static int		fd, _errno;
	static struct stat	statb;
	static unsigned char	*BLK = NULL;
	static size_t		toread;
	static ssize_t		n;

	memset(&statb, 0, sizeof(statb));
	if (lstat(fname, &statb) < 0)
		goto _err;
	if (!(BLK = (unsigned char *)calloc((EVP_MAX_MD_SIZE+1), sizeof(unsigned char))))
		goto _err;
	if ((fd = open(fname, O_RDONLY)) < 0)
		goto _err;
	toread = statb.st_size;
	if ((ctx = EVP_MD_CTX_create()) == NULL)
		goto _err;
	if (1 != EVP_DigestInit_ex(ctx, EVP_sha1(), NULL))
		goto _err;
	while (toread > 0)
	  {
		if ((n = read_n(fd, (char *)BLK, EVP_MAX_MD_SIZE)) < 0)
			goto _err;
		BLK[n] = 0;
		if (1 != EVP_DigestUpdate(ctx, BLK, n))
			goto _err;
		toread -= n;
	  }
	if (1 != EVP_DigestFinal_ex(ctx, d, &dlen))
		goto _err;
	if (BLK != NULL) { free(BLK); BLK = NULL; }
	EVP_MD_CTX_destroy(ctx);
	ctx = NULL;
	close(fd);
	return(d);

	_err:
	_errno = errno;
	if (BLK != NULL) { free(BLK); BLK = NULL; }
	if (ctx != NULL) { EVP_MD_CTX_destroy(ctx); ctx = NULL; }
	close(fd);
	errno = _errno;
	return(NULL);
}

unsigned char *
get_sha1_file_r(char *fname, unsigned char **digest)
{
	static int		fd, _errno;
	static struct stat	statb;
	static unsigned char	*BLK = NULL;
	static size_t		toread;
	static ssize_t		n;

	memset(&statb, 0, sizeof(statb));
	if (lstat(fname, &statb) < 0)
		goto _err;
	if (!(BLK = (unsigned char *)calloc((EVP_MAX_MD_SIZE+1), sizeof(unsigned char))))
		goto _err;
	toread = statb.st_size;
	if ((ctx = EVP_MD_CTX_create()) == NULL)
		goto _err;
	if (1 != EVP_DigestInit_ex(ctx, EVP_sha1(), NULL))
		goto _err;
	if ((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha1()))) == NULL)
		goto _err;
	if ((fd = open(fname, O_RDONLY)) < 0)
		goto _err;
	while (toread > 0)
	  {
		if ((n = read_n(fd, (char *)BLK, EVP_MAX_MD_SIZE)) < 0)
			goto _err;
		BLK[n] = 0;
		if (1 != EVP_DigestUpdate(ctx, BLK, n))
			goto _err;
		toread -= n;
	  }
	if (1 != EVP_DigestFinal_ex(ctx, *digest, &dlen))
		goto _err;
	if (BLK != NULL) { free(BLK); BLK = NULL; }
	EVP_MD_CTX_destroy(ctx);
	ctx = NULL;
	close(fd);
	return(*digest);

	_err:
	_errno = errno;
	if (BLK != NULL) { free(BLK); BLK = NULL; }
	if (ctx != NULL) { EVP_MD_CTX_destroy(ctx); ctx = NULL; }
	if (*digest != NULL) { OPENSSL_free(*digest); *digest = NULL; }
	close(fd);
	errno = _errno;
	return(NULL);
}

unsigned char *
get_sha256(char *data, size_t len)
{
	static int		_errno;

	if ((ctx = EVP_MD_CTX_create()) == NULL)
		goto _err;
	if (1 != EVP_DigestInit_ex(ctx, EVP_sha256(), NULL))
		goto _err;
	if (1 != EVP_DigestUpdate(ctx, (unsigned char *)data, len))
		goto _err;
	if (1 != EVP_DigestFinal_ex(ctx, d, &dlen))
		goto _err;

	EVP_MD_CTX_destroy(ctx);
	ctx = NULL;
	return(d);

	_err:
	_errno = errno;
	if (ctx != NULL) EVP_MD_CTX_destroy(ctx);
	ctx = NULL;
	errno = _errno;
	return(NULL);
}

unsigned char *
get_sha256_r(char *data, size_t len, unsigned char **digest)
{
	static int		_errno;

	if ((ctx = EVP_MD_CTX_create()) == NULL)
		goto _err;
	if (1 != EVP_DigestInit_ex(ctx, EVP_sha256(), NULL))
		goto _err;
	if ((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
		goto _err;
	if (1 != EVP_DigestUpdate(ctx, (unsigned char *)data, len))
		goto _err;
	if (1 != EVP_DigestFinal_ex(ctx, *digest, &dlen))
		goto _err;

	EVP_MD_CTX_destroy(ctx);
	ctx = NULL;
	return(*digest);

	_err:
	_errno = errno;
	if (*digest != NULL) { OPENSSL_free(*digest); *digest = NULL; }
	if (ctx != NULL) { EVP_MD_CTX_destroy(ctx); ctx = NULL; }
	errno = _errno;
	return(NULL);
}



unsigned char *
get_sha256_file(char *fname)
{
	static int		_errno, fd;
	static struct stat	statb;
	static unsigned char	*BLK = NULL;
	static size_t		toread;
	static ssize_t		n;

	memset(&statb, 0, sizeof(statb));
	if (lstat(fname, &statb) < 0)
		goto _err;
	toread = statb.st_size;
	if ((ctx = EVP_MD_CTX_create()) == NULL)
		goto _err;
	if (1 != EVP_DigestInit_ex(ctx, EVP_sha256(), NULL))
		goto _err;
	if (!(BLK = (unsigned char *)calloc((EVP_MAX_MD_SIZE+1), sizeof(unsigned char))))
		goto _err;
	if ((fd = open(fname, O_RDONLY)) < 0)
		goto _err;
	while (toread > 0)
	  {
		if ((n = read_n(fd, (char *)BLK, EVP_MAX_MD_SIZE)) < 0)
			goto _err;
		BLK[n] = 0;
		if (1 != EVP_DigestUpdate(ctx, (char *)BLK, n))
			goto _err;
		toread -= n;
	  }
	if (1 != EVP_DigestFinal_ex(ctx, d, &dlen))
		goto _err;

	if (BLK != NULL) { free(BLK); BLK = NULL; }
	EVP_MD_CTX_destroy(ctx);
	ctx = NULL;
	close(fd);
	return(d);

	_err:
	_errno = errno;
	if (ctx != NULL) { EVP_MD_CTX_destroy(ctx); ctx = NULL; }
	if (BLK != NULL) { free(BLK); BLK = NULL; }
	close(fd);
	errno = _errno;
	return(NULL);
}

unsigned char *
get_sha256_file_r(char *fname, unsigned char **digest)
{
	static int		fd, _errno;
	static struct stat	statb;
	static unsigned char	*BLK = NULL;
	static size_t		toread;
	static ssize_t		n;

	memset(&statb, 0, sizeof(statb));
	if (lstat(fname, &statb) < 0)
		goto _err;
	toread = statb.st_size;
	if ((ctx = EVP_MD_CTX_create()) == NULL)
		goto _err;
	if (1 != EVP_DigestInit_ex(ctx, EVP_sha256(), NULL))
		goto _err;
	if (!(BLK = (unsigned char *)calloc((EVP_MAX_MD_SIZE+1), sizeof(unsigned char))))
		goto _err;
	if ((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
		goto _err;
	if ((fd = open(fname, O_RDONLY)) < 0)
		goto _err;
	while (toread > 0)
	  {
		if ((n = read_n(fd, (char *)BLK, EVP_MAX_MD_SIZE)) < 0)
			goto _err;
		BLK[n] = 0;
		if (1 != EVP_DigestUpdate(ctx, BLK, n))
			goto _err;
		toread -= n;
	  }
	if (1 != EVP_DigestFinal_ex(ctx, *digest, &dlen))
		goto _err;

	EVP_MD_CTX_destroy(ctx);
	ctx = NULL;
	if (BLK != NULL) { free(BLK); BLK = NULL; }
	close(fd);
	return(*digest);

	_err:
	_errno = errno;
	if (*digest != NULL) { OPENSSL_free(*digest); *digest = NULL; }
	if (ctx != NULL) { EVP_MD_CTX_destroy(ctx); ctx = NULL; }
	if (BLK != NULL) { free(BLK); BLK = NULL; }
	close(fd);
	errno = _errno;
	return(NULL);
}


unsigned char *
get_sha384(char *data, size_t len)
{
	static int		_errno;

	if ((ctx = EVP_MD_CTX_create()) == NULL)
		goto _err;
	if (1 != EVP_DigestInit_ex(ctx, EVP_sha384(), NULL))
		goto _err;
	if (1 != EVP_DigestUpdate(ctx, (unsigned char *)data, len))
		goto _err;
	if (1 != EVP_DigestFinal_ex(ctx, d, &dlen))
		goto _err;

	EVP_MD_CTX_destroy(ctx);
	ctx = NULL;
	return(d);

	_err:
	_errno = errno;
	if (ctx != NULL) { EVP_MD_CTX_destroy(ctx); ctx = NULL; }
	errno = _errno;
	return(NULL);
}

unsigned char *
get_sha384_r(char *data, size_t len, unsigned char **digest)
{
	static int		_errno;

	if ((ctx = EVP_MD_CTX_create()) == NULL)
		goto _err;
	if (1 != EVP_DigestInit_ex(ctx, EVP_sha384(), NULL))
		goto _err;
	if ((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha384()))) == NULL)
		goto _err;
	if (1 != EVP_DigestUpdate(ctx, (unsigned char *)data, len))
		goto _err;
	if (1 != EVP_DigestFinal_ex(ctx, *digest, &dlen))
		goto _err;

	EVP_MD_CTX_destroy(ctx);
	ctx = NULL;
	return(*digest);

	_err:
	_errno = errno;
	if (*digest != NULL) { OPENSSL_free(*digest); *digest = NULL; }
	if (ctx != NULL) { EVP_MD_CTX_destroy(ctx); ctx = NULL; }
	errno = _errno;
	return(NULL);
}

unsigned char *
get_sha384_file(char *fname)
{
	static int		_errno, fd;
	static struct stat	statb;
	static unsigned char	*BLK = NULL;
	static size_t		toread;
	static ssize_t		n;

	memset(&statb, 0, sizeof(statb));
	if (lstat(fname, &statb) < 0)
		goto _err;
	toread = statb.st_size;
	if ((ctx = EVP_MD_CTX_create()) == NULL)
		goto _err;
	if (1 != EVP_DigestInit_ex(ctx, EVP_sha384(), NULL))
		goto _err;
	if (!(BLK = (unsigned char *)calloc((EVP_MAX_MD_SIZE+1), sizeof(unsigned char))))
		goto _err;
	if ((fd = open(fname, O_RDONLY)) < 0)
		goto _err;
	while (toread > 0)
	  {
		if ((n = read_n(fd, (char *)BLK, EVP_MAX_MD_SIZE)) < 0)
			goto _err;
		BLK[n] = 0;
		if (1 != EVP_DigestUpdate(ctx, (char *)BLK, n))
			goto _err;
		toread -= n;
	  }
	if (1 != EVP_DigestFinal_ex(ctx, d, &dlen))
		goto _err;
	EVP_MD_CTX_destroy(ctx);
	ctx = NULL;
	if (BLK != NULL) { free(BLK); BLK = NULL; }
	close(fd);
	return(d);

	_err:
	_errno = errno;
	if (ctx != NULL) { EVP_MD_CTX_destroy(ctx); ctx = NULL; }
	if (BLK != NULL) { free(BLK); BLK = NULL; }
	close(fd);
	errno = _errno;
	return(NULL);
}

unsigned char *
get_sha384_file_r(char *fname, unsigned char **digest)
{
	static int		_errno, fd;
	static struct stat	statb;
	static unsigned char	*BLK = NULL;
	static size_t		toread;
	static ssize_t		n;

	memset(&statb, 0, sizeof(statb));
	if (lstat(fname, &statb) < 0)
		goto _err;
	toread = statb.st_size;
	if ((ctx = EVP_MD_CTX_create()) == NULL)
		goto _err;
	if (1 != EVP_DigestInit_ex(ctx, EVP_sha384(), NULL))
		goto _err;
	if (!(BLK = (unsigned char *)calloc((EVP_MAX_MD_SIZE+1), sizeof(unsigned char))))
		goto _err;
	if ((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha384()))) == NULL)
		goto _err;
	if ((fd = open(fname, O_RDONLY)) < 0)
		goto _err;
	while (toread > 0)
	  {
		if ((n = read_n(fd, (char *)BLK, EVP_MAX_MD_SIZE)) < 0)
			goto _err;
		BLK[n] = 0;
		if (1 != EVP_DigestUpdate(ctx, BLK, n))
			goto _err;
		toread -= n;
	  }
	if (1 != EVP_DigestFinal_ex(ctx, *digest, &dlen))
		goto _err;
	EVP_MD_CTX_destroy(ctx);
	ctx = NULL;
	if (BLK != NULL) { free(BLK); BLK = NULL; }
	close(fd);
	return(*digest);

	_err:
	_errno = errno;
	if (ctx != NULL) { EVP_MD_CTX_destroy(ctx); ctx = NULL; }
	if (BLK != NULL) { free(BLK); BLK = NULL; }
	if (*digest != NULL) { OPENSSL_free(*digest); *digest = NULL; }
	close(fd);
	errno = _errno;
	return(NULL);
}

unsigned char *
get_sha512(char *data, size_t len)
{
	static int			_errno;

	if ((ctx = EVP_MD_CTX_create()) == NULL)
		goto _err;
	if (1 != EVP_DigestInit_ex(ctx, EVP_sha512(), NULL))
		goto _err;
	if (1 != EVP_DigestUpdate(ctx, (unsigned char *)data, len))
		goto _err;
	if (1 != EVP_DigestFinal_ex(ctx, d, &dlen))
		goto _err;

	EVP_MD_CTX_destroy(ctx);
	ctx = NULL;
	return(d);

	_err:
	_errno = errno;
	if (ctx != NULL) { EVP_MD_CTX_destroy(ctx); ctx = NULL; }
	errno = _errno;
	return(NULL);
}

unsigned char *
get_sha512_r(char *data, size_t len, unsigned char **digest)
{
	static int		_errno;

	if ((ctx = EVP_MD_CTX_create()) == NULL)
		goto _err;
	if (1 != EVP_DigestInit_ex(ctx, EVP_sha512(), NULL))
		goto _err;
	if ((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha512()))) == NULL)
		goto _err;
	if (1 != EVP_DigestUpdate(ctx, (unsigned char *)data, len))
		goto _err;
	if (1 != EVP_DigestFinal_ex(ctx, *digest, &dlen))
		goto _err;

	EVP_MD_CTX_destroy(ctx);
	ctx = NULL;
	return(*digest);

	_err:
	_errno = errno;
	if (*digest != NULL) { OPENSSL_free(*digest); *digest = NULL; }
	if (ctx != NULL) { EVP_MD_CTX_destroy(ctx); ctx = NULL; }
	errno = _errno;
	return(NULL);
}

unsigned char *
get_sha512_file(char *fname)
{
	static int		_errno, fd;
	static struct stat	statb;
	static unsigned char	*BLK = NULL;
	static size_t		toread;
	static ssize_t		n;

	memset(&statb, 0, sizeof(statb));
	if (lstat(fname, &statb) < 0)
		goto _err;
	toread = statb.st_size;
	if ((ctx = EVP_MD_CTX_create()) == NULL)
		goto _err;
	if (1 != EVP_DigestInit_ex(ctx, EVP_sha512(), NULL))
		goto _err;
	if (!(BLK = (unsigned char *)calloc((EVP_MAX_MD_SIZE+1), sizeof(unsigned char))))
		goto _err;
	if ((fd = open(fname, O_RDONLY)) < 0)
		goto _err;
	while (toread > 0)
	  {
		if ((n = read_n(fd, (char *)BLK, EVP_MAX_MD_SIZE)) < 0)
			goto _err;
		BLK[n] = 0;
		if (1 != EVP_DigestUpdate(ctx, BLK, n))
			goto _err;
		toread -= n;
	  }
	if (1 != EVP_DigestFinal_ex(ctx, d, &dlen))
		goto _err;
	EVP_MD_CTX_destroy(ctx);
	ctx = NULL;
	if (BLK != NULL) { free(BLK); BLK = NULL; }
	close(fd);
	return(d);

	_err:
	_errno = errno;
	if (ctx != NULL) { EVP_MD_CTX_destroy(ctx); ctx = NULL; }
	if (BLK != NULL) { free(BLK); BLK = NULL; }
	close(fd);
	errno = _errno;
	return(NULL);
}

unsigned char *
get_sha512_file_r(char *fname, unsigned char **digest)
{
	static int		_errno, fd;
	static struct stat	statb;
	static unsigned char	*BLK = NULL;
	static size_t		toread;
	static ssize_t		n;

	memset(&statb, 0, sizeof(statb));
	if (lstat(fname, &statb) < 0)
		goto _err;
	toread = statb.st_size;
	if ((ctx = EVP_MD_CTX_create()) == NULL)
		goto _err;
	if (1 != EVP_DigestInit_ex(ctx, EVP_sha512(), NULL))
		goto _err;
	if (!(BLK = (unsigned char *)calloc((EVP_MAX_MD_SIZE+1), sizeof(unsigned char))))
		goto _err;
	if ((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha512()))) == NULL)
		goto _err;
	if ((fd = open(fname, O_RDONLY)) < 0)
		goto _err;
	while (toread > 0)
	  {
		if ((n = read_n(fd, (char *)BLK, EVP_MAX_MD_SIZE)) < 0)
			goto _err;
		BLK[n] = 0;
		if (1 != EVP_DigestUpdate(ctx, BLK, n))
			goto _err;
		toread -= n;
	  }
	if (1 != EVP_DigestFinal_ex(ctx, *digest, &dlen))
		goto _err;
	EVP_MD_CTX_destroy(ctx);
	ctx = NULL;
	if (BLK != NULL) { free(BLK); BLK = NULL; }
	close(fd);
	return(*digest);

	_err:
	_errno = errno;
	if (ctx != NULL) { EVP_MD_CTX_destroy(ctx); ctx = NULL; }
	if (BLK != NULL) { free(BLK); BLK = NULL; }
	if (*digest != NULL) { OPENSSL_free(*digest); *digest = NULL; }
	close(fd);
	errno = _errno;
	return(NULL);
}

	// for the reentrant get_XXX functions
void
destroy_digest(unsigned char **digest)
{
	if (*digest == NULL)
		return;
	OPENSSL_free(*digest);
	*digest = NULL;
	return;
}

/*uint32_t
reflect(uint32_t x)
{
	uint32_t		t;
	static uint32_t		top;
	static int		i;

	t &= ~t; top = (1 << 31);
	for (i = 0; i < 32; ++i)
	  {
		if ((x & (1 << i)) != 0)
			t |= (top >> i);
	  }
	return(t);
}*/

uint32_t *
get_crc32(char *data)
{
	static uint32_t		crc;
	static unsigned char	*p = NULL;
	static size_t		l;

	l = strlen(data);
	p = (unsigned char *)data;

	crc = 0xffffffff;
	for( ; l > 0; --l)
	  {
		crc = (crc_table[(crc & 0xff) ^ *p++] ^ (crc >> 8));
	  }

	*CRC = ~crc;
	return(CRC);
}

uint32_t *
get_crc32_r(char *data, uint32_t *crc)
{
	static unsigned char	*p = NULL;
	static size_t		l;

	l = strlen(data);
	p = (unsigned char *)data;
	*crc = 0xffffffff;

	for ( ; l > 0; --l)
	  {
		*crc = (crc_table[(*crc & 0xff) ^ *p++] ^ (*crc >> 8));
	  }

	*crc = ~(*crc);
	return(crc);
}

uint32_t *
get_crc32_file(char *fname)
{
	static int		_errno, fd;
	static void		*start = NULL;
	static unsigned char	*p = NULL;
	static size_t		l;
	static uint32_t		crc;
	static struct stat	statb;

	memset(&statb, 0, sizeof(statb));
	if (lstat(fname, &statb) < 0)
		goto _err;

	crc = 0xffffffff;
	l = statb.st_size;

	if ((fd = open(fname, O_RDONLY)) < 0)
		goto _err;
	if ((start = mmap(NULL, statb.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
		goto _err;
	close(fd);

	p = (unsigned char *)start;
	for ( ; l > 0; --l)
	  {
		crc = (crc_table[(crc & 0xff) ^ *p++] ^ (crc >> 8));
	  }
	if (start != NULL) munmap(start, statb.st_size);

	*CRC = ~crc;
	return(CRC);

	_err:
	_errno = errno;
	if (start != NULL) munmap(start, statb.st_size);
	errno = _errno;
	return(NULL);
}

uint32_t *
get_crc32_file_r(char *fname, uint32_t *crc)
{
	static int		_errno, fd;
	static void		*start = NULL;
	static unsigned char	*p = NULL;
	static size_t		l;
	static struct stat	statb;

	// créer le tableau des restes
	memset(&statb, 0, sizeof(statb));
	if (lstat(fname, &statb) < 0)
		goto _err;

	*crc = 0xffffffff;
	l = statb.st_size;

	if ((fd = open(fname, O_RDONLY)) < 0)
		goto _err;
	if ((start = mmap(NULL, statb.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
		goto _err;
	close(fd);

	p = (unsigned char *)start;
	for ( ; l > 0; --l)
	  {
		*crc = (crc_table[(*crc & 0xff) ^ *p++] ^ (*crc >> 8));
	  }
	if (start != NULL) munmap(start, statb.st_size);

	*crc = ~(*crc);
	return(crc);

	_err:
	_errno = errno;
	if (start != NULL) munmap(start, statb.st_size);
	errno = _errno;
	return(NULL);
}
