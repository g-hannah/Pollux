#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <hashlib.h>
#include <misclib.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <sys/ioctl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MAXLINE		1024
#define BLKSIZE		64
#define DUPCOL		"\e[38;5;124m"
#define HASHCOL		"\e[38;5;2m"
#define CUSHION		24

#define pe(str)											\
{												\
	fprintf(stderr, "%s: %s\n", (str), strerror(errno));					\
	exit(0xff);										\
}

#define pe_o(str)										\
{												\
	ERR_print_errors_fp(stderr);								\
	return(-1);										\
}

#define pe_r(str)										\
{												\
	fprintf(stderr, "%s: %s\n", (str), strerror(errno));					\
	return(-1);										\
}

#define log(str)										\
{												\
	printf("[FIND_DUPS]: %s\n", (str));							\
}

enum HASHTYPE
{
	__MD5,
#define __MD5 __MD5
	__SHA1,
#define __SHA1 __SHA1
	__SHA256,
#define __SHA256 __SHA256
	__SHA384,
#define __SHA384 __SHA384
	__SHA512
#define __SHA512 __SHA512
};

//static char		*start_dir = NULL;
static char		*path = NULL;
static unsigned char	*BLOCK = NULL;
//static struct winsize	WS;
static int		ofd, ndups, skipped_num;
static char		*tmp = NULL, *outfile = NULL;
static time_t		start, end;
static struct tm	TIME;
static char		time_str[50];

static char		**BLACKLIST = NULL;
static int		BLIST_SZ, NO_DELETE = 0, HASH_TYPE = __SHA256;
static int		QUIET = 0;

struct DIGEST
{
	char		*n;
	char		*d;
	struct DIGEST	*left;
	struct DIGEST	*right;
};

struct DIGEST		*root = NULL;

void init(void);
void clean_up(void);
void usage(void) __attribute__ ((__noreturn__));
int get_hash(char *) __THROW __nonnull ((1)) __wur;
int insert_hash(char *, char *, struct DIGEST *) __THROW __nonnull ((1,2,3)) __wur;
void free_binary_tree(struct DIGEST *) __THROW __nonnull ((1));
void print_binary_tree(struct DIGEST *) __THROW __nonnull ((1));
int find_files(char *) __THROW __nonnull ((1)) __wur;
int check_path(char *) __THROW __nonnull ((1)) __wur;
int get_options(int, char *[]) __THROW __nonnull ((2)) __wur;
char *get_hash_name(int) __wur;
char *get_time_str(void) __wur;

int
main(int argc, char *argv[])
{
	static char		c;
	static int		i;
	
	if (get_options(argc, argv) != 0)
		pe("main() > get_options()");

	if (QUIET)
	  {
		int		dfd;

		if ((dfd = open("/dev/null", O_RDWR)) < 0)
			pe("main() > open()");
		if (STDOUT_FILENO != dfd)
			dup2(dfd, STDOUT_FILENO);
		close(dfd);
	  }

	printf(
		"starting scan on %s in directory \"%s\"\n"
		"using hash \"%s\" to fingerprint files\n"
		"--nodelete flag is %s\n"
		"blacklisted keywords in search paths:\n",
		get_time_str(),
		path,
		get_hash_name(HASH_TYPE),
		(NO_DELETE?"on":"off"));
	for (i = 0; BLACKLIST[i] != NULL; ++i)
		printf("[%d] \"%s\"\n", (i+1), BLACKLIST[i]);
	init();
	find_files(path);
	time(&end);
	sprintf(tmp, "\nTIME ELAPSED: %ld seconds\n",
		((end - start)/1000000000UL));
	write_n(ofd, tmp, strlen(tmp));
	sprintf(tmp, "\n# DUPLICATE FILES: %d\n", ndups);
	write_n(ofd, tmp, strlen(tmp));
	sprintf(tmp, "\n# SKIPPED DIRECTORIES: %d\n", skipped_num);
	write_n(ofd, tmp, strlen(tmp));
	exit(0);
}

void
init(void)
{
	if (!(BLOCK = (unsigned char *)calloc(BLKSIZE, sizeof(unsigned char))))
		pe("init() > calloc(BLOCK)");
	atexit(clean_up);
	if (!(tmp = (char *)calloc(MAXLINE, sizeof(char))))
		pe("init() > calloc(tmp)");
	if (getcwd(tmp, MAXLINE) == NULL)
		pe("init() > getcwd()");
	if (path == NULL)
	  {
		if (!(path = (char *)calloc(MAXLINE, sizeof(char))))
			pe("init() > calloc(path)");
		memset(path, 0, MAXLINE);
		strncpy(path, tmp, strlen(tmp));
	  }
	if (!(root = (struct DIGEST *)malloc(sizeof(struct DIGEST))))
		pe("init() > malloc()");
	root->left = NULL;
	root->right = NULL;
	root->n = NULL;
	root->d = NULL;

	/*if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &WS) < 0)
		pe("init() > ioctl()");*/

	if (outfile == NULL)
	  {
		sprintf((tmp + strlen(tmp)),
			"/removed_dups_%ld.txt", time(NULL));
	  }
	else
	  {
		char		*home = NULL, *p = NULL;
		int		abs = 0;

		p = outfile;
		while (p < (outfile + strlen(outfile)))
		  {
			if (*p == 0x2f)
			  { abs = 1; break; }
			++p;
		  }
		if (!abs)
			sprintf((tmp + strlen(tmp)), "/%s", outfile);
		else
		  {
			memset(tmp, 0, MAXLINE);
			strncpy(tmp, outfile, MAXLINE);
		  }
	  }
	if ((ofd = open(tmp, O_RDWR|O_CREAT|O_TRUNC, S_IRWXU & ~S_IXUSR)) < 0)
		pe("init() > open(tmp)");

	if (QUIET)
	  {
		if (STDERR_FILENO != ofd)
			dup2(ofd, STDERR_FILENO);
	  }

	ndups &= ~ndups;
	skipped_num &= ~skipped_num;
	time(&start);
}

void
clean_up(void)
{
	static int		k;

	if (path != NULL) free(path);
	if (BLOCK != NULL) free(BLOCK);
	if (tmp != NULL) free(tmp);
	if (BLACKLIST != NULL)
	  {
		for (k = 0; BLACKLIST[k] != NULL; ++k)
		  {
			if (BLACKLIST[k] != NULL) { free(BLACKLIST[k]); BLACKLIST[k] = NULL; }
		  }
		free(BLACKLIST);
	  }
	close(ofd);
	free_binary_tree(root);
}

int
find_files(char *fpath)
{
	DIR		*dp = NULL;
	struct dirent	*dinf = NULL;
	size_t		n, n_sv;
	struct stat	statb;
	int		i, r;

	n = strlen(fpath);
	if (n != 0)
	  {
		if (fpath[(n-1)] != 0x2f)
	  	  {
			fpath[n++] = 0x2f;
			fpath[n] = 0;
	  	  }
	  }
	n_sv = n;

	memset(&statb, 0, sizeof(statb));
	if (!(dp = opendir(fpath)))
		return(-1);

	while ((dinf = readdir(dp)) != NULL)
	  {
		if ((strncmp(".", dinf->d_name, 1) == 0) ||
		    (strncmp("..", dinf->d_name, 2) == 0) ||
		    dinf->d_name[0] == 0x2e)
			continue;

		strncpy((fpath + n), dinf->d_name, strlen(dinf->d_name));
		*(fpath + n + strlen(dinf->d_name)) = 0;

		if (lstat(fpath, &statb) < 0)
		  { printf("lstat: %s: %s\n", fpath, strerror(errno)); return(-1); }
		

		r = check_path(fpath);
		if (r == -2)
			return(-1);
		else if (r == -1)
			continue;

		if (S_ISREG(statb.st_mode))
		  {
			if (get_hash(fpath) == -1)
				return(-1);
		  }
		else if (S_ISDIR(statb.st_mode))
		  {
			if (find_files(fpath) == -1)
				return(-1);
		  }
	  }
	*(fpath + n_sv) = 0;
	return(0);
}

int
get_hash(char *_FILE)
{
	static int		fd, _errno;
	static struct stat	statb;
	static unsigned char	*digest = NULL;
	static size_t		tr;
	static ssize_t		n;
	static char		*h = NULL;

	if (access(_FILE, R_OK) != 0)
	  {
		printf("Unable to access \"%s\": skipping\n", _FILE);
		return(0);
	  }
	memset(&statb, 0, sizeof(statb));
	if (lstat(_FILE, &statb) < 0)
		pe_r("get_hash() > lstat()");
	switch(HASH_TYPE)
	  {
		case(__MD5):
		if (get_md5_file_r(_FILE, &digest) == NULL)
			pe_r("get_hash() > get_md5_file_r()");
		h = hexlify(digest, EVP_MD_size(EVP_md5()));
		break;
		case(__SHA1):
		if (get_sha1_file_r(_FILE, &digest) == NULL)
			pe_r("get_hash() > get_sha1_file_r()");
		h = hexlify(digest, EVP_MD_size(EVP_sha1()));
		break;
		case(__SHA256):
		if (get_sha256_file_r(_FILE, &digest) == NULL)
			pe_r("get_hash() > get_sha256_file_r()");
		h = hexlify(digest, EVP_MD_size(EVP_sha256()));
		break;
		case(__SHA384):
		if (get_sha384_file_r(_FILE, &digest) == NULL)
			pe_r("get_hash() > get_sha384_file_r()");
		h = hexlify(digest, EVP_MD_size(EVP_sha384()));
		break;
		case(__SHA512):
		if (get_sha512_file_r(_FILE, &digest) == NULL)
			pe_r("get_hash() > get_sha512_file_r()");
		h = hexlify(digest, EVP_MD_size(EVP_sha512()));
		break;
		default:
		if (get_sha256_file_r(_FILE, &digest) == NULL)
			pe_r("get_hash() > get_sha256_file_r()");
		h = hexlify(digest, EVP_MD_size(EVP_sha256()));
	  }

	n = insert_hash(h, _FILE, root);
	if (n == -2) // error occurred
	  {
		printf("get_hash() > insert_hash(): %s\n", strerror(errno));
		goto __err;
	  }
	else if (n == -1) // duplicate file
	  {
		//remove(_FILE);
	  }

	close(fd);
	if (digest != NULL) { destroy_digest(&digest); digest = NULL; }
	return(0);

	__err:
	_errno = errno;
	close(fd);
	if (digest != NULL) { destroy_digest(&digest); digest = NULL; }
	errno = _errno;
	return(-1);
}

int
insert_hash(char *hash, char *fname, struct DIGEST *n)
{
	ssize_t		r;
	size_t		hsz;


	hsz = (EVP_MD_size(EVP_sha512()) * 2);

	if (n->d == NULL)
	  {
		if (!(n->d = (char *)calloc(hsz+1, sizeof(char))))
			return(-2);
		if (strncpy(n->d, hash, hsz) == NULL)
			return(-2);
		n->d[hsz] = 0;
		if (!(n->n = (char *)calloc((strlen(fname)+1), sizeof(char))))
			return(-2);
		if (strncpy(n->n, fname, strlen(fname)) == NULL)
			return(-2);
		n->n[(strlen(fname))] = 0;
		return(0);
	  }

	if (strncmp(hash, n->d, hsz) < 0)
	  {
		if (n->left == NULL)
		  {
			if (!(n->left = (struct DIGEST *)malloc(sizeof(struct DIGEST))))
				return(-2);
			n->left->left = NULL;
			n->left->right = NULL;
			if (!(n->left->d = (char *)calloc(hsz+1, sizeof(char))))
				return(-2);
			if (strncpy(n->left->d, hash, hsz) == NULL)
				return(-2);
			n->left->d[hsz] = 0;
			if (!(n->left->n = (char *)calloc((strlen(fname)+1), sizeof(char))))
				return(-2);
			if (strncpy(n->left->n, fname, strlen(fname)) == NULL)
				return(-2);
			n->left->n[(strlen(fname))] = 0;
			return(0);
		  }
		else
		  {
			r = insert_hash(hash, fname, n->left);
			return(r);
		  }
	  }
	else if (strncmp(hash, n->d, hsz) > 0) // recur right
	  {
		if (n->right == NULL) // put it here
		  {
			if (!(n->right = (struct DIGEST *)malloc(sizeof(struct DIGEST))))
				return(-2);
			n->right->left = NULL;
			n->right->right = NULL;
			if (!(n->right->d = (char *)calloc(hsz+1, sizeof(char))))
				return(-2);
			if (strncpy(n->right->d, hash, hsz) == NULL)
				return(-2);
			n->right->d[hsz] = 0;
			if (!(n->right->n = (char *)calloc((strlen(fname)+1), sizeof(char))))
				return(-2);
			if (strncpy(n->right->n, fname, strlen(fname)) == NULL)
				return(-2);
			n->right->n[(strlen(fname))] = 0;
			return(0);
		  }
		else
		  {
			r = insert_hash(hash, fname, n->right);
			return(r);
		  }
	  }
	else if (strncmp(hash, n->d, hsz) == 0) // duplicate
	  {
		++ndups;

		printf("%s and %s both have hash digest %s\n",
			fname, n->n, hash);
		/*printf(
			"%10s %s\"%.*s%s\"\e[m\n"
			"                and\n"
			"           %s\"%.*s%s\"\e[m\n"
			"%10s %s%s\e[m\n",
			"[DUP]", DUPCOL, (int)(WS.ws_col - CUSHION), fname,
			(strlen(fname)>(WS.ws_col-CUSHION)?"...":""),
			DUPCOL, (int)(WS.ws_col - CUSHION), n->n,
			(strlen(n->n)>(WS.ws_col-CUSHION)?"...":""),
			"[HASH]", HASHCOL, hash);*/

		sprintf(tmp,
			"%s and %s both have hash digest %s\n",
			fname, n->n, hash);
		/*sprintf(tmp,
			"%10s \"%s\"\n"
			"            and\n"
			"          \"%s\"\n"
			"%10s %s\n",
			"[DUP]", fname,
			n->n,
			"[HASH]", hash);*/
		write_n(ofd, tmp, strlen(tmp));

		if (!NO_DELETE)
		  {
			if (strlen(fname) > strlen(n->n))
		  	  {
				unlink(n->n);
				printf("removed %s\n", n->n);
				sprintf(tmp, "removed %s\n", n->n);
				/*printf("%10s %s\"%.*s%s\"\e[m\n\n",
					"[REMOVED]", DUPCOL, (int)(WS.ws_col - CUSHION), n->n,
					(strlen(n->n)>(WS.ws_col-CUSHION)?"...":""));
				sprintf(tmp,
					"%10s \"%s\"\n",
					"[REMOVED]", n->n);*/
				write_n(ofd, tmp, strlen(tmp));
				if ((n->n = realloc(n->n, strlen(fname)+1)) == NULL)
					return(-2);
				strncpy(n->n, fname, strlen(fname));
				*(n->n + strlen(fname)) = 0;
		  	  }
			else
		  	  {
				unlink(fname);
				printf("removed %s\n", fname);
				sprintf(tmp, "removed %s\n", fname);
				/*printf("%10s %s\"%.*s%s\"\e[m\n\n",
					"[REMOVED]", DUPCOL, (int)(WS.ws_col - CUSHION), fname,
					(strlen(fname)>(WS.ws_col-CUSHION)?"...":""));
				sprintf(tmp,
					"%10s \"%s\"\n",
					"[REMOVED]", fname);*/
				write_n(ofd, tmp, strlen(tmp));
		  	  }
		  }
		return(-1);
	  }
}

void
free_binary_tree(struct DIGEST *n)
{
	if (n->left != NULL)
		free_binary_tree(n->left);
	if (n->right != NULL)
		free_binary_tree(n->right);
	if (n->d != NULL) free(n->d);
	n->d = NULL;
	if (n->n != NULL) free(n->n);
	n->n = NULL;
	free(n);
	n = NULL;
	return;
}

void
print_binary_tree(struct DIGEST *n)
{
	if (n->left != NULL)
		print_binary_tree(n->left);
	if (n->right != NULL)
		print_binary_tree(n->right);
	printf("[%s][%s]\n", n->n, n->d);
	return;
}

int
check_path(char *path)
{
	static int		i;

	if (strstr(path, "./"))
	  { printf("\e[48;5;9m\e[38;5;0mAbsolute pathnames ONLY! (no \"./\" allowed)\e[m\n"); return(-2); }

	for (i = 0; BLACKLIST[i] != NULL; ++i)
	  {
		if (strstr(path, BLACKLIST[i]))
		  {
			fprintf(stderr, "\e[48;5;9m\e[38;5;0mBLACKLISTED!\e[m \"%s\"\n", path);
			return(-1);
		  }
	  }
	return(0);
}

int
get_options(int _argc, char *_argv[])
{
	static char		*p = NULL, *q = NULL;
	static int		i, j, blist_on, bidx;

	blist_on = 0;
	BLIST_SZ = 16;
	if (!(BLACKLIST = (char **)calloc(BLIST_SZ, sizeof(char *))))
		return(-1);
	for (i = 0; i < BLIST_SZ; ++i)
		BLACKLIST[i] = NULL;

	for (i = 0; i < _argc; ++i)
	  {
		if ((strncmp("--blacklist", _argv[i], 11) == 0) ||
		     (strncmp("-B", _argv[i], 2) == 0))
		  {
			blist_on = 1;
			bidx &= ~bidx;
			j = (i+1);
			while (j < _argc &&
				(strncmp("--", _argv[j], 2) != 0) &&
				(strncmp("-", _argv[j], 1) != 0))
			  {
				if (!(BLACKLIST[bidx] = (char *)calloc(strlen(_argv[j])+1, sizeof(char))))
					return(-1);
				strncpy(BLACKLIST[bidx], _argv[j], strlen(_argv[j]));
				BLACKLIST[bidx][strlen(_argv[j])] = 0;
				++bidx; ++j;
				if (bidx >= BLIST_SZ)
				  {
					if (!(BLACKLIST = (char **)realloc(BLACKLIST, (BLIST_SZ*2))))
						return(-1);
					BLIST_SZ *= 2;
				  }
			  }
			BLACKLIST[bidx] = NULL;
			i = (j-1);
		  }
		else if ((strncmp("--start", _argv[i], 7) == 0) ||
		     (strncmp("-s", _argv[i], 2) == 0))
		  {
			if (path == NULL)
				if (!(path = (char *)calloc(1024, sizeof(char))))
					return(-1);
			++i;
			strncpy(path, _argv[i], strlen(_argv[i]));
			path[strlen(_argv[i])] = 0;
		  }
		else if ((strncmp("--nodelete", _argv[i], 10) == 0) ||
		     (strncmp("-N", _argv[i], 2) == 0))
		  {
			NO_DELETE = 1;
		  }
		else if ((strncmp("--out", _argv[i], 5) == 0) ||
		     (strncmp("-o", _argv[i], 2) == 0))
		  {
			++i;
			outfile = _argv[i];
		  }
		else if ((strncmp("--hash", _argv[i], 6) == 0) ||
		     (strncmp("-H", _argv[i], 2) == 0))
		  {
			++i;
			if (strncmp("md5", _argv[i], 3) == 0)
				HASH_TYPE = __MD5;
			else if (strncmp("sha1", _argv[i], 4) == 0)
				HASH_TYPE = __SHA1;
			else if (strncmp("sha256", _argv[i], 6) == 0)
				HASH_TYPE = __SHA256;
			else if (strncmp("sha384", _argv[i], 6) == 0)
				HASH_TYPE = __SHA384;
			else if (strncmp("sha512", _argv[i], 6) == 0)
				HASH_TYPE = __SHA512;
			else
				HASH_TYPE = __SHA256;
		  }
		else if ((strncmp("--help", _argv[i], 6) == 0) ||
		     (strncmp("-h", _argv[i], 2) == 0))
		  {
			usage();
		  }
		else if ((strncmp("--quiet", _argv[i], 7) == 0) ||
		     (strncmp("-q", _argv[i], 2) == 0))
		  {
			QUIET = 1;
		  }
	  }

	// NEED TO BLACKLIST SOME DIRECTORIES BY DEFAULT (FOR ME PERSONALLY)
	if (!blist_on)
	  {
		if (!(BLACKLIST = (char **)calloc(6, sizeof(char *))))
			return(-1);
		for (i = 0; i < 6; ++i)
			if (!(BLACKLIST[i] = (char *)calloc(64, sizeof(char))))
				return(-1);
		BLACKLIST[5] = NULL;
		strncpy(BLACKLIST[0], "bin/", 4);
		strncpy(BLACKLIST[1], "Projects/", 9);
		strncpy(BLACKLIST[2], "sensible/", 9);
		strncpy(BLACKLIST[3], "usr/", 4);
		strncpy(BLACKLIST[4], "etc/", 4);
	  }

	return(0);
}

char *
get_hash_name(int hashtype)
{
	switch(hashtype)
	  {
		case(__MD5):
		return("md5");
		break;
		case(__SHA1):
		return("sha1");
		break;
		case(__SHA256):
		return("sha256");
		break;
		case(__SHA384):
		return("sha384");
		break;
		case(__SHA512):
		return("sha512");
		break;
		default:
		return("sha256");
	  }
}

size_t
get_hash_size(int hashtype)
{
	switch(hashtype)
	  {
		case(__MD5):
		return((size_t)(EVP_MD_size(EVP_md5()) * 2));
		break;
		case(__SHA1):
		return((size_t)(EVP_MD_size(EVP_sha1()) * 2));
		break;
		case(__SHA256):
		return((size_t)(EVP_MD_size(EVP_sha256()) * 2));
		break;
		case(__SHA384):
		return((size_t)(EVP_MD_size(EVP_sha384()) * 2));
		break;
		case(__SHA512):
		return((size_t)(EVP_MD_size(EVP_sha512()) * 2));
		break;
		default:
		return((size_t)(EVP_MD_size(EVP_sha256()) * 2));
	  }
}

char *
get_time_str(void)
{
	static time_t		seed;

	memset(&TIME, 0, sizeof(TIME));
	time(&seed);
	if ((localtime_r(&seed, &TIME)) == NULL)
		return(NULL);
	if (strftime(time_str, 50, "%a, %d %b %Y %H:%M:%S %z %Z", &TIME) < 0)
		return(NULL);
	return(time_str);
}

void
usage(void)
{
	fprintf(stdout,
		"pollux [OPTIONS]\n\n"
		"  -s, --start		Specify the starting directory\n"
		"			 + only absolute paths are permitted because Pollux needs to check the\n"
		"			 + entire directory path for keywords in order to avoid traversing\n"
		"			 + into blacklisted directories\n"
		"  -B, --blacklist	Specify keywords to blacklist; will not descend into any directories\n"
		"			 + containing these keywords (e.g., \"bin\", \"lib\", \"usr\").\n"
		"  -H, --hash		Specify the hash digest to use\n"
		"			 + Choices are \"md5\", \"sha1\", \"sha256\", \"sha384\", \"sha512\"\n"
		"			 + (Default is sha256)\n"
		"  -N, --nodelete	Do not delete any of the duplicates found, simply list them\n"
		"  -o, --out		 + Specify output file to print the results to (the default outfile is\n"
		"			 + called \"removed_duplicates_\'TIMESTAMP\'.txt\").\n"
		"  -q, --quiet		Do not print anything to stdout\n"
		"  -h, --help		Print this information menu\n");
	exit(0);
}
