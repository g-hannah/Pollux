#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#define MAXLINE		1024
#define BLK_SIZE	8192
#define TMP_FILE	"/tmp/.dup_files.txt"
#define HASH_SIZE	64 // sha256 in string format
#define ARROW_COL	"\e[38;5;13m"
#define BANNER_COL	"\e[38;5;202m"
#define HIGHLIGHT_COL	"\e[38;5;246m"
#define BUILD			"2.0.2"

struct Node
{
	int		array;
	char		*name;
	size_t		size;
	struct Node	*l;
	struct Node	*r;
	struct Node	*s;
	char		hash[HASH_SIZE];
};

typedef struct Node Node;

/* option flags */
int		IGNORE_HIDDEN = 0;
int		NO_DELETE = 0;
int		QUIET = 0;
int		DEBUG = 0;

struct stat	cur_file_stats;
Node		*root = NULL;
int		files_scanned = 0;
int		dup_files = 0;
int		tmp_fd = -1;
FILE		*tmp_fp = NULL;
uint64_t	used_bytes = 0;
uint64_t	wasted_bytes = 0;
time_t		start = 0, end = 0;
char		*path = NULL;
static char program_name[64];
struct rlimit	rlims;
char		**user_blacklist = NULL;
char *illegal_terms[] = 
  {
	"/sys",
	"/usr",
	"/bin",
	"/sbin",
	"/kernel",
	"/proc",
	"/dev",
	"/etc/",
	"/lib",
	"/run",
	"/tmp",
	"/boot",
	"/var",
	"/opt",
	"/firmware",
	"/Program Files/",
	"/ProgramData/",
	".dll",
	".so",
	".bin",
	(char *)NULL
  };

char		*line_buf = NULL;
unsigned char	*hash_buf = NULL;
char		*hash_hex = NULL;
char		*block = NULL;

struct winsize	winsz;
int		max_col = 0;

static int insert_file(Node **, char *, size_t, FILE *) __nonnull ((1,2,4)) __wur;
static void free_tree(Node **) __nonnull ((1));
static int scan_dirs(char *) __nonnull ((1)) __wur;
static int print_and_decide(char *, char *, char *, FILE *) __nonnull ((1,2,3,4)) __wur;
static int remove_which(char *, char *) __nonnull ((1,2)) __wur;
static unsigned char *get_sha256_file(char *) __nonnull ((1)) __wur;
static void close_excess_fds(int, int);
static void strip_crnl(char *) __nonnull ((1));
static inline char *hexlify(unsigned char *, size_t) __nonnull ((1)) __wur;
static void display_usage(const int) __attribute__ ((__noreturn__));
static int check_file(const char *) __nonnull ((1)) __wur;

static void log_err(char *, ...) __nonnull ((1));
static void debug(char *, ...) __nonnull ((1));
static void signal_handler(int) __attribute__ ((__noreturn__));
static void pollux_init(void) __attribute__ ((constructor));
static void pollux_fini(void) __attribute__ ((destructor));
static int get_options(int, char *[]) __nonnull ((2)) __wur;
static void print_stats(void);

int
main(int argc, char *argv[])
{
	int 	r = 0;

	IGNORE_HIDDEN = NO_DELETE = QUIET = DEBUG = 0;

	strncpy(program_name, argv[0], strlen(argv[0]));
	program_name[strlen(argv[0])] = 0;

	if (argc < 2)
			display_usage(EXIT_FAILURE);
	else
	if (get_options(argc, argv) < 0)
		goto fail;

	if (check_file(argv[1]))
		goto fail;

	/*
	 * Might be using Cron to run us, so test first before doing ioctl() for
	 * TIOCGWINSZ, otherwise it will fail. Getting terminal dimensions needs
	 * to be done here and not in the constructor function, because they
	 * are not known before main()
	 */

	if (isatty(STDOUT_FILENO))
	  {
			if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsz) < 0)
		  	{ log_err("main: ioctl TIOCGWINSZ error"); goto fail; }

			max_col = winsz.ws_col - 6;
	  }
	 

	if (!NO_DELETE)
	  {
		if ((tmp_fd = open(TMP_FILE, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR)) < 0)
		  { log_err("main: open error"); goto fail; }
		if (!(tmp_fp = fdopen(tmp_fd, "r+")))
		  { log_err("main: fdopen error"); goto fail; }
		if (setvbuf(tmp_fp, NULL, _IONBF, 0) < 0)
		  { log_err("main: setvbuf error"); goto fail; }
	  }

	if (QUIET)
	  {
		int		fd = -1;

		if ((fd = open("/dev/null", O_RDWR)) < 0)
		  { log_err("main: open error"); goto fail; }

		if (fd != STDOUT_FILENO)
			dup2(fd, STDOUT_FILENO);
		if (fd != STDERR_FILENO)
			dup2(fd, STDERR_FILENO);

		close(fd);
		fd = -1;
	  }

	strncpy(path, argv[1], strlen(argv[1]));
	path[strlen(argv[1])] = 0;

	fprintf(stdout,
			"\n%s"
			"   OOOOOOOOO    OOOOOOOOO    OOOO        OOOO        OOOO     OOOO  OOOOOO     OOOOOO\n"
			"  OOOOOOOOOOO  OOOOOOOOOOO  OOOOOO      OOOOOO      OOOOOO   OOOOOO  OOOOOO   OOOOOO \n"
			" OOOOO  OOOOO OOOOOOOOOOOOO OOOOOO      OOOOOO      OOOOOO   OOOOOO   OOOOOO OOOOOO  \n"
			" OOOOO  OOOOO OOOOO   OOOOO OOOOOO      OOOOOO      OOOOOO   OOOOOO    OOOOOOOOOOO   \n"
			" OOOOOOOOOOOO OOOOO   OOOOO OOOOOO      OOOOOO      OOOOOO   OOOOOO     OOOOOOOOO    \n"
			" OOOOOOOOOOO  OOOOO   OOOOO OOOOOO      OOOOOO      OOOOOO   OOOOOO    OOOOOOOOOOO   \n"
			" OOOOO        OOOOOOOOOOOOO OOOOOOOOOO  OOOOOOOOOO  OOOOOOOOOOOOOOO   OOOOOO OOOOOO  \n"
			" OOOOO         OOOOOOOOOOO  OOOOOOOOOOO OOOOOOOOOOO  OOOOOOOOOOOOO   OOOOOO   OOOOOO \n"
			" OOOOO          OOOOOOOOO    OOOOOOOOO   OOOOOOOOO    OOOOOOOOOOO   OOOOOO     OOOOOO\e[m\n"
			"\n"
			" v%s\n\n",
			BANNER_COL,
			BUILD);

	printf("Starting scan in %s%s\e[m\n\n", HIGHLIGHT_COL, argv[1]);

	time(&start);
	r = scan_dirs(path);
	time(&end);

	debug("Scan ended with ret %d\n", r);

	//sync();

	if (!NO_DELETE)
	{
		lseek(tmp_fd, 0, SEEK_SET);
		while (fgets(line_buf, MAXLINE, tmp_fp) != NULL)
	  {
			strip_crnl(line_buf);
			unlink(line_buf);
		}
		unlink(TMP_FILE);
	}

	debug("printing stats");
	print_stats();

	if (r < 0) exit(EXIT_FAILURE);
	else exit(EXIT_SUCCESS);

	fail:
	exit(EXIT_FAILURE);
}

int
scan_dirs(char *path)
{
	size_t		n = 0, n_sv = 0;
	DIR		*dp = NULL;
	struct dirent	*dinf = NULL;
#ifndef __APPLE__
	long		dir_position = 0;
#endif
	int		i = 0;
	int		dfd = -1;
	int		illegal = 0;
	register int	loop_cnt = 0;

	n = strlen(path);

	if (n != 0)
	  {
		if (path[(n-1)] != 0x2f)
	  	  {
			path[n++] = 0x2f;
			path[n] = 0;
	  	  }
	  }

	n_sv = n;

	debug("scanning %s", path);

	if ((dfd = open(path, O_RDONLY)) < 0)
	  {
		if (errno == EACCES) return(0);

		log_err("scan_dirs: failed to open %s (line %d)", path, __LINE__);
		goto fail;
	  }

	if (!(dp = fdopendir(dfd)))
	  {
		log_err("scan_dirs: failed open %s from fd (line %d)", path, __LINE__);
		goto fail;
	  }

	debug("opened %s", path);

	illegal = loop_cnt = 0;

	while ((dinf = readdir(dp)) != NULL)
	{
		++loop_cnt;
		debug("in main loop: path %s", path);

		if (strcmp(".", dinf->d_name) == 0
		    || strcmp("..", dinf->d_name) == 0)
		  { debug("continuing (%s)", dinf->d_name); continue; }

		if (IGNORE_HIDDEN) { if (dinf->d_name[0] == 0x2e) continue; }

		debug("file %s", dinf->d_name);

		strncpy((path + n), dinf->d_name, strlen(dinf->d_name));
		*(path + n + strlen(dinf->d_name)) = 0;

		for (i = 0; illegal_terms[i] != NULL; ++i)
		{
			if (strstr(path, illegal_terms[i]))
			  { debug("illegal term (%s) in path (%s)", illegal_terms[i], path); illegal = 1; }
		}

		if (illegal) { illegal = 0; continue; }		

		if (user_blacklist != NULL)
		{
			for (i = 0; user_blacklist[i] != NULL; ++i)
		  {
				if (strstr(path, user_blacklist[i]))
				  { debug("blacklisted term (%s) in path (%s)", user_blacklist[i], path); illegal = 1; }
		  }

			if (illegal) { illegal = 0; continue; }
		}

		memset(&cur_file_stats, 0, sizeof(cur_file_stats));
		if (lstat(path, &cur_file_stats) < 0)
		{
			if (errno == EACCES) continue;

			log_err("scan_dirs: lstat error for %s (line %d)", path, __LINE__); goto fail;
		}

		if (S_ISLNK(cur_file_stats.st_mode)) continue;
		if (S_ISSOCK(cur_file_stats.st_mode)) continue;
		if (S_ISCHR(cur_file_stats.st_mode)) continue;

		if (S_ISREG(cur_file_stats.st_mode))
		{
			++files_scanned;
			used_bytes += cur_file_stats.st_size;

			debug("adding file %s to tree", path);

			if (insert_file(&root, path, cur_file_stats.st_size, tmp_fp) < 0)
				return(-1);
		}

		else if (S_ISDIR(cur_file_stats.st_mode))
		{
#ifdef __APPLE__
			/*
			 * on OS X, cannot save directory position with telldir()
			 * and then reopen the directory and seek to that position
			 * because the return from telldir() is rendered invalid
			 * on closing/reopening the directory.
			 */
			char		*cur_file_name = NULL;
			size_t		sz;

			sz = ((strlen(dinf->d_name) + 0x10) & ~(0xf));
			if (!(cur_file_name = calloc(sz, 1)))
			{
				log_err("insert_file: failed to allocate memory for current file %s (line %d)",
					dinf->d_name, __LINE__);
				goto fail;
			}

			strncpy(cur_file_name, dinf->d_name, strlen(dinf->d_name));
			cur_file_name[strlen(dinf->d_name)] = 0;

			closedir(dp);
			close_excess_fds(NO_DELETE ? 3 : (tmp_fd + 1), rlims.rlim_cur);

			if (scan_dirs(path) < 0) goto fail;

			path[n] = 0;

			/* do not need to worry here about open() failing because we
			 * already previously opened PATH with no problems
			 */
			if (!(dp = fdopendir(open(path, O_RDONLY)))) { log_err("insert_file: opendir error"); goto fail; }

			rewinddir(dp);

			dinf = readdir(dp);

			if (! dinf) goto fini;

			/*
			 * Just read until we reach the file we were previously
			 * at before closing and reopening the directory
			 * (successfully tested on OS X High Sierra)
			 */
			while (strcmp(dinf->d_name, cur_file_name) != 0 && dinf)
				dinf = readdir(dp);

			if (! dinf) goto fini;

			if (cur_file_name != NULL) { free(cur_file_name); cur_file_name = NULL; }

#else
			dir_position = telldir(dp);

			closedir(dp);
			dp = NULL;

			close_excess_fds(NO_DELETE ? 3 : (tmp_fd + 1), rlims.rlim_cur);

			debug("descending into %s", path);

			if (scan_dirs(path) < 0) goto fail;

			path[n] = 0;

			debug("reopening %s", path);

			/* do not need to worry here about open() failing because we
			 * already previously opened PATH with no problems
			 */
			if (!(dp = fdopendir(open(path, O_RDONLY))))
			{ log_err("scan_dirs: opendir error (line %d)", __LINE__); goto fail; }

			seekdir(dp, dir_position);
#endif
		}
		else
		{
			continue;
		}

	} // while ((dir_inf = readdir()) != NULL)

	debug("finished main loop");

#ifdef __APPLE__
	fini:
#endif
	path[n_sv] = 0;
	return(0);

	fail:
	path[n_sv] = 0;
	return(-1);
}

int
insert_file(Node **root, char *fname, size_t size, FILE *fp)
{
	int		i = 0;
	unsigned char	*cur_file_hash = NULL;
	unsigned char	*comp_file_hash = NULL;
	char		*h = NULL;
	Node		*nptr = NULL;
	size_t		l = 0, rl = 0;

	l = strlen(fname);
	rl = ((l + 0xf) & ~(0xf));

	if (*root == NULL)
	  {
		if (!((*root) = malloc(sizeof(Node))))
		  { log_err("insert_file: malloc error"); goto fail; }

		memset(*root, 0, sizeof(Node));

		if (!((*root)->name = calloc(rl, 1)))
		  { log_err("insert_file: calloc error"); goto fail; }

		strncpy((*root)->name, fname, l);
		(*root)->name[l] = 0;
		(*root)->hash[0] = 0;
		(*root)->size = size;
		(*root)->l = NULL;
		(*root)->r = NULL;
		(*root)->s = NULL;
		(*root)->array = 0;

		return(0);
	  }

	if (size < (*root)->size)
	  { if (insert_file(&(*root)->l, fname, size, fp) < 0) return(-1); }

	else if (size > (*root)->size)
	  { if (insert_file(&(*root)->r, fname, size, fp) < 0) return(-1); }

	else // possible duplicate file
	  {
		//if (!(hash_hex = calloc(HASH_SIZE+1, 1))) { log_err("insert_file: calloc error"); goto fail; }

		if (!(cur_file_hash = get_sha256_file(fname)))
		  {
			if (errno == EACCES)
				goto fini;

			log_err("insert_file: get_sha256_file error");
			goto fail;
		  }

		if (!(h = hexlify(cur_file_hash, (HASH_SIZE >> 1))))
		  { log_err("insert_file: hexlify error"); goto fail; }

		strncpy(hash_hex, h, HASH_SIZE);

		if ((*root)->hash[0] == 0)
		  {
			if (!(comp_file_hash = get_sha256_file((*root)->name)))
		  	  {
				if (errno == EACCES)
					goto fini;

				log_err("insert_file: get_sha256_file_r error");
				goto fail;
		 	   }

			if (!(h = hexlify(comp_file_hash, (HASH_SIZE >> 1))))
		    	  { log_err("insert_file: hexlify error"); goto fail; }

			strncpy((*root)->hash, h, HASH_SIZE);
		  }

		if (strncmp(hash_hex, (*root)->hash, HASH_SIZE) == 0) // duplicate files
		  {
			wasted_bytes += cur_file_stats.st_size;
			++dup_files;

			if (print_and_decide(hash_hex, fname, (*root)->name, fp) == -1)
			  { log_err("insert_file: print_and_decide error"); goto fail; }

			goto fini;
		  }
		else
		  {
			/*
			 * Before, those nodes with the same size were joined using a linked list;
			 * but due to not great performance (presumably due to non-contiguous
			 * memory accesses while testing for a duplicate file in the linked list),
			 * using a single array of nodes, which will go as needed. This should ensure
			 * better spatial locality and thus better usage of the fast cache memories
			 */
			if ((*root)->array == 0)
			  {
				if (!((*root)->s = calloc(1, sizeof(Node))))
				    { log_err("insert_file: calloc error"); goto fail; }

				(*root)->array = 1;

				if (!(((*root)->s[0]).name = calloc(rl, 1)))
				  { log_err("insert_file: calloc error"); goto fail; }

				strncpy((*root)->s[0].name, fname, l);
				((*root)->s[0]).name[l] = 0;

				strncpy((*root)->s[0].hash, hash_hex, HASH_SIZE);

				((*root)->s[0]).size = size;
				((*root)->s[0]).array = 0;
				((*root)->s[0]).l = NULL;
				((*root)->s[0]).r = NULL;
				((*root)->s[0]).s = NULL;

				goto fini;
			  }
			else
			  {
				/* compare FNAME with two at a time each iteration */
				for (i = 0; i < ((*root)->array - 1); i+=2)
				  {
					if (strncmp(hash_hex, ((*root)->s[i]).hash, HASH_SIZE) == 0)
		 			  {
						wasted_bytes += cur_file_stats.st_size;
						++dup_files;

						if (print_and_decide(hash_hex, fname, (*root)->s[i].name, fp) == -1)
						  { log_err("insert_file: print_and_decide error"); goto fail; }

						goto fini;
					  }
					else if (strncmp(hash_hex, ((*root)->s[i+1]).hash, HASH_SIZE) == 0)
					  {
						wasted_bytes += cur_file_stats.st_size;
						++dup_files;

						if (print_and_decide(hash_hex, fname, (*root)->s[i+1].name, fp) == -1)
						  { log_err("insert_file: print_and_decide error"); goto fail; }

						goto fini;
					  }
					else { continue; }
				  }

				if (i < (*root)->array)
				  {
					if (strncmp(hash_hex, ((*root)->s[i]).hash, HASH_SIZE) == 0)
					  {
						wasted_bytes += cur_file_stats.st_size;
						++dup_files;

						if (print_and_decide(hash_hex, fname, (*root)->s[i].name, fp) == -1)
						  { log_err("insert_file: print_and_decide error"); goto fail; }

						goto fini;
					  }
				  }

				(*root)->array = ((*root)->array + 1);

				if (!((*root)->s = realloc((*root)->s, (*root)->array * sizeof(Node))))
				  { log_err("insert_file: realloc error"); goto fail; }

				nptr = &((*root)->s[((*root)->array - 1)]);

				memset(nptr, 0, sizeof(Node));
				nptr->array = 0;
				nptr->l = NULL;
				nptr->r = NULL;
				nptr->s = NULL;

				if (!(nptr->name = calloc(rl, 1)))
				  { log_err("insert_file: malloc error"); goto fail; }
				strncpy(nptr->name, fname, l);
				nptr->name[l] = 0;

				strncpy(nptr->hash, hash_hex, HASH_SIZE);

				nptr->size = size;
			  }
		  }
	  }

	fini:
	//if (hash_hex != NULL) { free(hash_hex); hash_hex = NULL; }

	return (0);

	fail:
	//if (hash_hex != NULL) { free(hash_hex); hash_hex = NULL; }

	return(-1);
}

void
free_tree(Node **root)
{
	int		i = 0;

	if (*root == NULL) return;

	if ((*root)->l) free_tree(&((*root)->l));
	if ((*root)->r) free_tree(&((*root)->r));

	if ((*root)->array > 0)
	  {
		for (i = 0; i < (*root)->array; ++i)
		  {
			if (((*root)->s[i]).name != NULL)
			  { free(((*root)->s[i]).name); ((*root)->s[i]).name = NULL; }
		  }

		(*root)->array = 0;
	  }

	if ((*root)->name != NULL) { free((*root)->name); (*root)->name = NULL; }

	free(*root); *root = NULL;

	return;
}

void
log_err(char *fmt, ...)
{
	va_list		args;
	char		*tmp = NULL;

	tmp = calloc(MAXLINE, 1);
	memset(tmp, 0, MAXLINE);

	va_start(args, fmt);
	vsprintf(tmp, fmt, args);
	va_end(args);

	fprintf(stderr, "%s (%s)\n", tmp, strerror(errno));

	if (tmp != NULL) { free(tmp); tmp = NULL; }
	return;
}

void
debug(char *fmt, ...)
{
	va_list		args;
	char		*tmp = NULL;

	if (DEBUG)
	  {
		tmp = calloc(MAXLINE, 1);
		memset(tmp, 0, MAXLINE);

		va_start(args, fmt);
		vsprintf(tmp, fmt, args);
		va_end(args);

		fprintf(stderr, "[debug]: %s\n", tmp);

		if (tmp != NULL) { free(tmp); tmp = NULL; }
	  }

	return;
}

void
signal_handler(int signo)
{
	int	i = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	for (i = 0; i < 2; ++i)
		printf("%c%c%c", 0x08, 0x20, 0x08);
	setvbuf(stdout, NULL, _IOLBF, 0);

	printf("\n>>> Pollux v1.0 <<<\n*** Caught %s ***\n",
		(signo==SIGINT?"SIGINT":
		 signo==SIGQUIT?"SIGQUIT":"signal"));

	time(&end);
	print_stats();
	free_tree(&root);

	exit(EXIT_SUCCESS);
}

void
pollux_init(void)
{
	used_bytes = 0;
	wasted_bytes = 0;
	files_scanned = 0;
	dup_files = 0;

	OPENSSL_config(NULL);
	OpenSSL_add_all_digests();

	memset(&rlims, 0, sizeof(rlims));
	if (getrlimit(RLIMIT_NOFILE, &rlims) < 0)
	  { log_err("pollux_init: getrlimit error"); goto fail; }

	signal(SIGINT, signal_handler);
	signal(SIGQUIT, signal_handler);

	if (!(path = calloc((MAXLINE*2), 1)))
	  { log_err("pollux_init: calloc error (line %d)", __LINE__); goto fail; }

	if (!(line_buf = calloc(MAXLINE, 1)))
	  { log_err("pollux_init: calloc error (line %d)", __LINE__); goto fail; }

	if (!(hash_buf = calloc(32, 1)))
	  { log_err("pollux_init: calloc error (line %d)", __LINE__); goto fail; }

	if (!(hash_hex = calloc((HASH_SIZE+16), 1)))
	  { log_err("pollux_init: calloc error (line %d)", __LINE__); goto fail; }

	if (!(block = calloc(BLK_SIZE+16, 1)))
	  { log_err("pollux_init: calloc error (line %d)", __LINE__); goto fail; }

	return;

	fail:
	exit(EXIT_FAILURE);
}

void
pollux_fini(void)
{
	if (root) free_tree(&root);

	if (path != NULL) { free(path); path = NULL; }
	if (line_buf != NULL) { free(line_buf); line_buf = NULL; }
	if (hash_buf != NULL) { free(hash_buf); hash_buf = NULL; }
	if (hash_hex != NULL) { free(hash_hex); hash_hex = NULL; }
	if (block != NULL) { free(block); block = NULL; }
}

int
get_options(int argc, char *argv[])
{
	int		i = 0, j = 0;
	int		blist_idx = 0;

	for (i = 1; i < argc; ++i)
	  {
		while (i < argc
			&& strncmp("-", argv[i], 1) != 0
			&& strncmp("--", argv[i], 2) != 0)
			++i;

		if (i >= argc) break;

		if (strcmp("--help", argv[i]) == 0
			|| strcmp("-h", argv[i]) == 0)
		  {
				display_usage(EXIT_SUCCESS);

				exit(EXIT_SUCCESS);
		  }
		else
		if (strcmp("--blacklist", argv[i]) == 0
			|| strcmp("-B", argv[i]) == 0)
		  {
			if (!(user_blacklist = calloc(1, sizeof(char *))))
			  { log_err("get_options: calloc error"); goto fail; }

			user_blacklist[0] = NULL;

			++i;
			j = i;
			blist_idx = 0;

			while (j < argc
				&& strncmp("-", argv[j], 1) != 0
				&& strncmp("--", argv[j], 2) != 0)
			  {
				if (!(user_blacklist[blist_idx] = calloc(64, 1)))
				  { log_err("get_options: calloc error"); goto fail; }

				strncpy(user_blacklist[blist_idx], argv[j], strlen(argv[j]));
				user_blacklist[blist_idx][strlen(argv[j])] = 0;

				++blist_idx;

				++j;

				if (!(user_blacklist = realloc(user_blacklist, ((blist_idx+1) * sizeof(char *)))))
				  { log_err("get_options: realloc error"); goto fail; }
			  }

			user_blacklist[blist_idx] = NULL;

			i = (j-1);
		  }
		else if (strcmp("--nodelete", argv[i]) == 0
			|| strcmp("-N", argv[i]) == 0)
		  {
			NO_DELETE = 1;
		  }
		else if (strcmp("--nohidden", argv[i]) == 0)
		  {
			IGNORE_HIDDEN = 1;
		  }
		else if (strcmp("--quiet", argv[i]) == 0
			|| strcmp("-q", argv[i]) == 0)
		  {
			QUIET = 1;
		  }
		else
		if (strcmp("--debug", argv[i]) == 0
			|| strcmp("-D", argv[i]) == 0)
		  {
			DEBUG = 1;
		  }
		else
		  {
			continue;
		  }
	  }

	return(0);

	fail:
	if (user_blacklist != NULL)
	  {
		for (i = 0; user_blacklist[i] != NULL; ++i)
		  {
			if (user_blacklist[i] != NULL) { free(user_blacklist[i]); user_blacklist[i] = NULL; }
		  }
		free(user_blacklist);
		user_blacklist = NULL;
	  }
	return(-1);
}

void
print_stats(void)
{
	time_t		time_taken = 0;
	int		ret = 0;
	int		fd = -1;
	char		*quiet_out = NULL;

	time_taken = (end - start);

	if (QUIET)
	  {
		char	*home_dir = NULL;

		home_dir = getenv("HOME");
		quiet_out = calloc(MAXLINE, 1);
		if (quiet_out && home_dir)
			sprintf(quiet_out, "%s/pollux_scan_results.txt", home_dir);
		fd = open(quiet_out, O_RDWR|O_CREAT|O_TRUNC, S_IRWXU & ~S_IXUSR);
	  }

	if (time_taken > 3599)
	  {
		time_t	minutes;
		time_t	seconds;
		time_t	hours;

		hours = (time_taken / 3600);
		seconds = (time_taken % 3600);
		minutes = (seconds / 60);
		seconds -= (minutes * 60);

		if (QUIET)
		  {

			sprintf(line_buf,
				"%22s: %ld hour%s %ld minute%s %ld second%s\n",
				"Time elapsed",
				hours,
				(hours==1?"":"s"),
				minutes,
				(minutes==1?"":"s"),
				seconds,
				(seconds==1?"":"s"));

			if (fd > 0)
				ret = write(fd, line_buf, strlen(line_buf));
		  }
		else
		  {
			fprintf(stdout, "%22s: %ld hour%s %ld minute%s %ld second%s\n",
				"Time elapsed",
				hours,
				(hours==1?"":"s"),
				minutes,
				(minutes==1?"":"s"),
				seconds,
				(seconds==1?"":"s"));
		  }
	  }
	else if (time_taken > 59)
	  {
		time_t	minutes;
		time_t	seconds;

		minutes = (time_taken / 60);
		seconds = (time_taken % 60);

		if (QUIET)
		  {
			sprintf(line_buf,
				"%22s: %ld minute%s %ld second%s\n",
				"Time elapsed",
				minutes,
				(minutes==1?"":"s"),
				seconds,
				(seconds==1?"":"s"));

			if (fd > 0)
				ret = write(fd, line_buf, strlen(line_buf));
		  }
		else
		  {
			fprintf(stdout, "%22s: %ld minute%s %ld second%s\n",
				"Time elapsed",
				minutes,
				(minutes==1?"":"s"),
				seconds,
				(seconds==1?"":"s"));
		  }
	  }
	else
	  {
		if (QUIET)
		  {
			sprintf(line_buf,
				"%22s: %ld second%s\n",
				"Time elapsed",
				time_taken,
				(time_taken==1?"":"s"));

			if (fd > 0)
				ret = write(fd, line_buf, strlen(line_buf));
		  }
		else
		  {
			fprintf(stdout, "%22s: %ld second%s\n",
				"Time elapsed",
				time_taken,
				(time_taken==1?"":"s"));
		  }
	  }

	if (QUIET)
	  {
		sprintf(line_buf,
			"%22s: %d\n"
			"%22s: %d\n"
			"%22s: %.2lf %s\n"
			"%22s: %.2lf %s\n"
			"%22s: %.4lf%%\n",
			"Files scanned", files_scanned,
			(NO_DELETE?"Duplicate files":"Removed files"), dup_files,
			"Used memory",
			(used_bytes>999999999999999?(double)used_bytes/(double)1000000000000000:
		 	used_bytes>999999999999?(double)used_bytes/(double)1000000000000:
		 	used_bytes>999999999?(double)used_bytes/(double)1000000000:
		 	used_bytes>999999?(double)used_bytes/(double)1000000:
		 	used_bytes>999?(double)used_bytes/(double)1000:used_bytes),
			(used_bytes>999999999999999?"PB":
		 	used_bytes>999999999999?"TB":
		 	used_bytes>999999999?"GB":
		 	used_bytes>999999?"MB":
		 	used_bytes>999?"KB":"bytes"),
			(NO_DELETE?"Wasted memory":"Freed memory"),
			(wasted_bytes>999999999999999?(double)wasted_bytes/(double)1000000000000000:
		 	wasted_bytes>999999999999?(double)wasted_bytes/(double)1000000000000:
		 	wasted_bytes>999999999?(double)wasted_bytes/(double)1000000000:
		 	wasted_bytes>999999?(double)wasted_bytes/(double)1000000:
		 	wasted_bytes>999?(double)wasted_bytes/(double)1000:wasted_bytes),
			(wasted_bytes>999999999999999?"PB":
		 	wasted_bytes>999999999999?"TB":
		 	wasted_bytes>999999999?"GB":
		 	wasted_bytes>999999?"MB":
		 	wasted_bytes>999?"KB":"bytes"),
			(NO_DELETE?"Wasted/Used":"Freed/Used"),
			((double)wasted_bytes/(double)used_bytes)*100);

			if (fd > 0)
				ret = write(fd, line_buf, strlen(line_buf));
	  }
	else
	  {
	/*
	 * Want to avoid the compiler complaining about the unused result of write()
	 * so resetting to zero and using it in an add operation in the following
	 */
		ret = 0;

		fprintf(stdout,
		"%22s: %d\n"
		"%22s: %d\n"
		"%22s: %.2lf %s\n"
		"%22s: %.2lf %s\n"
		"%22s: %.4lf%%\n",
		"Files scanned", files_scanned,
		(NO_DELETE?"Duplicate files":"Removed files"), (dup_files+ret),
		"Used memory",
		(used_bytes>999999999999999?(double)used_bytes/(double)1000000000000000:
		 used_bytes>999999999999?(double)used_bytes/(double)1000000000000:
		 used_bytes>999999999?(double)used_bytes/(double)1000000000:
		 used_bytes>999999?(double)used_bytes/(double)1000000:
		 used_bytes>999?(double)used_bytes/(double)1000:used_bytes),
		(used_bytes>999999999999999?"PB":
		 used_bytes>999999999999?"TB":
		 used_bytes>999999999?"GB":
		 used_bytes>999999?"MB":
		 used_bytes>999?"KB":"bytes"),
		(NO_DELETE?"Wasted memory":"Freed memory"),
		(wasted_bytes>999999999999999?(double)wasted_bytes/(double)1000000000000000:
		 wasted_bytes>999999999999?(double)wasted_bytes/(double)1000000000000:
		 wasted_bytes>999999999?(double)wasted_bytes/(double)1000000000:
		 wasted_bytes>999999?(double)wasted_bytes/(double)1000000:
		 wasted_bytes>999?(double)wasted_bytes/(double)1000:wasted_bytes),
		(wasted_bytes>999999999999999?"PB":
		 wasted_bytes>999999999999?"TB":
		 wasted_bytes>999999999?"GB":
		 wasted_bytes>999999?"MB":
		 wasted_bytes>999?"KB":"bytes"),
		(NO_DELETE?"Wasted/Used":"Freed/Used"),
		((double)wasted_bytes/(double)used_bytes)*100);
	  }

	fputc(0x0a, stdout);

	if (QUIET)
	{
		if (quiet_out) { free(quiet_out); quiet_out = NULL; }
	}

	return;
}

int
remove_which(char *c1, char *c2)
{
	char		*p = NULL, *q = NULL;
	size_t		l1 = 0, l2 = 0;
	int		choice = 0;

	if (strstr(c1, "System Volume")) return(1);
	else if (strstr(c2, "System Volume")) return(2);

	if (strstr(c1, "/Temporary")) return(1);
	else if (strstr(c2, "/Temporary")) return(2);

	if (strstr(c1, "$RECYCLE")) return(1);
	else if (strstr(c2, "$RECYCLE")) return(2);

	if (strstr(c1, "Trash")) return(1);
	else if (strstr(c2, "Trash")) return(2);

	if (strstr(c1, "Copy")) return(1);
	else if (strstr(c2, "Copy")) return(2);

	if ((p = strchr(c1, 0x28)))
	  {
		if ((*(p+2) == 0x29) && isdigit(*(p+1))) { choice = 1; goto made_choice; }
	  }
	else if ((p = strchr(c2, 0x28)))
	  {
		if ((*(p+2) == 0x29) && isdigit(*(p+1))) { choice = 2; goto made_choice; }
	  }

	q = (c1 + (strlen(c1) - 1));
	p = q;
	while (*p != 0x2f && p > (c1 + 1)) --p;
	++p;

	l1 = (q - p);

	q = (c2 + (strlen(c2) - 1));
	p = q;
	while (*p != 0x2f && p > (c2 + 1)) --p;
	++p;

	l2 = (q - p);

	if (l1 < l2) choice = 1;
	else if (l2 < l1) choice = 2;
	else choice = 1;

	made_choice:
	return(choice);
}

int
print_and_decide(char *hash, char *f1, char *f2, FILE *fp)
{
	int		choice = 0;

	if (!NO_DELETE)
	  {
		choice = remove_which(f1, f2);
		if (choice < 0) { return(-1); }

		if (choice == 1) fprintf(fp, "%s\n", f1);
		else fprintf(fp, "%s\n", f2);

		fprintf(stdout,
			"%s _\e[m %s%.*s%s\n"
			"%s|_\e[m %s%.*s%s\n"
			"%s|\e[m\n"
			"%s`--->\e[m[\e[38;5;10m%s\e[m]\n\n",
			ARROW_COL,
			(choice==1?"\e[9;38;5;88m":""),
			max_col,
			f1,
			(choice==1?"\e[m":""),
			ARROW_COL,
			(choice==2?"\e[9;38;5;88m":""),
			max_col,
			f2,
			(choice==2?"\e[m":""),
			ARROW_COL,
			ARROW_COL,
			hash);
	  }
	else
	  {
		fprintf(stdout,
			"%s _\e[m %.*s\n"
			"%s|_\e[m %.*s\n"
			"%s|\e[m\n"
			"%s`--->\e[m[\e[38;5;10m%s\e[m]\n\n",
			ARROW_COL,
			max_col,
			f1,
			ARROW_COL,
			max_col,
			f2,
			ARROW_COL,
			ARROW_COL,
			hash);
	  }

	return(0);
}

unsigned char *
get_sha256_file(char *fname)
{
	EVP_MD_CTX		*ctx = NULL;
	int			fd = -1;
	int			_errno = 0;
	unsigned int		hashlen = 0;
	struct stat		statb;
	size_t			toread = 0;
	ssize_t			nbytes = 0;

	memset(&statb, 0, sizeof(statb));
	if (lstat(fname, &statb) < 0) goto fail;

	if ((fd = open(fname, O_RDONLY)) < 0) goto fail;

	if (!(ctx = EVP_MD_CTX_create())) goto fail;

	if (1 != EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) goto fail;

	toread = statb.st_size;

	while (toread > 0 && (nbytes = read(fd, block, BLK_SIZE)) > 0)
	  {
		block[nbytes] = 0;
		if (1 != EVP_DigestUpdate(ctx, block, nbytes)) goto fail;
		toread -= nbytes;
	  }

	if (1 != EVP_DigestFinal_ex(ctx, hash_buf, &hashlen)) goto fail;

	close(fd);
	if (ctx != NULL) { EVP_MD_CTX_destroy(ctx); ctx = NULL; }
	return(hash_buf);

	fail:
	_errno = errno;
	close(fd);
	if (ctx != NULL) { EVP_MD_CTX_destroy(ctx); ctx = NULL; }
	errno = _errno;
	return(NULL);
}

void
close_excess_fds(int start, int limit)
{
	int		i;

	for (i = start; i < limit; ++i)
		close(i);

	return;
}

void
strip_crnl(char *line)
{
	char	*p = NULL;
	size_t	l = 0;

	l = strlen(line);

	p = (line + (l - 1));

	if (*p != 0x0a && *p != 0x0d) return;

	while ((*p == 0x0d || *p == 0x0a) && p > (line + 1)) --p;

	++p;

	*p = 0;

	return;
}

char *
hexlify(unsigned char *data, size_t len)
{
	char	c = 0;
	int	i = 0, k = 0;

	k = 0;

	for (i = 0; i < len; ++i)
	  {
		c = ((data[i] >> 0x4) & 0x0f);
		if (c < 0x0a)
			c += 0x30;
		else
			c += 0x57;
		line_buf[k++] = c;

		c = (data[i] & 0x0f);
		if (c < 0x0a)
			c += 0x30;
		else
			c += 0x57;
		line_buf[k++] = c;
	  }

	line_buf[k] = 0;

	return(line_buf);
}

int
check_file(const char *file)
{
	if (access(file, F_OK) != 0)
	{
		fprintf(stderr, "check_file: %s does not exist\n", file);
		return 1;
	}
	else
	if (access(file, R_OK) != 0) // must be readable to get hash digest
	{
		fprintf(stderr, "check_file: not read permission for %s\n", file);
		return 1;
	}
	else
		return 0;
}

void
display_usage(const int exit_status)
{
	fprintf(stderr,
		"\n%s </path/to/directory> [options]\n\n"
		"-B,--blacklist		Blacklist keywords from scan\n"
		"-N,--nodelete		Don't delete the duplicate files\n"
		"--nohidden		Ignore hidden files (begin with '.')\n"
		"-q,--quiet		Only output final stats\n"
		"-D,--debug		Run in debug mode\n"
		"-h,--help		Display this information menu\n",
		program_name);

	exit(exit_status);
}
