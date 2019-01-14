#ifndef __MISCLIB
#define __MISCLIB

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define perr(str)									\
{											\
	fprintf(stderr, "[libmisclib.so]: %s (%s)\n", (str), strerror(errno));		\
	exit(0xff);									\
}

extern ssize_t read_n(int, char *, size_t) __nonnull ((2)) __wur;
extern ssize_t write_n(int, char *, size_t) __nonnull ((2)) __wur;
extern ssize_t send_n(int, char *, size_t, int) __nonnull ((2)) __wur;

extern char *hexlify(char *, size_t) __nonnull ((1)) __wur;
extern char *hexlify_r(char *, size_t, char **) __nonnull ((1,3)) __wur;
extern char *ascii_to_bin(char *) __nonnull ((1)) __wur;
extern char *ascii_to_bin_r(char *, char **) __nonnull ((1,2)) __wur;
extern void strip_crnl(char *, size_t) __nonnull ((1));
extern void change_case(char *, size_t, int) __nonnull ((1));
extern time_t get_time_t(char *) __nonnull ((1)) __wur;
extern void daemonise(void);

#endif // __MISCLIB
