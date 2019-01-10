#include <misclib.h>

char			*t = NULL;

static void __misclib_clean(void);

static void
__attribute__ ((constructor)) __misclib_init(void)
{
	atexit(__misclib_clean);
	if (!(t = (char *)calloc(1024, sizeof(char))))
	  { fprintf(stderr, "[libmisclib.so]: __misclib_init() > calloc()\n"); exit(0xff); }
}

static void
__misclib_clean(void)
{
	if (t != NULL) { free(t); t = NULL; }
}


ssize_t
read_n(int fd, char *buf, size_t len)
{
	static size_t		toread;
	static ssize_t		n, tot;
	static char		*p = NULL;

	p = buf;
	toread = len;
	tot &= ~tot;

	while (toread > 0 && (n = read(fd, p, toread)) > 0)
	  {
		if (n < 0)
			return(-1);
		p += n;
		toread -= n;
		tot += n;
	  }

	return(tot);
}

ssize_t
write_n(int fd, char *buf, size_t len)
{
	static size_t		towrite;
	static ssize_t		n, tot;
	static char		*p = NULL;

	p = buf;
	towrite = len;
	tot &= ~tot;

	while (towrite > 0 && (n = write(fd, p, towrite)) > 0)
	  {
		if (n < 0)
			return(-1);
		p += n;
		towrite -= n;
		tot += n;
	  }

	return(tot);
}

ssize_t
send_n(int sock, char *buf, size_t len, int flags)
{
	static size_t		tosend;
	static ssize_t		n, tot;
	static char		*p = NULL;

	p = buf;
	tosend = len;
	tot &= ~tot;

	while (tosend > 0 && (n = send(sock, p, tosend, flags)) > 0)
	  {
		if (n < 0)
			return(-1);
		p += n;
		tosend -= n;
		tot += n;
	  }

	return(tot);
}

char *
hexlify(char *data, size_t len)
{
	static int		i, k;
	static char		c;

	k &= ~k;
	c &= ~c;

	memset(t, 0, 1024);
	for (i = 0; i < len; ++i)
	  {
		c = ((data[i] >> 0x4) & 0x0f);
		if (c < 0x0a)
			c += 0x30;
		else
			c += 0x57;
		t[k++] = c;

		c = (data[i] & 0x0f);
		if (c < 0x0a)
			c += 0x30;
		else
			c += 0x57;
		t[k++] = c;
	  }
	t[(len*2)] = 0;
	return(t);
}

char *
ascii_to_bin(char *a)
{
	size_t		l;
	int		i, j;
	char		c, *p = NULL;

	l = strlen(a);
	j &= ~j; c &= ~c;
	memset(t, 0, 1024);
	p = t;
	for (i = 0; i < (l-1); i+=2)
	  {
		if (a[i] > 0x39)
		  {
			c = ((a[i] - 0x57) & 0x0f);
			c <<= 4;
			c &= 0xf0;
		  }
		else
		  {
			c = ((a[i] - 0x30) & 0x0f);
			c <<= 4;
			c &= 0xf0;
		  }
		if (a[(i+1)] > 0x39)
		  {
			c |= ((a[(i+1)] - 0x57) & 0x0f);
		  }
		else
		  {
			c |= ((a[(i+1)] - 0x30) & 0x0f);
		  }
		
		*p = c;
		++p;
	  }

	*p = 0;
	return(t);
}

char *
ascii_to_bin_r(char *a, char **b)
{
	size_t		l;
	int		i, j;
	char		c, *p = NULL;

	l = strlen(a);
	j &= ~j; c &= ~c;
	p = *b;
	for (i = 0; i < (l-1); i+=2)
	  {
		if (a[i] > 0x39)
		  {
			c = ((a[i] - 0x57) & 0x0f);
			c <<= 4;
			c &= 0xf0;
		  }
		else
		  {
			c = ((a[i] - 0x30) & 0x0f);
			c <<= 4;
			c &= 0xf0;
		  }
		if (a[(i+1)] > 0x39)
		  {
			c |= ((a[(i+1)] - 0x57) & 0x0f);
		  }
		else
		  {
			c |= ((a[(i+1)] - 0x30) & 0x0f);
		  }
		
		*p = c;
		++p;
	  }

	return(*b);
}

void
strip_crnl(char *data, size_t l)
{
	static char 		*p = NULL;

	p = (data + (l - 1));
	while (*p != 0x0d && *p != 0x0a && p > (data + 1))
		--p;
	if (p == data)
		return;
	while ((*p == 0x0d || *p == 0x0a) && p > (data + 1))
		--p;
	if (p == data)
		return;
	++p;
	*p = 0;
}

void
change_case(char *data, size_t l, int flag)
{
	static int		i;

	for (i = 0; i < l; ++i)
	  {
		if (isalpha(data[i]))
		  {
			if (flag)
		  	  {
				data[i] = toupper(data[i]);
		  	  }
			else
		  	  {
				data[i] = tolower(data[i]);
		  	  }
		  }
		else
		  { continue; }
	  }
	return;
}

time_t
get_time_t(char *str)
{
	static char		*p = NULL, *q = NULL, dom[3], t[6];
	static struct tm	__time;
	static time_t		res;

	// format: DoW, DoM Month Year Hour:Minute:Seconds TZ
	memset(&__time, 0, sizeof(__time));
	p = q = str;
	while (*q != 0x2c && q < (str + strlen(str)))
		++q;
	if (*q != 0x2c)
	  { errno = EPROTO; return(-1); }
	if (strncasecmp("Mon", p, 3) == 0)
		__time.tm_wday = 0;
	else if (strncasecmp("Tue", p, 3) == 0)
		__time.tm_wday = 1;
	else if (strncasecmp("Wed", p, 3) == 0)
		__time.tm_wday = 2;
	else if (strncasecmp("Thu", p, 3) == 0)
		__time.tm_wday = 3;
	else if (strncasecmp("Fri", p, 3) == 0)
		__time.tm_wday = 4;
	else if (strncasecmp("Sat", p, 3) == 0)
		__time.tm_wday = 5;
	else if (strncasecmp("Sun", p, 3) == 0)
		__time.tm_wday = 6;

	// GET THE DAY OF THE MONTH
	++q;
	while (*q == 0x20) ++q;
	p = q;
	while (*q != 0x20 && q < (str + strlen(str)))
		++q;
	if (*q != 0x20)
	  { errno = EPROTO; return(-1); }
	if (*(p+1) == 0x30)
		++p;
	strncpy(dom, p, (q - p));
	dom[(q - p)] = 0;
	__time.tm_mday = atoi(dom);

	++q;
	p = q;
	while (*q != 0x20 && q < (str + strlen(str)))
		++q;
	if (*q != 0x20)
	  { errno = EPROTO; return(-1); }

	// GET THE MONTH OF THE YEAR
	if (strncasecmp("Jan", p, 3) == 0)
		__time.tm_mon = 0;
	else if (strncasecmp("Feb", p, 3) == 0)
		__time.tm_mon = 1;
	else if (strncasecmp("Mar", p, 3) == 0)
		__time.tm_mon = 2;
	else if (strncasecmp("Apr", p, 3) == 0)
		__time.tm_mon = 3;
	else if (strncasecmp("May", p, 3) == 0)
		__time.tm_mon = 4;
	else if (strncasecmp("Jun", p, 3) == 0)
		__time.tm_mon = 5;
	else if (strncasecmp("Jul", p, 3) == 0)
		__time.tm_mon = 6;
	else if (strncasecmp("Aug", p, 3) == 0)
		__time.tm_mon = 7;
	else if (strncasecmp("Sep", p, 3) == 0)
		__time.tm_mon = 8;
	else if (strncasecmp("Oct", p, 3) == 0)
		__time.tm_mon = 9;
	else if (strncasecmp("Nov", p, 3) == 0)
		__time.tm_mon = 10;
	else if (strncasecmp("Dec", p, 3) == 0)
		__time.tm_mon = 11;

	++q;
	p = q;
	while (*q != 0x20 && q < (str + strlen(str)))
		++q;
	if (*q != 0x20)
	  { errno = EPROTO; return(-1); }
	strncpy(t, p, (q - p));
	t[(q - p)] = 0;
	__time.tm_year = (atoi(t) - 1900);

	++q;
	p = q;
	while (*q != 0x3a && q < (str + strlen(str)))
		++q;
	if (*q != 0x3a)
	  { errno = EPROTO; return(-1); }
	
	strncpy(t, p, (q - p));
	t[(q - p)] = 0;
	__time.tm_hour = atoi(t);

	++q;
	p = q;
	while (*q != 0x3a && q < (str + strlen(str)))
		++q;
	if (*q != 0x3a)
	  { errno = EPROTO; return(-1); }

	strncpy(t, p, (q - p));
	t[(q - p)] = 0;
	__time.tm_min = atoi(t);

	++q;
	p = q;
	while (*q != 0x20 && q < (str + strlen(str)))
		++q;
	if (*q != 0x20)
	  { errno = EPROTO; return(-1); }

	strncpy(t, p, (q - p));
	t[(q - p)] = 0;
	__time.tm_sec = atoi(t);

	res = mktime(&__time);
	return(res);
}
