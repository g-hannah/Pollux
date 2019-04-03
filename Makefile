CC=gcc
CFILES=pollux.c
OFILES=pollux.o
CFLAGS=-g
WFLAGS=-Wall -Werror
LIBS=-lcrypto

pollux: $(OFILES)
	$(CC) $(CFLAGS) $(WFLAGS) -O2 -o pollux $(OFILES) $(LIBS)

$(OFILES): $(CFILES)
	$(CC) $(CFLAGS) $(WFLAGS) -O2 -c $(CFILES)

clean:
	rm *.o
