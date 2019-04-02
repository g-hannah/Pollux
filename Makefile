CC=gcc
CFILES=pollux.c
OFILES=pollux.o
WFLAGS=-Wall -Werror
LIBS=-lcrypto

pollux: $(OFILES)
	$(CC) $(WFLAGS) -O2 -o pollux $(OFILES) $(LIBS)

$(OFILES): $(CFILES)
	$(CC) $(WFLAGS) -O2 -c $(CFILES)

clean:
	rm *.o
