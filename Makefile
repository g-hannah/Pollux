CC=gcc
CFILES=pollux.c
OFILES=pollux.o
LIBS=-lcrypto -lhashlib -lmisclib

pollux: $(OFILES)
	$(CC) -g -o pollux $(OFILES) $(LIBS)

$(OFILES): $(CFILES)
	$(CC) -c $(CFILES)

clean:
	rm *.o
