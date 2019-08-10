CC=gcc
CFILES=pollux.c
OFILES=pollux.o
WFLAGS=-Wall -Werror
LIBS=-lcrypto
BUILD=2.0.4
DEBUG:=0

.PHONY: clean

pollux: $(OFILES)
	$(CC) $(WFLAGS) -O2 -o pollux $(OFILES) $(LIBS)

$(OFILES): $(CFILES)
ifeq ($(DEBUG),1)
	@echo "Compiling DEBUG version (build $(BUILD))"
	$(CC) -g -DDEBUG $(WFLAGS) -O2 -c $(CFILES)
else
	@echo "Compiling PRODUCTION version (build $(BUILD))"
	$(CC) $(WFLAGS) -O2 -c $(CFILES)
endif

clean:
	rm *.o
