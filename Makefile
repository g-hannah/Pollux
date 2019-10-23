CC=gcc
WFLAGS=-Wall -Werror
LIBS=-lcrypto
BUILD=2.0.4
DEBUG:=0

.PHONY: clean

SOURCE_FILES := \
	cache.c \
	pollux.c

OBJECT_FILES := ${SOURCE_FILES:.c=.o}

pollux: $(OBJECT_FILES)
	$(CC) $(WFLAGS) -O2 -o pollux $(OBJECT_FILES) $(LIBS)

$(OBJECT_FILES): $(SOURCE_FILES)
ifeq ($(DEBUG),1)
	@echo "Compiling DEBUG version (build $(BUILD))"
	$(CC) -g -DDEBUG $(WFLAGS) -O2 -c $(SOURCE_FILES)
else
	@echo "Compiling PRODUCTION version (build $(BUILD))"
	$(CC) $(WFLAGS) -O2 -c $(SOURCE_FILES)
endif

clean:
	rm *.o
