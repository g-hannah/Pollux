CC=gcc

SOURCE_FILES := \
	polluxgui.c

OBJECT_FILES := ${SOURCE_FILES:.c=.o}

PKG_CFLAGS := $(shell echo `pkg-config --cflags gtk+-3.0`)
PKG_LIBS := $(shell echo `pkg-config --libs gtk+-3.0`)
LIBS := -lcrypto

pollux-gui: $(OBJECT_FILES)
	$(CC) -g -Wall -Werror $(PKG_CFLAGS) -o pollux-gui $(SOURCE_FILES) $(PKG_LIBS) $(LIBS)

$(OBJECT_FILES): $(SOURCE_FILES)
	$(CC) -g -Wall -Werror $(PKG_CFLAGS) $^ $(PKG_LIBS) $(LIBS)
