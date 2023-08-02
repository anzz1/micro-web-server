
CC     ?= cc
STRIP  ?= strip
CFLAGS ?= -O2 -Wall

TARGET = server

HAVE_SETUID ?= $(shell echo '\#include <unistd.h>\nint main(void){setgid(0);setuid(0);return 0;}' | $(CC) -Wall -Werror -x c -S -o - - >/dev/null 2>/dev/null && echo 1)

ifeq ($(HAVE_SETUID), 1)
	CFLAGS += -DHAVE_SETUID
endif

$(TARGET): server.c server.h server_config.h
	$(CC) $(CFLAGS) -o $(TARGET) server.c
	$(STRIP) -s $(TARGET)

all: $(TARGET)

clean:
	rm -f $(TARGET)
