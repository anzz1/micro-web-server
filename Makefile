
CC     ?= cc
STRIP  ?= strip
CFLAGS ?= -O2 -Wall -march=native -fno-strict-aliasing -fno-strict-overflow -fvisibility=hidden -fomit-frame-pointer -fno-stack-protector -fno-pie -no-pie -Wl,--no-export-dynamic

TARGET = server

HAVE_SETUID ?= $(shell printf '\#include <unistd.h>\nint main(void){setgid(0);setuid(0);return 0;}' | $(CC) -Wall -Werror -x c -S -o - - >/dev/null 2>/dev/null && echo 1)

ifeq ($(HAVE_SETUID), 1)
	CFLAGS += -DHAVE_SETUID
endif

$(TARGET): server.c server.h server_config.h
	$(CC) $(CFLAGS) -o $(TARGET) server.c
	$(STRIP) -s $(TARGET)

all: $(TARGET)

clean:
	rm -f $(TARGET)
