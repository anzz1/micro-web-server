
CC     ?= cc
STRIP  ?= strip
CFLAGS ?= -O2 -Wall

TARGET = server

$(TARGET):
	$(CC) $(CFLAGS) -o $(TARGET) server.c
	$(STRIP) -s $(TARGET)

all: $(TARGET)

clean:
	rm -f $(TARGET)
