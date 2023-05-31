ifeq (,$(CROSS_COMPILE))
$(error missing CROSS_COMPILE for this toolchain)
endif

ARCH    = arm
CC      = $(CROSS_COMPILE)gcc
STRIP   = $(CROSS_COMPILE)strip
CFLAGS  = -Os -Wall -marm -march=armv7ve+simd -mtune=cortex-a7 -mfpu=neon-vfpv4 -mfloat-abi=hard
CFLAGS += -ffunction-sections -fdata-sections -Wl,--gc-sections -Wl,-s
CFLAGS += -DNO_SETUID

TARGET = server

$(TARGET):
	$(CC) $(CFLAGS) -o $(TARGET) server.c
	$(STRIP) -s $(TARGET)

all: $(TARGET)

clean:
	rm -f $(TARGET)
