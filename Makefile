CC = gcc
CFLAGS = -Iinclude `pkg-config --cflags libcrypto`
LDFLAGS = `pkg-config --libs libcrypto`
TARGET = Hacha-Crack

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(TARGET)
