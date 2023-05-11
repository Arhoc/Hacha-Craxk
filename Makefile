CC = gcc
CFLAGS = `pkg-config --cflags libcrypto` -O3 -march=native -flto -funroll-all-loops `pkg-config --cflags libcrypto
LDFLAGS = `pkg-config --libs libcrypto`
TARGET = Hacha-Crack

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(TARGET)
