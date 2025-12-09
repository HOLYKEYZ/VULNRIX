# WHOIS Lookup Makefile
# Compiles pure C implementation

CC = gcc
CFLAGS = -Wall -O2
TARGET = whois_lookup

# Detect OS
ifeq ($(OS),Windows_NT)
    LDFLAGS = -lws2_32
    TARGET = whois_lookup.exe
else
    LDFLAGS =
endif

all: $(TARGET)

$(TARGET): whois_lookup.c
	$(CC) $(CFLAGS) -o $(TARGET) whois_lookup.c $(LDFLAGS)

debug: whois_lookup.c
	$(CC) $(CFLAGS) -g -DDEBUG -o $(TARGET) whois_lookup.c $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o *.json

test: $(TARGET)
	@echo "Testing WHOIS lookup..."
	./$(TARGET) google.com
	./$(TARGET) 8.8.8.8

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

.PHONY: all clean test install debug
