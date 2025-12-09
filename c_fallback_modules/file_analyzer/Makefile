# File Analyzer Makefile
# Compiles pure C implementations

CC = gcc
CFLAGS = -Wall -O2
TARGETS = file_hash file_analyze

# Detect OS
ifeq ($(OS),Windows_NT)
    EXT = .exe
else
    EXT =
endif

all: $(TARGETS)

file_hash: file_hash.c
	$(CC) $(CFLAGS) -o file_hash$(EXT) file_hash.c

file_analyze: file_analyze.c
	$(CC) $(CFLAGS) -o file_analyze$(EXT) file_analyze.c

# With OpenSSL (faster)
file_hash_ssl: file_hash.c
	$(CC) $(CFLAGS) -o file_hash_ssl$(EXT) file_hash.c -lcrypto

debug:
	$(CC) $(CFLAGS) -g -DDEBUG -o file_hash$(EXT) file_hash.c
	$(CC) $(CFLAGS) -g -DDEBUG -o file_analyze$(EXT) file_analyze.c

clean:
	rm -f file_hash$(EXT) file_analyze$(EXT) file_hash_ssl$(EXT) *.o *.json

test: $(TARGETS)
	@echo "Testing file hash..."
	./file_hash$(EXT) Makefile
	@echo "Testing file analyzer..."
	./file_analyze$(EXT) Makefile

install: $(TARGETS)
	cp file_hash$(EXT) /usr/local/bin/
	cp file_analyze$(EXT) /usr/local/bin/

.PHONY: all clean test install debug
