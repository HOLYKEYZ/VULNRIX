# OSINT Tools Makefile
# Compiles pure C implementations

CC = gcc
CFLAGS = -Wall -O2
TARGETS = secret_scanner search_engine

# Detect OS
ifeq ($(OS),Windows_NT)
    LDFLAGS = -lws2_32
    EXT = .exe
else
    LDFLAGS =
    EXT =
endif

all: $(TARGETS)

secret_scanner: secret_scanner.c
	$(CC) $(CFLAGS) -o secret_scanner$(EXT) secret_scanner.c

search_engine: search_engine.c
	$(CC) $(CFLAGS) -o search_engine$(EXT) search_engine.c $(LDFLAGS)

debug:
	$(CC) $(CFLAGS) -g -DDEBUG -o secret_scanner$(EXT) secret_scanner.c
	$(CC) $(CFLAGS) -g -DDEBUG -o search_engine$(EXT) search_engine.c $(LDFLAGS)

clean:
	rm -f secret_scanner$(EXT) search_engine$(EXT) *.o *.json

test_secrets: secret_scanner
	@echo "Testing secret scanner..."
	./secret_scanner$(EXT) . secrets.json

test_search: search_engine
	@echo "Testing search engine..."
	./search_engine$(EXT) "site:github.com security scanner" results.json

test: test_secrets test_search

install: $(TARGETS)
	cp secret_scanner$(EXT) /usr/local/bin/
	cp search_engine$(EXT) /usr/local/bin/

.PHONY: all clean test test_secrets test_search install debug
