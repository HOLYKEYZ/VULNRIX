# Network Scanner Makefile
# Compiles pure C implementations

CC = gcc
CFLAGS = -Wall -O2 -pthread
TARGETS = port_scan banner_grab

# Detect OS
ifeq ($(OS),Windows_NT)
    LDFLAGS = -lws2_32
    EXT = .exe
else
    LDFLAGS = -lpthread
    EXT =
endif

all: $(TARGETS)

port_scan: port_scan.c
	$(CC) $(CFLAGS) -o port_scan$(EXT) port_scan.c $(LDFLAGS)

banner_grab: banner_grab.c
	$(CC) $(CFLAGS) -o banner_grab$(EXT) banner_grab.c $(LDFLAGS)

debug:
	$(CC) $(CFLAGS) -g -DDEBUG -o port_scan$(EXT) port_scan.c $(LDFLAGS)

clean:
	rm -f port_scan$(EXT) banner_grab$(EXT) *.o *.json

test: port_scan
	@echo "Testing port scanner..."
	./port_scan$(EXT) scanme.nmap.org top100 20 1000

install: $(TARGETS)
	cp port_scan$(EXT) /usr/local/bin/
	cp banner_grab$(EXT) /usr/local/bin/

.PHONY: all clean test install debug
