# Breach Checker Makefile
# Compiles pure C implementation

CC = gcc
CFLAGS = -Wall -O2
TARGET = breach_check

# Detect OS
ifeq ($(OS),Windows_NT)
    LDFLAGS = -lws2_32
    TARGET = breach_check.exe
else
    LDFLAGS =
endif

all: $(TARGET)

$(TARGET): breach_check.c
	$(CC) $(CFLAGS) -o $(TARGET) breach_check.c $(LDFLAGS)

debug: breach_check.c
	$(CC) $(CFLAGS) -g -DDEBUG -o $(TARGET) breach_check.c $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o *.json

test: $(TARGET)
	@echo "Testing breach checker..."
	./$(TARGET) hash test@example.com --email
	./$(TARGET) password testpassword123

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

.PHONY: all clean test install debug
