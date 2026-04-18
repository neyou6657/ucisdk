CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Werror -pedantic -O2 -pthread -Iinclude
LDFLAGS ?= -pthread

SRC = \
	src/main.c \
	src/log.c \
	src/protocol.c \
	src/config.c \
	src/resource.c \
	src/queue.c \
	src/translator.c \
	src/scheduler.c \
	src/driver_dispatch.c \
	src/driver_classic.c \
	src/driver_pqc.c \
	src/server.c

TEST_SRC = \
	tests/test_runner.c \
	src/log.c \
	src/protocol.c \
	src/config.c \
	src/resource.c \
	src/queue.c \
	src/translator.c \
	src/scheduler.c \
	src/driver_dispatch.c \
	src/driver_classic.c \
	src/driver_pqc.c

CLIENT_SRC = src/client.c src/log.c

all: bin/crypto_gateway bin/crypto_client bin/test_runner

bin/crypto_gateway: $(SRC)
	mkdir -p bin
	$(CC) $(CFLAGS) $(SRC) -o $@ $(LDFLAGS)

bin/crypto_client: $(CLIENT_SRC)
	mkdir -p bin
	$(CC) $(CFLAGS) $(CLIENT_SRC) -o $@ $(LDFLAGS)

bin/test_runner: $(TEST_SRC)
	mkdir -p bin
	$(CC) $(CFLAGS) $(TEST_SRC) -o $@ $(LDFLAGS)

test: all
	./bin/test_runner
	./tests/e2e.sh

clean:
	rm -rf bin

.PHONY: all test clean
