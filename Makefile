CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Werror -pedantic -O2 -pthread -Iinclude
LDFLAGS ?= -pthread

COMMON_SRC = \
	src/common/log.c

SERVER_GATEWAY_SRC = \
	src/server/gateway/main.c \
	src/server/gateway/server.c \
	src/server/gateway/protocol.c \
	src/server/gateway/queue.c

SERVER_SERVICE_SRC = \
	src/server/service/config.c \
	src/server/service/resource.c \
	src/server/service/scheduler.c \
	src/server/service/translator.c

SERVER_DRIVER_SRC = \
	src/server/driver/driver_dispatch.c \
	src/server/driver/driver_classic.c \
	src/server/driver/driver_pqc.c

SRC = \
	$(SERVER_GATEWAY_SRC) \
	$(SERVER_SERVICE_SRC) \
	$(SERVER_DRIVER_SRC) \
	$(COMMON_SRC)

TEST_SRC = \
	tests/test_runner.c \
	src/server/gateway/protocol.c \
	src/server/gateway/queue.c \
	src/server/service/config.c \
	src/server/service/resource.c \
	src/server/service/scheduler.c \
	src/server/service/translator.c \
	src/server/driver/driver_dispatch.c \
	src/server/driver/driver_classic.c \
	src/server/driver/driver_pqc.c \
	src/common/log.c

CLIENT_SRC = \
	src/client/api/client_api.c \
	src/client/core/client_core.c \
	src/client/transport/client_transport.c \
	src/common/log.c

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
