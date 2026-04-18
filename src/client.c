#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int fd;
    struct sockaddr_un addr;
    char request[2048];
    char response[4096];
    size_t len;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <socket_path>\n", argv[0]);
        return 1;
    }

    if (fgets(request, sizeof(request), stdin) == NULL) {
        fprintf(stderr, "no request on stdin\n");
        return 1;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", argv[1]);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("connect");
        close(fd);
        return 1;
    }

    len = strlen(request);
    if (write(fd, request, len) < 0) {
        perror("write");
        close(fd);
        return 1;
    }
    if (request[len - 1] != '\n') {
        (void)write(fd, "\n", 1U);
    }

    ssize_t n = read(fd, response, sizeof(response) - 1U);
    if (n < 0) {
        perror("read");
        close(fd);
        return 1;
    }
    response[n] = '\0';
    printf("%s", response);
    close(fd);
    return 0;
}
