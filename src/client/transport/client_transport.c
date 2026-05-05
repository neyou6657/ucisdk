#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int write_all(int fd, const char *buf, size_t len) {
    size_t sent = 0U;
    while (sent < len) {
        ssize_t n = write(fd, buf + sent, len - sent);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

static int read_response(int fd, char *response, size_t response_size) {
    size_t used = 0U;
    if (response_size == 0U) {
        return -1;
    }
    while (used + 1U < response_size) {
        ssize_t n = read(fd, response + used, response_size - used - 1U);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            break;
        }
        used += (size_t)n;
        if (memchr(response, '\n', used) != NULL) {
            break;
        }
    }
    response[used] = '\0';
    return 0;
}

int client_transport_send_unix_socket(const char *socket_path,
                                      const char *request,
                                      char *response,
                                      size_t response_size) {
    int fd;
    struct sockaddr_un addr;
    size_t len;

    if (socket_path == NULL || request == NULL || response == NULL || response_size == 0U) {
        return -1;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("connect");
        close(fd);
        return -1;
    }

    len = strlen(request);
    if (write_all(fd, request, len) != 0) {
        perror("write");
        close(fd);
        return -1;
    }

    if (len == 0U || request[len - 1U] != '\n') {
        if (write_all(fd, "\n", 1U) != 0) {
            perror("write");
            close(fd);
            return -1;
        }
    }

    if (read_response(fd, response, response_size) != 0) {
        perror("read");
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}
