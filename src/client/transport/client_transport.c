#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int client_transport_send_unix_socket(const char *socket_path,
                                      const char *request,
                                      char *response,
                                      size_t response_size) {
    int fd;
    struct sockaddr_un addr;
    size_t len;
    ssize_t n;

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
    if (write(fd, request, len) < 0) {
        perror("write");
        close(fd);
        return -1;
    }

    if (len == 0U || request[len - 1U] != '\n') {
        if (write(fd, "\n", 1U) < 0) {
            perror("write");
            close(fd);
            return -1;
        }
    }

    n = read(fd, response, response_size - 1U);
    if (n < 0) {
        perror("read");
        close(fd);
        return -1;
    }

    response[n] = '\0';
    close(fd);
    return 0;
}
