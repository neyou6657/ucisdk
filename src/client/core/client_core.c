#include <stdio.h>

int client_transport_send_unix_socket(const char *socket_path,
                                      const char *request,
                                      char *response,
                                      size_t response_size);

int client_core_run_once(const char *socket_path, FILE *input, FILE *output) {
    char request[2048];
    char response[4096];

    if (socket_path == NULL || input == NULL || output == NULL) {
        return 1;
    }

    if (fgets(request, sizeof(request), input) == NULL) {
        fprintf(stderr, "no request on stdin\n");
        return 1;
    }

    if (client_transport_send_unix_socket(socket_path, request, response, sizeof(response)) != 0) {
        return 1;
    }

    fprintf(output, "%s", response);
    return 0;
}
