#include <stdio.h>

int client_core_run_once(const char *socket_path, FILE *input, FILE *output);

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <socket_path>\n", argv[0]);
        return 1;
    }

    return client_core_run_once(argv[1], stdin, stdout);
}
