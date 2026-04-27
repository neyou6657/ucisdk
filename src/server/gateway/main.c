#include "config.h"
#include "log.h"
#include "server.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    resource_registry_t registry;
    gateway_settings_t gateway_settings;
    server_t server;
    char errbuf[256];
    const char *device_config_path = "./configs/devices.conf";
    const char *gateway_config_path = "./configs/gateway.conf";
    const char *socket_path = "/tmp/crypto_gateway.sock";

    if (argc >= 2) {
        device_config_path = argv[1];
    }
    if (argc >= 3) {
        gateway_config_path = argv[2];
    }
    if (argc >= 4) {
        socket_path = argv[3];
    }

    registry_init(&registry);
    if (load_resources_from_file(device_config_path, &registry, errbuf, sizeof(errbuf)) != 0) {
        log_error("device config load failed: %s", errbuf);
        return 1;
    }
    if (load_gateway_settings(gateway_config_path, &gateway_settings, errbuf, sizeof(errbuf)) != 0) {
        log_error("gateway config load failed: %s", errbuf);
        return 1;
    }

    log_info("loaded %zu devices", registry.count);
    return server_run(&server, socket_path, &registry, &gateway_settings, DEFAULT_WORKERS) == 0 ? 0 : 1;
}
