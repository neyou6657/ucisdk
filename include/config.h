#ifndef CONFIG_H
#define CONFIG_H

#include "resource.h"

int load_resources_from_file(const char *path, resource_registry_t *registry, char *errbuf, size_t errbuf_sz);
int load_gateway_settings(const char *path, gateway_settings_t *settings, char *errbuf, size_t errbuf_sz);

#endif
