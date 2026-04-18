#include "config.h"
#include "protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int parse_bool(const char *s) {
    return strcmp(s, "1") == 0 ? 1 : 0;
}

static int parse_capability(const char *s, capability_t *cap) {
    char tmp[160];
    char *first;
    char *second;
    snprintf(tmp, sizeof(tmp), "%s", s);
    first = strchr(tmp, ':');
    if (first == NULL) {
        return -1;
    }
    *first = '\0';
    second = strchr(first + 1, ':');
    if (second == NULL) {
        return -1;
    }
    *second = '\0';

    cap->domain = parse_domain(tmp);
    cap->action = parse_action(first + 1);
    if (cap->domain == DOMAIN_UNKNOWN || cap->action == ACTION_UNKNOWN) {
        return -1;
    }
    if (normalize_algorithm_name(second + 1, cap->algorithm, sizeof(cap->algorithm)) != 0) {
        return -1;
    }
    return 0;
}

int load_resources_from_file(const char *path, resource_registry_t *registry, char *errbuf, size_t errbuf_sz) {
    FILE *fp = fopen(path, "r");
    char line[1024];
    if (fp == NULL) {
        snprintf(errbuf, errbuf_sz, "failed to open config: %s", path);
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        device_resource_t device;
        char caps[512];
        char *token;
        char *rest;
        char *cap_rest;
        char *cap_token;

        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }
        memset(&device, 0, sizeof(device));
        line[strcspn(line, "\r\n")] = '\0';
        token = strtok_r(line, ",", &rest);
        if (token == NULL) continue;
        snprintf(device.device_id, sizeof(device.device_id), "%s", token);
        token = strtok_r(NULL, ",", &rest);
        if (token == NULL) continue;
        device.type = parse_device_type(token);
        token = strtok_r(NULL, ",", &rest);
        if (token == NULL) continue;
        snprintf(device.backend_profile, sizeof(device.backend_profile), "%s", token);
        token = strtok_r(NULL, ",", &rest);
        if (token == NULL) continue;
        device.priority = atoi(token);
        token = strtok_r(NULL, ",", &rest);
        if (token == NULL) continue;
        device.enabled = parse_bool(token) ? true : false;
        token = strtok_r(NULL, ",", &rest);
        if (token == NULL) continue;
        device.max_inflight = atoi(token);
        token = strtok_r(NULL, ",", &rest);
        if (token == NULL) continue;
        device.security_score = atoi(token);
        token = strtok_r(NULL, ",", &rest);
        if (token == NULL) continue;
        device.efficiency_score = atoi(token);
        token = strtok_r(NULL, ",", &rest);
        if (token == NULL) continue;
        snprintf(caps, sizeof(caps), "%s", token);

        cap_token = strtok_r(caps, "|", &cap_rest);
        while (cap_token != NULL) {
            if (device.cap_count >= MAX_CAPS) {
                fclose(fp);
                snprintf(errbuf, errbuf_sz, "too many capabilities on device %s", device.device_id);
                return -1;
            }
            if (parse_capability(cap_token, &device.caps[device.cap_count]) != 0) {
                fclose(fp);
                snprintf(errbuf, errbuf_sz, "invalid capability '%s' on device %s", cap_token, device.device_id);
                return -1;
            }
            device.cap_count++;
            cap_token = strtok_r(NULL, "|", &cap_rest);
        }

        if (registry_add(registry, &device) != 0) {
            fclose(fp);
            snprintf(errbuf, errbuf_sz, "registry full");
            return -1;
        }
    }

    fclose(fp);
    return 0;
}

int load_gateway_settings(const char *path, gateway_settings_t *settings, char *errbuf, size_t errbuf_sz) {
    FILE *fp = fopen(path, "r");
    char line[256];
    memset(settings, 0, sizeof(*settings));
    if (fp == NULL) {
        snprintf(errbuf, errbuf_sz, "failed to open gateway config: %s", path);
        return -1;
    }
    while (fgets(line, sizeof(line), fp) != NULL) {
        char *eq;
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '#' || line[0] == '\0') {
            continue;
        }
        eq = strchr(line, '=');
        if (eq == NULL) {
            continue;
        }
        *eq = '\0';
        if (strcmp(line, "gateway_pin") == 0) {
            snprintf(settings->gateway_pin, sizeof(settings->gateway_pin), "%s", eq + 1);
        }
    }
    fclose(fp);
    if (settings->gateway_pin[0] == '\0') {
        snprintf(errbuf, errbuf_sz, "gateway_pin missing in %s", path);
        return -1;
    }
    return 0;
}
