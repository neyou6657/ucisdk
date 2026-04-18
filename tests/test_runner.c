#include "config.h"
#include "protocol.h"
#include "scheduler.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ASSERT_TRUE(expr) do { if (!(expr)) { fprintf(stderr, "ASSERT_TRUE failed: %s at %s:%d\n", #expr, __FILE__, __LINE__); return 1; } } while (0)
#define ASSERT_EQ_INT(a,b) do { if ((a) != (b)) { fprintf(stderr, "ASSERT_EQ_INT failed: %d != %d at %s:%d\n", (a), (b), __FILE__, __LINE__); return 1; } } while (0)
#define ASSERT_CONTAINS(hay, needle) do { if (strstr((hay), (needle)) == NULL) { fprintf(stderr, "ASSERT_CONTAINS failed: '%s' not in '%s' at %s:%d\n", (needle), (hay), __FILE__, __LINE__); return 1; } } while (0)

static int load_registry(resource_registry_t *registry) {
    char err[128];
    registry_init(registry);
    return load_resources_from_file("./configs/devices.conf", registry, err, sizeof(err));
}

static int load_gateway(gateway_settings_t *settings) {
    char err[128];
    return load_gateway_settings("./configs/gateway.conf", settings, err, sizeof(err));
}

static int test_protocol_parse(void) {
    request_t req;
    char err[128];
    int rc = parse_request_json("{\"request_id\":\"r1\",\"domain\":\"asym\",\"action\":\"sign\",\"algorithm\":\"sm2\",\"key_ref\":\"k1\",\"payload\":\"abc\",\"user_pin\":\"123456\",\"preference\":\"balanced\"}", &req, err, sizeof(err));
    ASSERT_EQ_INT(rc, 0);
    ASSERT_EQ_INT(req.domain, DOMAIN_ASYM);
    ASSERT_EQ_INT(req.action, ACTION_SIGN);
    ASSERT_TRUE(strcmp(req.algorithm, "sm2") == 0);
    ASSERT_EQ_INT(req.preference, PREF_BALANCED);
    ASSERT_TRUE(strcmp(req.key_ref, "k1") == 0);
    return 0;
}

static int test_gateway_pin_check(void) {
    resource_registry_t registry;
    gateway_settings_t gw;
    scheduler_t scheduler;
    request_t req;
    response_t resp;
    char err[128];

    ASSERT_EQ_INT(load_registry(&registry), 0);
    ASSERT_EQ_INT(load_gateway(&gw), 0);
    scheduler_init(&scheduler, &registry, &gw);
    ASSERT_EQ_INT(parse_request_json("{\"request_id\":\"auth-1\",\"domain\":\"auth\",\"action\":\"check_pin\",\"user_pin\":\"123456\"}", &req, err, sizeof(err)), 0);
    ASSERT_EQ_INT(scheduler_execute(&scheduler, &req, &resp), 0);
    ASSERT_EQ_INT(resp.status, STATUS_OK);
    ASSERT_TRUE(strcmp(resp.result, "pin_ok") == 0);
    return 0;
}

static int test_classic_asym_sign(void) {
    resource_registry_t registry;
    gateway_settings_t gw;
    scheduler_t scheduler;
    request_t req;
    response_t resp;
    char err[128];

    ASSERT_EQ_INT(load_registry(&registry), 0);
    ASSERT_EQ_INT(load_gateway(&gw), 0);
    scheduler_init(&scheduler, &registry, &gw);
    ASSERT_EQ_INT(parse_request_json("{\"request_id\":\"r2\",\"domain\":\"asym\",\"action\":\"sign\",\"algorithm\":\"sm2\",\"key_ref\":\"k1\",\"payload\":\"hello\",\"user_pin\":\"123456\"}", &req, err, sizeof(err)), 0);
    ASSERT_EQ_INT(scheduler_execute(&scheduler, &req, &resp), 0);
    ASSERT_EQ_INT(resp.status, STATUS_OK);
    ASSERT_TRUE(strcmp(resp.selected_device, "classic-1") == 0);
    ASSERT_CONTAINS(resp.backend_call, "SDF_InternalSign_ECC_Ex");
    return 0;
}

static int test_classic_sym_encrypt(void) {
    resource_registry_t registry;
    gateway_settings_t gw;
    scheduler_t scheduler;
    request_t req;
    response_t resp;
    char err[128];

    ASSERT_EQ_INT(load_registry(&registry), 0);
    ASSERT_EQ_INT(load_gateway(&gw), 0);
    scheduler_init(&scheduler, &registry, &gw);
    ASSERT_EQ_INT(parse_request_json("{\"request_id\":\"r3\",\"domain\":\"sym\",\"action\":\"encrypt\",\"algorithm\":\"sm4-cbc\",\"key_ref\":\"k1\",\"payload\":\"hello\",\"user_pin\":\"123456\"}", &req, err, sizeof(err)), 0);
    ASSERT_EQ_INT(scheduler_execute(&scheduler, &req, &resp), 0);
    ASSERT_CONTAINS(resp.backend_call, "SDF_Encrypt");
    ASSERT_CONTAINS(resp.result, "classic-sym-enc");
    return 0;
}

static int test_pqc_kem_variant(void) {
    resource_registry_t registry;
    gateway_settings_t gw;
    scheduler_t scheduler;
    request_t req;
    response_t resp;
    char err[128];

    ASSERT_EQ_INT(load_registry(&registry), 0);
    ASSERT_EQ_INT(load_gateway(&gw), 0);
    scheduler_init(&scheduler, &registry, &gw);
    ASSERT_EQ_INT(parse_request_json("{\"request_id\":\"r4\",\"domain\":\"pqc\",\"action\":\"kem_encap\",\"algorithm\":\"ml-kem-768\",\"key_ref\":\"k2\",\"payload\":\"peer_pub\",\"user_pin\":\"123456\"}", &req, err, sizeof(err)), 0);
    ASSERT_EQ_INT(scheduler_execute(&scheduler, &req, &resp), 0);
    ASSERT_TRUE(strcmp(resp.selected_device, "pqc-1") == 0);
    ASSERT_CONTAINS(resp.backend_call, "SDF_Encap_Kyber");
    ASSERT_CONTAINS(resp.result, "pqc-kem-ct");
    return 0;
}

static int test_file_api(void) {
    resource_registry_t registry;
    gateway_settings_t gw;
    scheduler_t scheduler;
    request_t req;
    response_t resp;
    char err[128];

    ASSERT_EQ_INT(load_registry(&registry), 0);
    ASSERT_EQ_INT(load_gateway(&gw), 0);
    scheduler_init(&scheduler, &registry, &gw);
    ASSERT_EQ_INT(parse_request_json("{\"request_id\":\"r5\",\"domain\":\"file\",\"action\":\"read_file\",\"key_ref\":\"cfg.bin\",\"user_pin\":\"123456\",\"device_hint\":\"classic-1\"}", &req, err, sizeof(err)), 0);
    ASSERT_EQ_INT(scheduler_execute(&scheduler, &req, &resp), 0);
    ASSERT_CONTAINS(resp.backend_call, "SDF_ReadFile");
    ASSERT_CONTAINS(resp.result, "classic-read-file");
    return 0;
}

static int test_sequence_mixed(void) {
    resource_registry_t registry;
    gateway_settings_t gw;
    scheduler_t scheduler;
    request_t req;
    response_t resp;
    char err[128];

    ASSERT_EQ_INT(load_registry(&registry), 0);
    ASSERT_EQ_INT(load_gateway(&gw), 0);
    scheduler_init(&scheduler, &registry, &gw);
    ASSERT_EQ_INT(parse_request_json("{\"request_id\":\"r6\",\"domain\":\"asym\",\"action\":\"sign\",\"algorithm\":\"sm2\",\"key_ref\":\"k1\",\"payload\":\"hello\",\"user_pin\":\"123456\",\"sequence\":\"asym:sign:classic:sm2>pqc:sign:pqc:dilithium3\"}", &req, err, sizeof(err)), 0);
    ASSERT_EQ_INT(scheduler_execute(&scheduler, &req, &resp), 0);
    ASSERT_CONTAINS(resp.selected_device, "classic-1>pqc-1");
    ASSERT_CONTAINS(resp.backend_call, "SDF_InternalSign_ECC_Ex>SDF_Sign_Dilithium");
    return 0;
}

static int test_bad_pin(void) {
    resource_registry_t registry;
    gateway_settings_t gw;
    scheduler_t scheduler;
    request_t req;
    response_t resp;
    char err[128];

    ASSERT_EQ_INT(load_registry(&registry), 0);
    ASSERT_EQ_INT(load_gateway(&gw), 0);
    scheduler_init(&scheduler, &registry, &gw);
    ASSERT_EQ_INT(parse_request_json("{\"request_id\":\"r7\",\"domain\":\"asym\",\"action\":\"sign\",\"algorithm\":\"sm2\",\"key_ref\":\"k1\",\"payload\":\"hello\",\"user_pin\":\"000000\"}", &req, err, sizeof(err)), 0);
    ASSERT_TRUE(scheduler_execute(&scheduler, &req, &resp) != 0);
    ASSERT_EQ_INT(resp.status, STATUS_UNAUTHORIZED);
    return 0;
}

int main(void) {
    if (test_protocol_parse() != 0) return 1;
    if (test_gateway_pin_check() != 0) return 1;
    if (test_classic_asym_sign() != 0) return 1;
    if (test_classic_sym_encrypt() != 0) return 1;
    if (test_pqc_kem_variant() != 0) return 1;
    if (test_file_api() != 0) return 1;
    if (test_sequence_mixed() != 0) return 1;
    if (test_bad_pin() != 0) return 1;
    printf("all unit tests passed\n");
    return 0;
}
