#include "config.h"
#include "ccm.h"
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

static int test_ccm_api_builds_unified_requests_with_algorithm_id(void) {
    char name[64];
    unsigned char out[1024];
    unsigned int out_len = sizeof(out);
    unsigned char data[] = "hello";
    unsigned char sig[256];
    unsigned int sig_len = sizeof(sig);
    unsigned char iv[16] = {0};
    unsigned char cipher[256];
    unsigned int cipher_len = sizeof(cipher);
    unsigned char plain[256];
    unsigned int plain_len = sizeof(plain);

    ASSERT_EQ_INT(CCM_AlgorithmName(CCM_ALG_SM2, name, sizeof(name)), 0);
    ASSERT_TRUE(strcmp(name, "sm2") == 0);
    ASSERT_EQ_INT(CCM_AlgorithmName(CCM_ALG_SM4_CBC, name, sizeof(name)), 0);
    ASSERT_TRUE(strcmp(name, "sm4-cbc") == 0);
    ASSERT_EQ_INT(CCM_AlgorithmName(CCM_ALG_MLKEM768, name, sizeof(name)), 0);
    ASSERT_TRUE(strcmp(name, "mlkem768") == 0);
    ASSERT_EQ_INT(CCM_AlgorithmName(CCM_ALG_DILITHIUM3, name, sizeof(name)), 0);
    ASSERT_TRUE(strcmp(name, "dilithium3") == 0);

    ASSERT_EQ_INT(CCM_GenerateKeyPair(NULL, CCM_ALG_DILITHIUM3, 3U, 7U, out, sig), 0);
    ASSERT_EQ_INT(CCM_Sign(NULL, CCM_ALG_RSA_SIGN, 1U, NULL, CCM_ALG_RSA_SIGN, data, 5U, sig, &sig_len, NULL), 0);
    ASSERT_EQ_INT(CCM_Verify(NULL, CCM_ALG_DILITHIUM3, 2U, NULL, 0U, data, 5U, sig, sig_len, NULL), 0);
    ASSERT_EQ_INT(CCM_SymEncrypt(NULL, CCM_ALG_SM4_CBC, 1U, NULL, iv, data, 5U, cipher, &cipher_len), 0);
    ASSERT_EQ_INT(CCM_SymDecrypt(NULL, CCM_ALG_SM4_CBC, 1U, NULL, iv, cipher, cipher_len, plain, &plain_len), 0);
    ASSERT_EQ_INT(CCM_AsymEncrypt(NULL, CCM_ALG_SM2_ENC, 1U, NULL, data, 5U, cipher, &cipher_len), 0);
    ASSERT_EQ_INT(CCM_AsymDecrypt(NULL, CCM_ALG_SM2_ENC, 1U, NULL, cipher, cipher_len, plain, &plain_len), 0);
    ASSERT_EQ_INT(CCM_KeyEncapsulate(NULL, CCM_ALG_MLKEM768, 3U, NULL, 3U, cipher, &cipher_len, out, &out_len), 0);
    ASSERT_EQ_INT(CCM_KeyDecapsulate(NULL, CCM_ALG_MLKEM768, 3U, NULL, 3U, cipher, cipher_len, out, &out_len), 0);
    ASSERT_EQ_INT(CCM_HashInit(NULL, CCM_ALG_SM3, NULL), 0);
    ASSERT_EQ_INT(CCM_HashUpdate(NULL, data, 5U), 0);
    ASSERT_EQ_INT(CCM_HashFinal(NULL, out, &out_len), 0);
    ASSERT_EQ_INT(CCM_Mac(NULL, CCM_ALG_SM4_MAC, 1U, NULL, iv, data, 5U, out, &out_len), 0);
    return 0;
}

static int test_ccm_four_function_families_have_full_unified_entrypoints(void) {
    unsigned char buf[2048];
    unsigned int len = sizeof(buf);
    unsigned char data[] = "abc";
    unsigned char iv[16] = {0};
    unsigned int state = 0U;
    void *ctx = NULL;
    void *handle = NULL;
    CCM_HybridExParams hybrid;
    CCM_DilithiumSignParams dil_sign;

    memset(&hybrid, 0, sizeof(hybrid));
    hybrid.uiSecondaryAlgID = CCM_ALG_DILITHIUM3;
    hybrid.uiSecondaryKeyIndex = 9U;
    memset(&dil_sign, 0, sizeof(dil_sign));
    dil_sign.uiHashAlgID = CCM_ALG_SM3;
    dil_sign.uiExpectHashDataLen = 32U;
    dil_sign.uiRandomizeSigning = 1U;

    ASSERT_EQ_INT(CCM_Initialize(&ctx), 0);
    ASSERT_EQ_INT(CCM_GetVersion((char *)buf, &len), 0);
    ASSERT_EQ_INT(CCM_Login(ctx, "user", "123456"), 0);
    ASSERT_EQ_INT(CCM_ChangePin(ctx, "123456", "654321"), 0);
    ASSERT_EQ_INT(CCM_Logout(ctx), 0);
    ASSERT_EQ_INT(CCM_Finalize(ctx), 0);

    len = sizeof(buf);
    ASSERT_EQ_INT(CCM_AddCertificate(ctx, 1U, data, 3U), 0);
    ASSERT_EQ_INT(CCM_GetCertificateCount(ctx, 1U, &state), 0);
    ASSERT_EQ_INT(CCM_GetCertificate(ctx, 1U, 0U, buf, &len), 0);
    ASSERT_EQ_INT(CCM_RemoveCertificate(ctx, 1U, 0U), 0);
    ASSERT_EQ_INT(CCM_AddCrl(ctx, data, 3U), 0);
    ASSERT_EQ_INT(CCM_VerifyCertificate(ctx, CCM_ALG_SM2, data, 3U, data, 3U, NULL), 0);
    ASSERT_EQ_INT(CCM_GetCertificateState(ctx, 1U, data, 3U, &state, NULL), 0);
    ASSERT_EQ_INT(CCM_FetchCertificate(ctx, "ldap://cert", buf, &len), 0);
    ASSERT_EQ_INT(CCM_FetchCrl(ctx, "ldap://crl", buf, &len), 0);
    ASSERT_EQ_INT(CCM_GetCertificateInfo(ctx, 1U, data, 3U, buf, &len), 0);
    ASSERT_EQ_INT(CCM_EnumCertificates(ctx, 1U, buf, &len), 0);
    ASSERT_EQ_INT(CCM_EnumKeyContainers(ctx, buf, &len), 0);

    len = sizeof(buf);
    ASSERT_EQ_INT(CCM_Base64Encode(data, 3U, buf, &len), 0);
    len = sizeof(buf);
    ASSERT_EQ_INT(CCM_Base64Decode(data, 3U, buf, &len), 0);
    ASSERT_EQ_INT(CCM_GenerateRandom(ctx, sizeof(buf), buf), 0);
    ASSERT_EQ_INT(CCM_GenerateAgreementData(ctx, 1U, 128U, data, 3U, buf, buf, &handle), 0);
    ASSERT_EQ_INT(CCM_GenerateKeyAgreement(ctx, 1U, 128U, data, 3U, buf, buf, handle, buf, buf, &handle), 0);
    ASSERT_EQ_INT(CCM_HybridSign(ctx, CCM_ALG_SM2_SIGN, 1U, &hybrid, data, 3U, buf, &len), 0);
    ASSERT_EQ_INT(CCM_HybridVerify(ctx, CCM_ALG_SM2_SIGN, 1U, NULL, &hybrid, data, 3U, buf, len), 0);
    ASSERT_EQ_INT(CCM_HybridAgreement(ctx, CCM_ALG_SM2, CCM_ALG_MLKEM768, 1U, 2U, buf, buf, buf, &handle), 0);
    ASSERT_EQ_INT(CCM_Sign(ctx, CCM_ALG_DILITHIUM3, 1U, NULL, 0U, data, 3U, buf, &len, &dil_sign), 0);

    len = sizeof(buf);
    ASSERT_EQ_INT(CCM_MessageEncode(1U, ctx, CCM_ALG_SM2, 1U, NULL, data, 3U, buf, &len, NULL), 0);
    ASSERT_EQ_INT(CCM_MessageDecode(1U, ctx, CCM_ALG_SM2, 1U, NULL, buf, len, data, &len, NULL), 0);
    ASSERT_EQ_INT(CCM_MessageParseSignedData(ctx, buf, len, buf, &len), 0);
    (void)iv;
    return 0;
}

int main(void) {
    if (test_ccm_api_builds_unified_requests_with_algorithm_id() != 0) return 1;
    if (test_ccm_four_function_families_have_full_unified_entrypoints() != 0) return 1;
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
