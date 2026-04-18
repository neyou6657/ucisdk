# Adapter 编写说明

## 结论

可以。

- **USB Key**：可以通过编写 `adapter` 接入。
- **密码机**：可以通过编写 `adapter` 接入。

前提是它们都满足以下条件之一：

1. 提供本机可加载的动态库，例如 `.so` / `.dll`
2. 提供头文件或函数签名说明
3. 可以在本机进程内直接调用

不能直接套同一个 adapter 的原因不是“设备形态不同”，而是：

- 动态库名不同
- 初始化流程不同
- 句柄类型不同
- PIN 校验接口不同
- 密钥定位方式不同
- 各类密码函数的参数格式不同

所以原则很简单：

**一个后端设备类型，对应一个 adapter。**

---

## 统一接口目标

adapter 的职责只有一件事：

**把统一密码接口，映射成厂商自己的驱动函数调用。**

统一层只认 7 大类能力：

1. 设备管理
2. 密钥管理
3. 非对称密码运算
4. 对称密码运算
5. 杂凑运算
6. 用户文件操作
7. 抗量子算法运算

USB Key 和密码机都按这 7 类去适配。

传统设备没有第 7 类时，可以返回“不支持”。

---

## adapter 必须实现的接口

建议每个 adapter 至少实现下面这组统一函数。

```c
#ifndef HSM_ADAPTER_H
#define HSM_ADAPTER_H

#include <stddef.h>
#include <stdint.h>

typedef struct hsm_adapter hsm_adapter_t;
typedef struct hsm_session hsm_session_t;

typedef enum {
    HSM_OK = 0,
    HSM_ERR = -1,
    HSM_ERR_NOT_SUPPORT = -2,
    HSM_ERR_BAD_PARAM = -3,
    HSM_ERR_AUTH = -4
} hsm_status_t;

typedef struct {
    const char *lib_path;
    const char *device_name;
    const char *app_name;
    const char *container_name;
    const char *reserved;
} hsm_adapter_config_t;

typedef struct {
    const char *key_id;
    const uint8_t *in;
    size_t in_len;
    uint8_t *out;
    size_t *out_len;
    const char *algorithm;
    const char *extra;
} hsm_blob_op_t;

struct hsm_adapter {
    hsm_status_t (*init)(hsm_adapter_t *self, const hsm_adapter_config_t *cfg);
    void (*cleanup)(hsm_adapter_t *self);

    hsm_status_t (*verify_user_pin)(hsm_adapter_t *self, const char *pin);

    hsm_status_t (*device_manage)(hsm_adapter_t *self, const char *action, void *arg);
    hsm_status_t (*key_manage)(hsm_adapter_t *self, const char *action, void *arg);
    hsm_status_t (*asym_crypto)(hsm_adapter_t *self, const char *action, hsm_blob_op_t *op);
    hsm_status_t (*sym_crypto)(hsm_adapter_t *self, const char *action, hsm_blob_op_t *op);
    hsm_status_t (*hash_ops)(hsm_adapter_t *self, const char *action, hsm_blob_op_t *op);
    hsm_status_t (*file_ops)(hsm_adapter_t *self, const char *action, void *arg);
    hsm_status_t (*pqc_ops)(hsm_adapter_t *self, const char *action, hsm_blob_op_t *op);

    void *priv;
};

#endif
```

---

## 统一动作建议

### 1. 设备管理

`device_manage(action, arg)` 建议支持：

- `open_device`
- `close_device`
- `get_device_info`
- `lock_device`
- `unlock_device`

### 2. 密钥管理

`key_manage(action, arg)` 建议支持：

- `open_application`
- `close_application`
- `open_container`
- `close_container`
- `export_public_key`
- `import_key`
- `generate_keypair`

### 3. 非对称密码运算

`asym_crypto(action, op)` 建议支持：

- `sign`
- `verify`
- `encrypt`
- `decrypt`

### 4. 对称密码运算

`sym_crypto(action, op)` 建议支持：

- `encrypt`
- `decrypt`
- `mac`

### 5. 杂凑运算

`hash_ops(action, op)` 建议支持：

- `init`
- `update`
- `final`
- `digest`

### 6. 文件操作

`file_ops(action, arg)` 建议支持：

- `create_file`
- `read_file`
- `write_file`
- `delete_file`
- `get_file_info`

### 7. 抗量子算法运算

`pqc_ops(action, op)` 建议支持：

- `sign`
- `verify`
- `kem_encap`
- `kem_decap`
- `generate_keypair`

---

## USB Key adapter 和密码机 adapter 的区别

只体现在 `priv` 和底层驱动调用细节上。

### USB Key

通常会涉及：

- `EnumDev`
- `ConnectDev`
- `OpenApplication`
- `VerifyPIN`
- `OpenContainer`
- `ECCSignData / RSASignData / SKF_Sign_Dilithium`

### 密码机

通常会涉及：

- `OpenDevice`
- `OpenSession`
- `GetPrivateKeyAccessRight`
- `InternalSign / InternalDecrypt / Encrypt / Hash`
- `SDF_Sign_Dilithium / SDF_Encap_Kyber`

所以：

- **统一层相同**
- **adapter 内部不同**

---

## 编写 adapter 的最小步骤

## 第 1 步：定义私有上下文

```c
typedef struct {
    void *lib;
    void *dev_handle;
    void *app_handle;
    void *container_handle;

    unsigned long (*pEnumDev)(int, char *, unsigned long *);
    unsigned long (*pConnectDev)(char *, void **);
    unsigned long (*pVerifyPIN)(void *, unsigned long, char *, unsigned long *);
    unsigned long (*pOpenApplication)(void *, char *, void **);
    unsigned long (*pOpenContainer)(void *, char *, void **);
    unsigned long (*pCloseContainer)(void *);
    unsigned long (*pCloseApplication)(void *);
    unsigned long (*pDisConnectDev)(void *);
} my_usbkey_ctx_t;
```

密码机版本把函数指针替换成对应 `SDF_*` 即可。

---

## 第 2 步：在 `init()` 中加载动态库并绑定函数

```c
#include <dlfcn.h>

static void *load_sym(void *lib, const char *name)
{
    void *p = dlsym(lib, name);
    return p;
}

static hsm_status_t my_init(hsm_adapter_t *self, const hsm_adapter_config_t *cfg)
{
    my_usbkey_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return HSM_ERR;

    ctx->lib = dlopen(cfg->lib_path, RTLD_NOW | RTLD_LOCAL);
    if (!ctx->lib) {
        free(ctx);
        return HSM_ERR;
    }

    ctx->pEnumDev = load_sym(ctx->lib, "SKF_EnumDev");
    ctx->pConnectDev = load_sym(ctx->lib, "SKF_ConnectDev");
    ctx->pVerifyPIN = load_sym(ctx->lib, "SKF_VerifyPIN");
    ctx->pOpenApplication = load_sym(ctx->lib, "SKF_OpenApplication");
    ctx->pOpenContainer = load_sym(ctx->lib, "SKF_OpenContainer");
    ctx->pCloseContainer = load_sym(ctx->lib, "SKF_CloseContainer");
    ctx->pCloseApplication = load_sym(ctx->lib, "SKF_CloseApplication");
    ctx->pDisConnectDev = load_sym(ctx->lib, "SKF_DisConnectDev");

    if (!ctx->pConnectDev || !ctx->pVerifyPIN) {
        dlclose(ctx->lib);
        free(ctx);
        return HSM_ERR;
    }

    self->priv = ctx;
    return HSM_OK;
}
```

---

## 第 3 步：实现 `verify_user_pin()`

```c
static hsm_status_t my_verify_user_pin(hsm_adapter_t *self, const char *pin)
{
    my_usbkey_ctx_t *ctx = (my_usbkey_ctx_t *)self->priv;
    unsigned long retry = 0;
    unsigned long rv;

    if (!ctx || !pin) return HSM_ERR_BAD_PARAM;
    if (!ctx->app_handle) return HSM_ERR;

    rv = ctx->pVerifyPIN(ctx->app_handle, 1, (char *)pin, &retry);
    return (rv == 0) ? HSM_OK : HSM_ERR_AUTH;
}
```

如果是密码机版本，可以把这里换成你自己的用户认证流程；如果密码机没有“用户 PIN 验证”语义，也可以让这里接网关自己的 PIN 校验逻辑。

---

## 第 4 步：把 7 大类函数映射进去

### 非对称

```c
static hsm_status_t my_asym_crypto(hsm_adapter_t *self, const char *action, hsm_blob_op_t *op)
{
    if (!strcmp(action, "sign")) {
        return HSM_OK;
    }
    if (!strcmp(action, "verify")) {
        return HSM_OK;
    }
    if (!strcmp(action, "encrypt")) {
        return HSM_OK;
    }
    if (!strcmp(action, "decrypt")) {
        return HSM_OK;
    }
    return HSM_ERR_NOT_SUPPORT;
}
```

### 对称

```c
static hsm_status_t my_sym_crypto(hsm_adapter_t *self, const char *action, hsm_blob_op_t *op)
{
    if (!strcmp(action, "encrypt")) return HSM_OK;
    if (!strcmp(action, "decrypt")) return HSM_OK;
    if (!strcmp(action, "mac")) return HSM_OK;
    return HSM_ERR_NOT_SUPPORT;
}
```

### 哈希

```c
static hsm_status_t my_hash_ops(hsm_adapter_t *self, const char *action, hsm_blob_op_t *op)
{
    if (!strcmp(action, "digest")) return HSM_OK;
    if (!strcmp(action, "init")) return HSM_OK;
    if (!strcmp(action, "update")) return HSM_OK;
    if (!strcmp(action, "final")) return HSM_OK;
    return HSM_ERR_NOT_SUPPORT;
}
```

### 文件

```c
static hsm_status_t my_file_ops(hsm_adapter_t *self, const char *action, void *arg)
{
    if (!strcmp(action, "create_file")) return HSM_OK;
    if (!strcmp(action, "read_file")) return HSM_OK;
    if (!strcmp(action, "write_file")) return HSM_OK;
    if (!strcmp(action, "delete_file")) return HSM_OK;
    if (!strcmp(action, "get_file_info")) return HSM_OK;
    return HSM_ERR_NOT_SUPPORT;
}
```

### 抗量子

```c
static hsm_status_t my_pqc_ops(hsm_adapter_t *self, const char *action, hsm_blob_op_t *op)
{
    if (!strcmp(action, "sign")) return HSM_OK;
    if (!strcmp(action, "verify")) return HSM_OK;
    if (!strcmp(action, "kem_encap")) return HSM_OK;
    if (!strcmp(action, "kem_decap")) return HSM_OK;
    if (!strcmp(action, "generate_keypair")) return HSM_OK;
    return HSM_ERR_NOT_SUPPORT;
}
```

---

## 第 5 步：导出工厂函数

```c
hsm_status_t create_adapter(hsm_adapter_t *ad)
{
    if (!ad) return HSM_ERR_BAD_PARAM;
    memset(ad, 0, sizeof(*ad));

    ad->init = my_init;
    ad->cleanup = my_cleanup;
    ad->verify_user_pin = my_verify_user_pin;
    ad->device_manage = my_device_manage;
    ad->key_manage = my_key_manage;
    ad->asym_crypto = my_asym_crypto;
    ad->sym_crypto = my_sym_crypto;
    ad->hash_ops = my_hash_ops;
    ad->file_ops = my_file_ops;
    ad->pqc_ops = my_pqc_ops;
    return HSM_OK;
}
```

---

## 哪些可以复用，哪些必须重写

## 可复用

这些通常可以在所有 adapter 里共用：

- 统一接口头文件
- 错误码映射框架
- 输入输出缓冲区处理
- 日志
- 能力声明
- 调度逻辑
- 网关鉴权逻辑

## 必须重写

这些通常每个设备都不同：

- `dlopen/dlsym` 绑定的函数集合
- 私有上下文 `priv`
- PIN 校验实现
- 句柄打开/关闭流程
- 每个 action 对应的底层函数
- 输入输出结构体转换
- 厂商错误码转统一错误码

---

## 接入新设备时最少需要做什么

新增一个设备，最少做这 4 件事：

1. 新建一个 `adapter_xxx.c`
2. 绑定它自己的动态库函数
3. 实现 7 大类统一入口
4. 在配置里声明它支持哪些能力

例如：

```text
adapters/
  adapter_sdf_hsm.c
  adapter_skf_usbkey.c
  adapter_custom_pqc.c
```

---

## 建议的能力声明格式

```ini
[device_1]
id = hsm01
type = sdf
adapter = adapter_sdf_hsm
lib = /opt/lib/libswsds.so
capabilities = \
  device:open_device,\
  key:generate_keypair,\
  asym:sign:sm2,\
  asym:verify:sm2,\
  sym:encrypt:sms4-cbc,\
  sym:decrypt:sms4-cbc,\
  hash:digest:sm3,\
  pqc:sign:dilithium3,\
  pqc:verify:dilithium3,\
  pqc:kem_encap:kyber768,\
  pqc:kem_decap:kyber768
```

```ini
[device_2]
id = usbkey01
type = skf
adapter = adapter_skf_usbkey
lib = /opt/lib/libskf.so
capabilities = \
  device:open_device,\
  asym:sign:sm2,\
  asym:verify:sm2,\
  hash:digest:sm3,\
  pqc:sign:dilithium3,\
  pqc:verify:dilithium3
```

---

## 编写 adapter 的最低验收标准

adapter 只有满足下面这些，才算接入完成。

### 必测 1：动态库能加载

- `dlopen` 成功
- 所需 `dlsym` 全部成功

### 必测 2：PIN 校验能通

- 正确 PIN 返回成功
- 错误 PIN 返回统一认证失败

### 必测 3：7 大类入口可调用

即使某类暂不支持，也必须：

- 有函数
- 明确返回 `HSM_ERR_NOT_SUPPORT`

不能缺函数。

### 必测 4：支持的能力必须能跑通一条真实链路

例如至少跑通一条：

- `sign -> verify`
- `kem_encap -> kem_decap`
- `encrypt -> decrypt`
- `digest`

### 必测 5：资源清理正确

- 关闭句柄
- 关闭容器
- 关闭应用
- 断开设备
- `dlclose`

---

## 什么时候不用新写 adapter

只有在下面条件同时满足时，才可以不新写 adapter，而是复用已有 adapter：

1. 动态库函数名相同
2. 调用顺序相同
3. 句柄模型相同
4. 参数结构相同
5. 错误码语义相同

只要其中有一个明显不同，就应该新建 adapter。

---

## 最后一句

**USB Key 和密码机都能接入，但接入方式不是“共用一个驱动”，而是“共用统一接口，各自写 adapter”。**

真正稳定的做法是：

- 上层统一 7 大类能力接口
- 下层每个设备一个 adapter
- 能力通过配置声明
- 差异全部收敛到 adapter 内部
