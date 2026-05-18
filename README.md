# ucisdk

C11 + Unix Domain Socket 统一密码服务网关原型。

本项目目标是在上层提供稳定、清晰的统一密码服务接口，在中间层继续保持 `domain + action + algorithm` 的统一请求模型，在后端适配多台密码机或不同类型密码设备。当前阶段重点关注统一接口、协议转换、调度和 adapter 分层，不把证书、消息封装、USBKey 或厂商专有能力暴露为最上层接口类别。

## 一、接口说明

### 1.1 上层 CCM 接口分类

`include/ccm.h` 暴露 `CCM_` 前缀的四类上层接口：

| 类别 | 职责 | 代表接口 |
|---|---|---|
| 环境类 | 初始化、释放、登录、登出、能力查询、随机数 | `CCM_Initialize`、`CCM_Finalize`、`CCM_Login`、`CCM_Logout`、`CCM_GetCapability`、`CCM_GenerateRandom` |
| 密码运算类 | Hash、MAC、对称加解密、非对称加解密 | `CCM_Hash`、`CCM_Mac`、`CCM_SymEncrypt`、`CCM_SymDecrypt`、`CCM_AsymEncrypt`、`CCM_AsymDecrypt` |
| 密钥管理类 | 密钥生成、导入导出、销毁查询、KEM、密钥协商、混合密钥协商 | `CCM_GenerateKeyPair`、`CCM_ImportKey`、`CCM_ExportPublicKey`、`CCM_KemEncapsulate`、`CCM_KeyAgreementInit`、`CCM_HybridKeyAgreement` |
| 数字签名类 | 普通签名/验签、摘要签名/验签、混合签名/验签 | `CCM_Sign`、`CCM_Verify`、`CCM_SignDigest`、`CCM_VerifyDigest`、`CCM_HybridSign`、`CCM_HybridVerify` |

分类边界如下：

- Hash、MAC、对称加解密、非对称加解密属于密码运算类。
- KEM、传统密钥协商、混合密钥协商属于密钥管理类。
- 普通签名、摘要签名、混合签名属于数字签名类。
- PQC、Hybrid、SM2、RSA、SM4、ML-KEM、ML-DSA 都不是顶层分类，它们通过算法 ID 和扩展参数表达。

### 1.2 统一参数结构

上层接口统一使用三种结构表达调用意图。

```c
typedef struct {
    unsigned int uiAlgID;
    unsigned int uiUsage;
    unsigned int uiSource;
    unsigned int uiKeyIndex;
    void *hKeyHandle;
    void *pExternalKey;
    char szKeyId[64];
    char szDeviceId[64];
} Unif_KeyRef;

typedef struct {
    unsigned char *pucData;
    unsigned int uiDataLen;
} Unif_Buffer;

typedef struct {
    unsigned int uiAlgID;
    unsigned int uiMode;
    unsigned int uiPadding;
    unsigned int uiHashAlgID;
    unsigned int uiSecurityLevel;
    void *pExParams;
} Unif_AlgParams;
```

含义对应关系：

| 结构 | 表达内容 |
|---|---|
| `Unif_AlgParams` | 用什么算法、什么模式、什么填充、什么 Hash、什么安全级别 |
| `Unif_KeyRef` | 用什么密钥，包括内部索引、会话句柄、外部密钥和用途 |
| `Unif_Buffer` | 对什么数据进行输入输出操作 |

### 1.3 中间统一请求模型

上层 `CCM_` 接口不会直接绑定某台设备或某个厂商 SDK。接口实现会把结构化 C 参数转换为网关中间请求：

```text
domain + action + algorithm
```

核心字段含义：

| 字段 | 含义 |
|---|---|
| `domain` | 能力域，例如 device、key、asym、sym、hash、pqc |
| `action` | 动作，例如 sign、verify、encrypt、decrypt、hash、kem_encap |
| `algorithm` | 算法变量，例如 sm2、rsa、sm4-cbc、sm3、mlkem768、dilithium3 |
| `key_ref` | 归一化后的密钥引用；可携带 `source/key_id/device_id/key_index/external_key` |
| `payload` | 主输入参数 |
| `aux_payload` | 输出、辅助参数或扩展参数 |
| `device_hint` / `preference` / `sequence` | 多设备调度和混合流程控制字段 |

### 1.4 Adapter 约束

后端 adapter 仍保留 7 大类 handler：

```text
device_manage
key_manage
asym_crypto
sym_crypto
hash_ops
file_ops
pqc_ops
```

这 7 类是后端适配层分类，不等同于最上层 CCM 接口分类。最上层接口面向业务语义，中间层负责归一化，adapter 层负责映射到具体密码机 SDK。

## 二、文件树说明

```text
ucisdk/
├── AGENTS.md                       # 项目开发约束和协作规则
├── Makefile                        # 构建、测试入口
├── README.md                       # 项目说明
├── PLAN.md                         # 阶段计划和任务状态
├── overall_architecture_zh.md      # 中文总体架构说明
├── module1_architecture.md         # 模块 1 架构说明
├── module2_protocol_translation.md # 模块 2 协议转换说明
├── module3_scheduler_drivers.md    # 模块 3 调度与驱动说明
├── module4_tests.md                # 模块 4 测试说明
├── configs/
│   ├── devices.conf                # 设备资源和能力声明
│   ├── gateway.conf                # 网关配置
│   └── gm3000-devices.conf         # GM3000 设备示例配置
├── docs/
│   └── adapter_guide.md            # 新 adapter 接入说明
├── include/
│   ├── ccm.h                       # 上层 CCM 统一接口
│   ├── common.h                    # 公共类型、domain/action 定义
│   ├── config.h                    # 配置加载接口
│   ├── driver.h                    # driver/adapter 抽象
│   ├── log.h                       # 日志接口
│   ├── protocol.h                  # JSON 协议解析和响应
│   ├── queue.h                     # 请求队列
│   ├── resource.h                  # 设备资源注册表
│   ├── scheduler.h                 # 调度器接口
│   ├── server.h                    # 网关服务接口
│   └── translator.h                # 协议到后端调用的转换接口
├── src/
│   ├── client/
│   │   ├── api/
│   │   │   ├── ccm_api.c           # CCM 上层接口到中间请求的归一化
│   │   │   └── client_api.c        # 命令行客户端入口
│   │   ├── core/
│   │   │   └── client_core.c       # 客户端请求封装和响应输出
│   │   └── transport/
│   │       └── client_transport.c  # Unix Domain Socket 客户端通信
│   ├── common/
│   │   └── log.c                   # 公共日志实现
│   └── server/
│       ├── gateway/
│       │   ├── main.c              # 网关进程入口
│       │   ├── protocol.c          # 协议解析、字段规范化
│       │   ├── queue.c             # 请求队列实现
│       │   └── server.c            # Socket 服务端主循环
│       ├── service/
│       │   ├── config.c            # 配置读取
│       │   ├── resource.c          # 设备资源和能力注册
│       │   ├── scheduler.c         # 设备选择、PIN 校验、sequence 执行
│       │   └── translator.c        # domain/action/algorithm 到后端调用映射
│       └── driver/
│           ├── driver_dispatch.c   # 根据 domain 分派到 adapter handler
│           ├── driver_classic.c    # 传统密码机 mock/适配层
│           ├── driver_pqc.c        # PQC 密码机 mock/适配层
│           └── skf_adapter.c       # SKF/GM3000 适配层
├── tests/
│   ├── test_runner.c               # 单元测试
│   ├── e2e.sh                      # 端到端测试
│   └── gm3000_smoke.sh             # GM3000 smoke 测试
└── vendor/
    ├── skfapi.h                    # SKF 供应商头文件
    └── swsds.h                     # SDF/SWSDS 供应商头文件
```

## 三、架构说明

### 3.1 分层结构

```text
应用 / 业务代码
    ↓
CCM 上层统一接口
    ↓
统一请求模型：domain + action + algorithm
    ↓
协议解析与参数归一化
    ↓
资源注册表与调度器
    ↓
translator 映射表
    ↓
adapter 分发层
    ↓
具体密码机 SDK / mock driver
```

各层职责：

| 层级 | 主要职责 |
|---|---|
| CCM 上层接口 | 提供环境、密码运算、密钥管理、数字签名四类业务语义接口 |
| 协议层 | 解析统一请求字段，规范化 domain/action/algorithm |
| 资源层 | 加载设备、能力、优先级、后端 profile |
| 调度层 | 根据能力、偏好、设备提示和 sequence 选择设备 |
| translator 层 | 把统一请求映射为具体后端调用名 |
| adapter 层 | 屏蔽 SDF、SKF、PQC SDK 等具体设备接口差异 |

### 3.2 多设备调度思路

设备能力在 `configs/devices.conf` 中声明，能力格式为：

```text
domain:action:algorithm
```

调度器基于以下信息选择设备：

- 请求的 `domain`
- 请求的 `action`
- 请求的 `algorithm`
- 设备 capability 声明
- `device_hint`
- `preference`
- `sequence`

混合流程不作为新的顶层接口分类，而通过 `sequence` 或密钥管理/数字签名类中的 Hybrid 接口表达。

### 3.3 PIN 处理边界

网关 PIN 与底层密码机 PIN 分离。网关只校验自己的访问 PIN，不把用户输入的网关 PIN 直接透传给底层密码机。底层设备鉴权由 adapter 或设备配置负责。

### 3.4 当前实现状态

当前代码是统一密码服务网关原型：

- `CCM_` 上层接口已经切换为四类结构化接口。
- 中间层保持 `domain + action + algorithm`。
- 后端 adapter 保留 7 大类 handler。
- 传统密码机、PQC 密码机和 SKF/GM3000 路径已有 mock 或适配骨架。
- 后续重点是把 mock driver 中的行为替换为真实 SDK 调用，并完善多密码机调度策略。

## 四、构建与验证

```bash
make
make test
```

## 托管式统一密码服务边界

UCiSDK 是托管式统一密码服务平台，不是把调用方 PIN 透传到底层设备的简单代理。上层调用方只使用 `CCM_*` 函数接口提交算法、动作、数据和统一密钥引用；网关负责认证、密钥归属解析、设备选择和 adapter 调用。网关 PIN 只用于网关侧认证，底层密码机、密码钥匙或软件库所需的登录状态由服务端 adapter 按设备配置和密钥归属处理。

`Unif_KeyRef` 同时支持外部密钥、会话句柄、设备内部索引和托管密钥标识。`uiSource=CCM_KEY_SOURCE_MANAGED_KEY` 时，调用方传入 `szKeyId`，服务端通过密钥注册表解析出真实 `device_id`、容器或内部索引；`uiSource=CCM_KEY_SOURCE_INTERNAL_INDEX` 时，必须通过 `szDeviceId` 或请求中的 `device_hint` 绑定具体设备，裸 `uiKeyIndex` 不能作为全局密钥标识。

调度器先执行网关 PIN 校验，再解析 `key_ref`。内部索引密钥请求必须能解析到具体设备；托管密钥请求由 `key_id` 映射到设备和密钥位置；外部密钥请求可以按能力表自由选择支持外部密钥的后端。设备能力支持三段式 `domain:action:algorithm` 和四段式 `domain:action:algorithm:key_source`，例如软件库可声明 `asym:sign:sm2:external_key`，从而在调度阶段拒绝内部索引密钥。adapter 的不支持返回只作为兜底。
