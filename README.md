# crypto_gateway_c_v3

C11 + Unix Domain Socket 统一密码机网关原型。

## 本版重点

- 统一 API 改为 `domain + action + algorithm`
- 网关 PIN 与底层密码机 PIN 分离
- 不做透传 PIN
- 通过两个 adapter 表达两台设备：
  - `swsds-classic`
  - `swsds-pqc`
- adapter 接口保留 7 大类 handler；CCM 兼容层只做上层路由覆盖，不代表所有底层 SAF 语义已真实实现
- 支持串行混合调用 `sequence`
- `src/` 已按客户端层和服务端层重新分层，客户端进一步拆分为 API、封装、通信三层

## 目录

- `src/client/api/`：客户端接口层，提供命令行入口和对外 API 边界
- `src/client/core/`：客户端封装层，负责组织请求读取、调用通信层、输出响应
- `src/client/transport/`：客户端通信层，负责 Unix Domain Socket 收发
- `src/server/gateway/`：服务端网关层，包含入口、server、protocol、queue
- `src/server/service/`：服务端服务层，包含 config、resource、scheduler、translator
- `src/server/driver/`：服务端驱动层，包含 driver_dispatch、driver_classic、driver_pqc、skf_adapter
- `src/common/`：客户端和服务端共用代码，例如日志
- `include/`：头文件
- `configs/devices.conf`：设备与能力声明
- `configs/gateway.conf`：网关 PIN
- `overall_architecture_zh.md`：中文总体架构说明
- `tests/`：单元测试与 e2e

## 编译

```bash
make
make test
```

## 运行

```bash
./bin/crypto_gateway ./configs/devices.conf ./configs/gateway.conf /tmp/crypto_gateway.sock
```

## CCM 上层接口

新增 `include/ccm.h` / `src/client/api/ccm_api.c`，提供 `CCM_` 前缀的四类上层统一接口：环境类、密码运算类、密钥管理类、数字签名类。上层不再暴露证书类、消息类、USBKey 类或厂商设备类接口。

新接口统一使用三种结构表达“用什么算法、什么密钥、对什么数据操作”：`Unif_AlgParams` 表达算法、模式、填充、Hash 算法和安全级别；`Unif_KeyRef` 表达内部索引、会话句柄或外部密钥；`Unif_Buffer` 表达输入输出数据。RSA、SM2、SM4、SM3、Dilithium、Kyber/ML-KEM 等仍通过 `uiAlgID` 归一化到既有 JSON API 的 `algorithm` 字段。

分类边界固定为：密码运算类只包含 Hash、MAC、对称加解密、非对称加解密；密钥管理类包含密钥生成、导入导出、销毁查询、KEM、传统密钥协商和混合密钥协商；数字签名类包含普通签名/验签、摘要签名/验签和混合签名/验签。混合密钥协商不再放入“混合密码运算”单独分类，而归入密钥管理类。

当前实现层对接已有 JSON API；如果旧 JSON API 的对应 `domain/action/algorithm` 已经正确工作，CCM 层会把结构化 C 参数归一化后路由过去。

## 请求示例

### 1. 校验网关 PIN

```bash
printf '%s\n' '{"request_id":"auth-1","domain":"auth","action":"check_pin","user_pin":"123456"}' | ./bin/crypto_client /tmp/crypto_gateway.sock
```

### 2. 传统密码机非对称签名

```bash
printf '%s\n' '{"request_id":"r1","domain":"asym","action":"sign","algorithm":"sm2","key_ref":"k1","payload":"hello","user_pin":"123456"}' | ./bin/crypto_client /tmp/crypto_gateway.sock
```

### 3. 抗量子 KEM 变种

```bash
printf '%s\n' '{"request_id":"r2","domain":"pqc","action":"kem_encap","algorithm":"mlkem768","key_ref":"k2","payload":"peer_pub","user_pin":"123456"}' | ./bin/crypto_client /tmp/crypto_gateway.sock
```

### 4. 串行混合流程

```bash
printf '%s\n' '{"request_id":"r3","domain":"asym","action":"sign","algorithm":"sm2","key_ref":"k1","payload":"hello","user_pin":"123456","sequence":"asym:sign:classic:sm2>pqc:sign:pqc:dilithium3"}' | ./bin/crypto_client /tmp/crypto_gateway.sock
```

## 能力声明格式

`devices.conf` 中 capability 形如：

```text
domain:action:algorithm
```

例如：

- `asym:sign:sm2`
- `sym:encrypt:sm4-cbc`
- `pqc:kem_encap:mlkem768`

## 下一步

把 `src/server/driver/driver_classic.c` / `src/server/driver/driver_pqc.c` 中的 mock 行为替换为真实 SDK 调用。
