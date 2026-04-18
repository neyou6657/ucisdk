# crypto_gateway_c_v3

C11 + Unix Domain Socket 统一密码机网关原型。

## 本版重点

- 统一 API 改为 `domain + action + algorithm`
- 网关 PIN 与底层密码机 PIN 分离
- 不做透传 PIN
- 通过两个 adapter 表达两台设备：
  - `swsds-classic`
  - `swsds-pqc`
- adapter 接口完整覆盖 7 大类函数族
- 支持串行混合调用 `sequence`

## 目录

- `src/`：源码
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

把 `driver_classic.c` / `driver_pqc.c` 中的 mock 行为替换为真实 SDK 调用。
