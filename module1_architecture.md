# module1_architecture

统一 API 采用 `domain + action + algorithm`。

- `domain`: auth/device/key/asym/sym/hash/file/pqc
- `action`: sign/verify/encrypt/decrypt/kem_encap/kem_decap etc.
- `algorithm`: sm2/sm4-cbc/dilithium3/mlkem768 etc.

Source layout:

- `src/client/api/`: client API layer
- `src/client/core/`: client wrapper layer
- `src/client/transport/`: client communication layer
- `src/server/gateway/`: server gateway layer
- `src/server/service/`: server service layer
- `src/server/driver/`: server driver layer
- `src/common/`: shared code

Adapters live under `src/server/driver/`.

## 托管式服务边界

UCiSDK 是托管式统一密码服务平台，不是把调用方 PIN 透传到底层设备的简单代理。上层调用方只使用 `CCM_*` 函数接口提交算法、动作、数据和统一密钥引用；网关负责认证、密钥归属解析、设备选择和 adapter 调用。网关 PIN 只用于网关侧认证，底层密码机、密码钥匙或软件库所需的登录状态由服务端 adapter 按设备配置和密钥归属处理。
