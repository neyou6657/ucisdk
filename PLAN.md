# PLAN.md

## 当前阶段

- [x] 统一 API 改成 `domain + action + algorithm`
- [x] 网关 PIN 校验与设备 PIN 解耦
- [x] 两个 adapter 完整覆盖 7 大类接口骨架
- [x] 设备能力改成 `domain:action:algorithm` 声明
- [x] 编译通过
- [x] 单元测试通过
- [x] e2e 通过

## 下一阶段

- [ ] 将 classic adapter 接入真实 `libswsds.so`
- [ ] 将 pqc adapter 接入真实 `libswsds.so`
- [ ] 加入真实错误码映射
- [ ] 加入真实会话与设备生命周期管理

- [x] 增加 CCM_ 四类上层统一接口：环境类、密码运算类、密钥管理类、数字签名类；统一使用 Unif_AlgParams / Unif_KeyRef / Unif_Buffer 表达算法、密钥和数据

- [x] 上层接口不再暴露证书类、消息类、USBKey 类或厂商设备类，后端仍保持 domain + action + algorithm 路由

## 托管式统一密码服务边界

UCiSDK 是托管式统一密码服务平台，不是把调用方 PIN 透传到底层设备的简单代理。上层调用方只使用 `CCM_*` 函数接口提交算法、动作、数据和统一密钥引用；网关负责认证、密钥归属解析、设备选择和 adapter 调用。网关 PIN 只用于网关侧认证，底层密码机、密码钥匙或软件库所需的登录状态由服务端 adapter 按设备配置和密钥归属处理。

`Unif_KeyRef` 同时支持外部密钥、会话句柄、设备内部索引和托管密钥标识。`uiSource=CCM_KEY_SOURCE_MANAGED_KEY` 时，调用方传入 `szKeyId`，服务端通过密钥注册表解析出真实 `device_id`、容器或内部索引；`uiSource=CCM_KEY_SOURCE_INTERNAL_INDEX` 时，必须通过 `szDeviceId` 或请求中的 `device_hint` 绑定具体设备，裸 `uiKeyIndex` 不能作为全局密钥标识。

调度器先执行网关 PIN 校验，再解析 `key_ref`。内部索引密钥请求必须能解析到具体设备；托管密钥请求由 `key_id` 映射到设备和密钥位置；外部密钥请求可以按能力表自由选择支持外部密钥的后端。设备能力支持三段式 `domain:action:algorithm` 和四段式 `domain:action:algorithm:key_source`，例如软件库可声明 `asym:sign:sm2:external_key`，从而在调度阶段拒绝内部索引密钥。adapter 的不支持返回只作为兜底。
