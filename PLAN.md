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

UCiSDK 定位为托管式统一密码服务平台。上层应用只能通过 `CCM_*` 函数接口提交算法、动作、数据和统一密钥引用；网关 PIN 只用于网关认证，不能当作底层密码机、密码钥匙或软件库 PIN 透传。内部密钥引用必须携带 `device_id` 或由托管 `key_id` 解析到具体设备，不能把裸 `key_index` 当作全局密钥标识。软件库等后端只声明自己支持的 key source 能力，例如外部密钥能力，不支持内部索引密钥时由调度层过滤，adapter 层仅作为最终兜底。
