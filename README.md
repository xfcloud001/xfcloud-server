# XFCloud Tunnel 服务端（xfcloud-server）

基于 [frp](https://github.com/fatedier/frp) 内核的多用户内网穿透业务管理平台 —— 套餐开号、端口授权、实时流量统计、带宽限速、集群管理、品牌贴牌、在线更新一站式完成。部署在具有公网 IP 的服务器上，即可把内网穿透做成一门生意。

- 客户端仓库：[xfcloud-client](https://github.com/xfcloud001/xfcloud-client)
- 官网 / 教程 / 飞牛 fpk 下载：<https://www.xfhub.top>

## 功能特性

- **多用户与套餐**：定义套餐批量开号，有效期 / 流量 / 端口数灵活控制，支持续费提醒与计费
- **端口授权**：按用户与节点授权端口段，映射可视化编辑
- **实时监控**：在线用户与映射流量实时统计，流量数据跨重启永久保留
- **带宽限速**：按用户 / 隧道精细限速
- **集群与从节点**：多节点集群统一管理，统计口径以集群为单位，主节点切换后客户端自动跟随
- **防火墙管理**：防火墙规则统一下发
- **公告与信息中心**：向客户端下发公告；frps 报错自动聚合提醒
- **frp 生命周期管理**：frps/frpc 二进制按平台与架构在线预拉取并缓存，一键重启
- **品牌贴牌**：站点名称、Logo、版权声明、备案信息自定义（商业授权）
- **在线更新**：一键检测并在线升级，升级后自动重启
- **安全**：管理台滑动验证码、会话 HMAC 签名、零第三方依赖（仅 Node.js 内置模块）

## 环境要求

- Linux / Windows / macOS
- Node.js **22.5+**（依赖内置 `node:sqlite`，无需 `npm install`）

## 快速开始

```bash
git clone https://github.com/xfcloud001/xfcloud-server.git
cd xfcloud-server
npm start            # 等价于 node --experimental-sqlite server/app.js
```

1. 浏览器访问 `http://127.0.0.1:8080`，使用管理员账号登录
2. 默认账号 `admin`，初始密码由环境变量 `ADMIN_PASSWORD` 设置（默认 `change-me-now`），**首次登录后请立即修改密码**
3. 在控制台「FRP 管理」在线拉取 frps（按平台 / 架构自动缓存），即可创建用户与隧道
4. 用户侧使用 [xfcloud-client](https://github.com/xfcloud001/xfcloud-client) 或飞牛 fnOS 原生 fpk 应用连接

### 常用环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `MANAGER_PORT` | `8080` | 管理控制台端口（首次配置后写入 `data/server-config.json`） |
| `MANAGER_HOST` | `0.0.0.0` | 监听地址 |
| `ADMIN_USER` / `ADMIN_PASSWORD` | `admin` / `change-me-now` | 初始管理员账号 |
| `DATA_DIR` | `./data/server` | 数据目录（SQLite 落盘） |
| `SERVER_RUNTIME_DIR` | `./runtime/server` | 运行时目录 |
| `SERVER_ROLE` | `master` | `master` / `slave`（集群从节点） |
| `LICENSE_SERVER_URL` | `https://key.xfhub.top` | 授权中心地址（商业许可校验与更新分发） |
| `FRPS_AUTOSTART` | `true` | 是否随服务自动启动 frps |
| `FRP_PUBLIC_HOST` | 空 | 隧道对外公网地址提示 |
| `FORCE_RESET_ADMIN_PASSWORD` | 空 | 设为 `1` 时启动即重置管理密码为初始值 |

### Linux 后台运行与集群部署

仓库自带 [server/service.sh](server/service.sh)：`start / stop / restart / status / logs` 一键管理，自动接管在线更新后的脱离进程；从节点（slave）推荐用 systemd（`xfcloud-slave.service`）托管，主节点切换客户端自动跟随新主。

## 免费额度与商业授权

默认**免费模式**即可完整运行（含额度限制）。品牌贴牌、解除免费额度、集群授权、优惠推送等商业能力需要 XFCloud 授权中心签发的许可密钥激活，见官网：<https://www.xfhub.top>。

## 谁在用 / 适用场景

- 想自建穿透服务卖给用户的**独立运营者**：开号、计费、限速、贴牌全套就绪
- **团队 / 个人**自用：把家里 NAS、公司内网服务安全地暴露到公网
- **飞牛 fnOS 用户**：服务端与客户端均有原生 fpk 应用，应用中心一键安装

## License

本项目基于 [AGPL-3.0](./LICENSE) 协议开源。frp 内核版权归其原作者所有。
