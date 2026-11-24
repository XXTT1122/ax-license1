# AX Pro Max 1.6.1 — 卡密体系接管（路线 A：授权门 dylib）

原包的"卡密随便输入都能进"是因为注入模块 `AXZQURLProtocol` 把请求拦下来、回了预置签名的成功响应。
本方案**不动被绕过的那套逻辑**，而是在 App 外面加一道你自己的门：启动即拦截界面，
卡密没过不准用；验证走你的服务器 + 内置公钥验签。

> 可选加固（路线 B）：另外把原包的假服务器也关掉、公钥/域名换成你的，见文末。

---

## 一、逆向结论（实测，供你判断风险）

| 项目 | 结果 |
|---|---|
| 包结构 | `Payload/Tips.app`，6 个文件，**无 `_CodeSignature`/`embedded.mobileprovision`** → 重打包/TrollStore 免签形态 |
| Bundle | `com.apple.music`，显示名 `AX Pro Max`，`1.6.1`，MinOS 16.5.1 |
| 主二进制 | `Tips`，34,543,248 B，**arm64e**，`cryptid=0`（未加密） |
| 段 | 标准 4 段 + `__AXOLD/__AXTEXT/__AXCONST/__AXDATA/__AXPAD`(16.5 MB 空洞) |
| 符号 | `nsyms=0` 全剥离；导入 661 项（chained fixups fmt=3） |
| 混淆 | 主包控制流平坦化（`braa x8,x17`）+ MBA 膨胀；AX 模块未混淆但带 `__axseal` IMP 自校验 |
| 绕过点 | `+[AXZQURLProtocol canInitWithRequest:]` @ VA `0x101116a78` / file `0x1096a78` |
| 真实校验 | `KVREQ-V3 → KVRESP-V1`，主包 `SecKeyVerifySignature` + `kSecKeyAlgorithmRSASignatureMessagePSSSHA256` |
| 内置公钥 | file `0x10b09ca`，360 字符 Base64（2048-bit RSAPublicKey DER=270 B） |

**为什么路线 A 最稳**：不碰混淆代码、不碰 `__axseal`，只挂一条启动通知 + 建一个 `UIWindow`。

---

## 二、整体结构

```
你的服务器 (server.py + SQLite + RSA 私钥)
        ▲  HTTPS /api/v1/app/verify
        │
gate.dylib（注入到 Tips.app）
  ├─ App 启动 → 盖最高层级窗口，未授权不许操作
  ├─ 输入卡密 → 提交 → 用内置公钥对 payload_raw 验签
  ├─ 通过 → 写本地缓存 → 退场
  └─ 缓存有效 + 设备一致 + 无时间回拨 → 离线放行
```

代码：`tweak/gate.m`（纯 ObjC，**不依赖 CydiaSubstrate/ElleKit**，TrollStore 侧载可用）

---

## 三五步出包

> 还没有域名/服务器？先看 [docs/域名与服务器.md](docs/域名与服务器.md)：
> 里面有一条 **0 元 0 域名的当天验证路径**（本机当服务器 + `--ats-allow-http`），
> 以及买域名、上 TLS、Cloudflare Tunnel 的完整命令。

### 1. 生成密钥（只做一次）

```bash
cd axlicense
python -m pip install cryptography
python server/crypto.py
```

产物：`server/keys/private.pem`（**立刻备份，丢了旧卡全废**）、`server/keys/public_b64.txt`

### 2. 生成构建配置

```bash
python patch/configure.py --server https://lic.你的域名.com \
    --pubkey-from server/keys/public_b64.txt
```

自动校验：地址格式、公钥必须 360 字符 / DER 270 字节（2048-bit），不满足直接报错。
生成 `tweak/axp_config.h`（已 gitignore，CI 会重新生成）。

> 不生成也能编过，但运行时会打印「公钥未配置」并**拒绝放行**（失败即关闭，不会白送）。

### 3. 起服务端

```bash
# 测试
python server/server.py --host 0.0.0.0 --port 8443

# 生产（强烈建议 HTTPS）
python server/server.py --host 0.0.0.0 --port 443 \
    --tls-cert /etc/letsencrypt/live/你的域名/fullchain.pem \
    --tls-key  /etc/letsencrypt/live/你的域名/privkey.pem
```

自检：`curl https://你的域名/health` → `{"ok":true,...}`

### 4. 编译 + 注入（CI，无需 Mac）

私有仓库放入：

```
in/input.ipa                        # 待注入的包
server/keys/public_b64.txt          # 公钥（可提交，非机密）
tweak/ patch/ .github/              # 本目录
```

Actions → `build-gate-ipa` → Run workflow，`server_url` 填你的地址 → 下载 `AXProMax-gate.ipa`。

CI 干的事：生成 `axp_config.h` → Theos 编 `gate.dylib` → 断言公钥确实进二进制 →
`inject.py` 追加 `LC_LOAD_DYLIB` → `ldid -S` 重签 → `otool -L` 复验 `gate.dylib` 在列 → 上传。

### 5. 安装

- **TrollStore**：直接把 `AXProMax-gate.ipa` 拖进去安装
- **Windows 侧签**：`inject.py` 产出的 unsigned IPA 用 ESign / Sideloadly 重签（会连同 dylib 一起签）
- **免打包（TrollFools）**：App 已装好的情况下，用 TrollFools 把 `gate.dylib` 直接注入已安装的 App，跳过 IPA 重打包

---

## 四、装机后怎么确认门真的生效

### 卡密输入在哪个位置（从二进制里解出的原文案）

App 真实身份是 **「AX自签正版 · v1.5.3」**（一个设备端自签/注入工具），卡密 UI 是**启动弹窗**：

1. 启动先弹说明框
   - 标题：`AX自签正版 . v1.5.3`
   - 正文：`本版本采用独立卡密认证 / 请输入有效卡密完成激活 / 首次激活后开始计算有效期 / 一张卡密仅限一台设备使用`
   - 按钮：`我已了解`
2. 点「我已了解」→ 弹出输入框（`UIAlertController` + `UITextField`，`secureTextEntry` 密文显示）→ 在这里输 `AXPM-...`
3. 校验通过后进入 HUD 菜单（标签：`版本说明` / `主题设置` / `菜单主题` / `过直播-开/关` / `退出HUD` / `防截屏已开启`）

> 破解版看不到这个框，是因为假服务器直接回了「已激活」。关掉拦截器、换成你自己的服务器后才会重新弹。
> 该 App 有「防截屏」功能，截图可能是黑屏，别以为是坏了。

### 验收步骤

1. 启动 App → 应先出现「激活 AX Pro Max / 请输入你的卡密」
2. 随便输 `AXPM-0000-0000-0000-0000` → 提示「卡密不存在」（说明请求真到了你服务器）
3. `python server/cardgen.py issue -n 1 -d 30` 生成真卡 → 输入 → 进入 App
4. `python server/cardgen.py info AXPM-....` → 能看到绑定设备与到期
5. 换第二台设备用同一张单设备卡 → 提示「该卡密已绑定其他设备」
6. `python server/cardgen.py revoke AXPM-....` → 重启 App 被拦

---

## 五、卡密体系

| 项 | 说明 |
|---|---|
| 格式 | `AXPM-XXXX-XXXX-XXXX-XXXX`，Crockford Base32，16 字符 = 80 bit 熵 |
| 输入容错 | 自动大写、去横线空格、`I/L→1` `O→0` `U→V` |
| 绑机 | 首次激活写 `device_id`（IDFV 的 SHA256），超 `max_devices` 拒绝 |
| 有效期 | 签发即定 `expires_at` |
| 封禁 | `revoke` 立即失效，已激活设备下次心跳被踢 |
| 离线 | 缓存的是**服务端签名过**的响应；服务器不可达且缓存有效 → 放行 |
| 防伪造 | 改任一字段都会验签失败；私钥只在服务器 |
| 防时间回拨 | 客户端记录"见过的最大时间"，本地时间倒退 >5 分钟即判定作弊、拦回激活页 |
| 审计 | 每次校验写 `audit` 表（卡号/设备/IP/UA/结果） |
| 防套壳 | `AXP_BUNDLE_IDS` 白名单，包名不匹配时门不接管（也不会误伤别的 App） |

协议：

```http
POST /api/v1/app/verify
X-App-Key: ax_pro_max          X-Version: 1.6.1
X-Protocol-Version: KVREQ-V3   X-Body-SHA256: <body sha256 hex>

{"schema":"KVREQ-V3","card_code":"AXPM-...","device_id":"<sha256>",
 "nonce":"<uuid>","issued_at":1795560100,"action":"activate"}
```

```json
{"schema":"KVRESP-V1","ok":true,
 "payload":{"activationState":"unlocked","expires_at":1798152074,"plan":"pro",
            "device_id":"...","devices_used":1,"devices_max":1},
 "payload_raw":"{...规范化JSON原文...}",
 "signature":"<RSA-PSS-SHA256 over payload_raw>"}
```

客户端对 **`payload_raw` 原文**验签（不做二次序列化），彻底规避两端 JSON 差异。

---

## 六、可选加固：顺便关掉原包假服务器（路线 B）

`patch_ipa.py` 可把原包的公钥、域名、IP 换成你的，并把 `canInitWithRequest:` 改成 `return NO`：

```bash
python patch/patch_ipa.py --ipa in/input.ipa --out out/patched.ipa \
    --pubkey-from server/keys/public_b64.txt \
    --host 你的域名 --ip 1.2.3.4 --kill-interceptor --dry-run   # 先看
```

| 补丁 | 位置 |
|---|---|
| 公钥（360B 等长） | file `0x10b09ca` |
| 域名 `api.axpro.local`(15B) | file `0x10b0c09` |
| 备用 IP | file `0x10b07dd` / `0x10b0bfd` |
| 拦截器 → `mov w0,#0; ret` | file `0x1096a78` |

风险：AX 模块有 IMP 自校验（`__axseal`），改它可能触发模块自禁用；且主包自身验签公钥是否就是这串需真机验。
**先跑通路线 A，再考虑叠加 B。**

---

## 七、文件清单

```
axlicense/
├─ server/
│  ├─ crypto.py       密钥生成、RSA-PSS 签名/验签、DER↔Base64
│  ├─ store.py        SQLite：卡密 / 绑机 / 审计
│  ├─ server.py       卡密服务（标准库 HTTP，可 TLS）
│  ├─ cardgen.py      生成/查询/封禁/解绑/导出
│  └─ keys/           private.pem（务必备份）、public_b64.txt
├─ tweak/
│  ├─ gate.m          授权门 dylib（UI + 验签 + 缓存 + 防回拨 + 可选关假服务器）
│  ├─ Makefile        Theos（LIBRARY_NAME = gate）
│  └─ axp_config.h.sample
├─ patch/
│  ├─ configure.py    生成 axp_config.h（地址 + 公钥 + 白名单）
│  ├─ machop.py       Mach-O 手术刀
│  ├─ inject.py       注入 dylib + 重打包（已实测 ncmds 44→45）
│  └─ patch_ipa.py    路线 B 常量补丁
├─ .github/workflows/build-ipa.yml
└─ README.md
```

---

## 八、已知坑

1. **arm64e**：手工改码要保 prologue/epilogue 配对；本方案唯一改的指令是 `mov w0,#0; ret`。
2. **签名**：任何字节改动都会让原签名失效；TrollStore 安装会重签，ESign/Sideloadly 同理。
3. **HTTPS/ATS**：iOS 默认拦明文，域名务必配有效证书。
4. **公钥必须与服务器私钥配对**：只换服务器私钥、包里公钥不动 → 全部验签失败（表现为一直停在激活页）。
5. **域名长度**：仅路线 B 受 `api.axpro.local`（15B）限制；路线 A 无此约束。
6. **误伤**：`AXP_BUNDLE_IDS` 不符时门不接管，避免把这套 dylib 注入别的 App 时白屏。
7. **别改主包混淆代码**：`activationState` 的调用点是一片 `braa` 分发器，硬改必然崩。
