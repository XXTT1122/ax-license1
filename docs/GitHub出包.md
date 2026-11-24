# 用 GitHub 出包（不用装 Mac、不用敲 git 命令）

本机没有 iOS 工具链，`gate.dylib` 必须在 macOS 上编译。用 GitHub 的免费 macOS runner，全程网页操作。

---

## 一、为什么必须换到 dylib（路线 A）

你装的那个测试包输卡密后闪退，原因已经查清：**注入模块被模组作者用私钥签名封印了**。

`__DATA.__axseal` 的内容：

```
41 58 53 4c 56 30 30 31   AXSLV001          ← magic
02 00 00 00               ver = 2
47 00 00 00               签名长度 = 71
bb 46 cd 46 …             SHA-256（模块内容哈希）
30 45 02 21 00 ff 7f …    DER ECDSA 签名（71 字节）
```

`__DATA.__axresid` 是第二个哈希 `33168dae…`。

主包 `__TEXT.__text` 有 3 处读这两个封印：`0x10029b5ec`、`0x10029b674`、`0x10029d7f0`。

**结论**：只要动 AX 段的任何一个字节（换公钥、换域名、改 `canInitWithRequest` 返回），哈希就对不上、ECDSA 签名验不过 → 主包判定"模块被改" → 崩。
私钥在作者手里，我们没法重新签。**所以路线 B 对密封模块不成立。**

路线 A 的 dylib 只挂启动通知 + 建窗口，**一个字节都不碰 AX 模块**，因此不受封印影响。

---

## 二、GitHub 网页操作（约 10 分钟）

### 1. 建私有仓库

浏览器打开 https://github.com/new

- Repository name：`ax-license`（随意）
- 选 **Private**（务必私有，里面有你的公钥和包）
- 不要勾 README / .gitignore / license
- Create repository

### 2. 上传文件

在新仓库页面点 **uploading an existing file**（或 `Add file → Upload files`）。

把 `axlicense-bundle.zip`（在 `out\` 目录）解开，然后**把 `axlicense` 里面的内容拖进去**，注意保持目录结构：

```
.github/workflows/build-ipa.yml
in/input.ipa
patch/*.py
server/*.py
server/keys/public_b64.txt
tweak/gate.m
tweak/Makefile
tweak/axp_config.h.sample
README.md
docs/域名与服务器.md
.gitignore
```

> 浏览器拖拽文件夹时，如果它把外层 `axlicense/` 也带进去了，就把仓库里的这个多出来的目录删掉，保证 `tweak/`、`patch/` 在**根目录**。

提交信息随便写，点 **Commit changes**。

### 3. 加仓库变量（可选，方便复用）

`Settings → Secrets and variables → Actions → Variables → New repository variable`

- Name：`AXP_SERVER_URL`
- Value：`http://192.168.1.112`（或你以后的正式域名）

这样以后不用每次手填。

### 4. 跑

`Actions` → 左侧 `build-gate-ipa` → 右侧 **Run workflow**

- `server_url`：`http://192.168.1.112`（本地测试）或 `https://lic.你的域名`
- `disable_ax_interceptor`：**保持 false**（务必关，碰它会触发封印）

点绿色 **Run workflow**，等 3–6 分钟（首次要下 SDK，会久一点）。

### 5. 取产物

进去点最新那次运行 → 底部 **Artifacts** → 下载 `AXProMax-gate`，里面是 `AXProMax-gate.ipa`
（CI 已自动 `ldid -S` 重签主二进制和 dylib）。

装它，启动就该弹「AX自签正版 · v1.5.3」——这次弹窗由**我们的 dylib** 控制，跟封印无关。

---

## 三、CI 失败怎么看

| 报错关键字 | 原因 | 处理 |
|---|---|---|
| `缺少 in/input.ipa` | 包没上传或名字不对 | 确认 `in/input.ipa` 存在且是 19 MB 那个 |
| `缺少公钥` | `server/keys/public_b64.txt` 没上传 | 上传它（只有公钥，非机密） |
| `candidates` / `no such sysroot` | SDK 没下全 | 重跑一次；或换 `macos-13` |
| `gate.dylib not found` | Makefile 目标名不符 | 看 make 日志里的实际产物名，改 `LIBRARY_NAME` |
| `公钥片段命中: False` | `configure.py` 没跑或写错文件 | 检查 workflow 里 `生成配置头` 那步的日志 |

---

## 四、装完还是弹不出我们的门？

我们的 dylib 是"盖窗口"，不改 App 内部逻辑，所以只有两种异常：

1. **没有弹窗**：`AXP_BUNDLE_IDS` 与实际 bundle id 不匹配（当前白名单 `com.apple.music`）→ 看 CI 里 `axp_config.h` 的 `AXP_BUNDLE_IDS`
2. **弹了但输卡密报"网络异常"**：手机没连到你电脑 → 手机浏览器开 `http://192.168.1.112/health` 验证

> 注意：App 原有的破解逻辑还在（假服务器照旧回"已激活"），但我们的窗口会盖在它上面，没有有效卡密就无法操作。这就是路线 A 的设计——不去争那一层，直接在外面加锁。
