# PerfLens-Server

PerfLens 的独立内网激活服务器。设备登记后按分组策略审批，获批且允许签发的设备自动领取并续签授权。服务端校验更新制品并用激活私钥签署更新清单。

## 环境初始化

在全新机器上部署前，运行 setup 脚本初始化环境。脚本优先检测本机的 64 位 Python 3.13；若未安装，会自动下载官方独立便携版 CPython 3.13 到 `private/python`（无需安装系统级软件包或管理员权限）。随后创建 `private/activation-venv`、安装依赖包并初始化激活密钥。

### Windows

双击或在命令行运行 `setup.bat`：

```bat
setup.bat
setup.bat --help
setup.bat --mirror https://ghproxy.net/
setup.bat --python "C:\Python313\python.exe"
setup.bat --force --no-pause
```

- `--mirror <URL>`：指定 GitHub / 代理加速前缀（也可设置环境变量 `GH_PROXY` 和 `PIP_INDEX_URL`）。
- `--python <路径>`：指定已有 Python 3.13 解释器路径。
- `--force`：强制重新创建虚拟环境并重装依赖。
- `--no-pause`：执行完毕后不暂停（适用于自动化调用）。

### Linux

在终端运行 `setup.sh`：

```bash
bash setup.sh
bash setup.sh --help
bash setup.sh --mirror https://ghproxy.net/
bash setup.sh --python /usr/local/bin/python3.13
bash setup.sh --force
```

首次初始化会在 `private/activation/` 生成 `activation-private.pem` 和 `activation-public.pem`。重复运行 setup 会使用已有的激活密钥。初始化后可选择内网 HTTP 或 HTTPS 部署。

## 部署

部署脚本会自动优先检测并复用 `setup` 初始化的 `private/activation-venv` 或 `private/python`。在对应脚本顶部填写 `PERFLENS_ADMIN_USERNAME` 和 `PERFLENS_ADMIN_PASSWORD`。两项默认留空，填好后才能部署。使用 ASCII 字符，用户名不能含冒号。实际凭据仅填写在部署机的脚本中，并限制文件访问权限。

### Windows（BAT）

双击或从 CMD 运行 `deploy.bat`，脚本会启动隐藏的后台进程并退出。双击时启动窗口可能短暂闪现。`ACTIVATION_PYTHON` 默认使用 PATH 中的 `python.exe`，也可填写 Python 3.13 的绝对路径。凭据中的 `%` 在 BAT 中写成 `%%`。

```bat
deploy.bat
deploy.bat --help
deploy.bat --status
deploy.bat --stop
deploy.bat --restart
```

`--status` 显示本目录实例的状态、服务进程 PID 和实际监听地址。`--stop` 停止本目录启动的实例，`--restart` 停止后重新在后台启动。需要在前台运行时使用 `deploy.bat --foreground`，按 `Ctrl+C` 停止。升级时先停止旧版后台实例，再用新脚本启动，以便登记进程。

### Linux（Bash）

`deploy.sh` 默认使用 `python3.13`，可修改 `python_exe` 指向实际解释器。

```bash
bash deploy.sh
bash deploy.sh --help
```

默认前台运行，按 `Ctrl+C` 停止。

在使用 systemd 的 Linux 上，以部署账号执行以下命令。脚本在需要时使用 sudo 安装系统服务，立即启动并设为开机自启。服务以该部署账号运行。首次安装前先停止占用同一端口的前台实例。

```bash
bash deploy.sh --install-service
```

- `bash deploy.sh --status` 查看状态、PID 和实际监听地址。也可查询从本目录启动的前台实例。查询使用 `ss`（iproute2）和 `pgrep`（procps）。
- `bash deploy.sh --stop` 停止 systemd 服务。
- `bash deploy.sh --restart` 重启 systemd 服务并读取最新配置。
- `sudo systemctl disable --now perflens-activation.service` 停止并取消自启。
- `bash deploy.sh --uninstall` 停止服务、取消自启并移除 systemd 服务单元。也可用 `bash deploy.sh uninstall`。部署文件、签名密钥、数据库和日志均保留。

部署脚本创建或复用 `private/activation-venv`，按 `activation_server/requirements.txt` 安装依赖，并初始化 `private/activation` 中的签名密钥。重跑复用原密钥和数据库。systemd 启动时直接使用已部署的环境。

两端服务日志写入脚本旁的 `log/activation-server.log`。Windows 的依赖安装和初始化输出也写入此文件。每条日志使用服务器本地时间并带 UTC 偏移。写入将超过 50 MiB 时，当前文件按轮转时间归档，例如 `activation-server-20261110-153000-123456+0800.log`，随后继续写入新的 `activation-server.log`。归档文件保留在 `log` 目录。

脚本同时启动激活和在线更新。发行目录默认是脚本旁的 `distribution`。Windows 在 `DISTRIBUTION_DIR` 中配置，Linux 在 `distribution_dir` 中配置，支持绝对路径和相对于脚本的路径。服务启动时创建该目录。

部署脚本默认监听 `0.0.0.0:8787`。可在 BAT 中修改 `ACTIVATION_HOST` 和 `ACTIVATION_PORT`，在 Bash 中修改 `listen_host` 和 `listen_port`。用防火墙将端口限制在使用 PerfLens 的内网。

## 管理与打包

- **内网 HTTP**。设置 `PERFLENS_ADMIN_ALLOW_HTTP=1`，TLS 证书和私钥路径留空。激活、更新和 `/admin` 均可通过 HTTP 使用，服务只接受来自私有内网或回环地址的 HTTP 连接。HTTP 模式下管理员凭据和设备信息为明文，适用于受控内网直连。
- **HTTPS**。在 BAT 填写 `ACTIVATION_TLS_CERTFILE` 和 `ACTIVATION_TLS_KEYFILE`，或在 Bash 填写 `tls_certfile` 和 `tls_keyfile`。浏览器和客户端通过与证书匹配的 HTTPS 地址连接，并信任签发 CA。关闭 HTTP 开关时，回环仍可用于服务主机本地 HTTP 维护。
- `/admin` 始终校验管理员凭据。`PERFLENS_ADMIN_NETWORKS` 可额外限制来源，填写逗号分隔的 CIDR。留空时，HTTP 开关开启允许内网和回环管理，关闭时只允许回环。直接运行 `serve` 也可重复传入 `--admin-network`。服务按 TCP 对端地址判断来源。
- 「分组管理」可分别设置自动审批和自动签发。每个分组默认关闭自动审批，默认分组也初始关闭自动签发。启用自动审批后，本组待审批设备在下次请求时通过审批。自动签发对已审批且跟随分组的设备生效，单机停发优先。关闭自动审批后，已审批设备保留审批状态。
- 人工审批时，在管理页核对设备的 UID、计算机名、来源 IP 和版本，再选择「审批通过」。在线租约默认 1440 分钟。停发对后续签发有效，已领取的租约有效至原到期时间。删除设备会移除其审批状态、租约、分组和灰度名单记录。设备下次请求时按默认分组重新登记。
- 客户端打包目录 `private/` 分别放入服务端使用的 `activation-public.pem` 和离线签发机导出的 `offline-license-public.pem`。在客户端 `buildscript/package.bat` 填写服务地址、协议和端口，再运行 `package.bat --check --no-pause`。HTTP 仅接受字面私有 IPv4（`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`）和 IPv6 `fc00::/7`。域名和其他 IP 使用 HTTPS。
- 限制服务数据目录权限。停机备份 `activation.sqlite3`、`activation-private.pem`、`activation-public.pem` 和 `updates`。离线授权管理员另外备份离线签名私钥。可用同一数据目录重复运行 `init` 校验或补导在线公钥。

客户端调用 `POST /api/v1/activate` 并发送 `{"uid":"<64位小写十六进制UID>"}`。成功返回 `200` 和 `{"code":"..."}`。待审批且无既有租约返回 `403`（`{"detail":"approval_required"}`），已审批但停发或迁移时保留既有租约的待审批设备返回 `403`（`{"detail":"issuance_disabled"}`）。UID 格式错误返回 `422`。客户端按签名中的 UTC 到期时间续期，在启动校验收到 `approval_required` 时清除本地 `license-online.json` 缓存。

激活请求可附带 `computer_name`、`local_ip`（IPv4 或 IPv6）和 `client_version`。首次登记及后续请求均可更新元数据。`local_ip` 优先记录连接来源地址，缺少有效连接地址时使用客户端上报值。桌面客户端启动时上报一次。UID 与元数据用于资产登记，防止仿冒已获批的 UID 需要独立设备凭据。

### 手工签发离线授权

在管理员保管的机器上用 Python 3.13 和本仓库依赖生成离线密钥。复制公钥用于客户端打包。按已核对的授权记录、UID 和到期时间签发 JSON。

```text
python -m activation_server init-signing-key --purpose offline-license --key-dir private/offline-signing
python -m activation_server issue-offline --signing-key private/offline-signing/offline-license-private.pem --uid <设备UID> --expires-at 2027-01-01T00:00:00Z --output issued.json
```

### 从旧版切换

1. 先限制管理入口并备份数据。若曾远程通过 HTTP 登录，轮换管理员凭据，核对授权和已发布版本。
2. 按新公钥组合及部署选定的地址和协议构建客户端。按已核对的授权记录换发离线授权，经可信内部分发渠道交付新版。
3. 在维护窗口切换服务。SQLite 自动迁移并保留分组、显式停发状态及已有租约的到期时间。从旧版迁移的未审批设备默认需人工审批后续签。先验证少量设备，再扩大部署。
4. 受管 Windows 设备升级后，可用企业应用控制策略限制旧版和篡改版运行。

## 发布与管理在线更新

直接使用打包生成的 `manifest.json`。三个发布入口都会核对清单中的激活公钥指纹、安装 EXE 和解包 ZIP 的大小及 SHA-256。服务端根据清单生成 `update.json`，使用现有激活私钥签名，并通过 `/api/v1/updates/windows-x64/latest` 返回 `{payload, signature}`。客户端先用内置激活公钥验签，再校验下载文件。

旧客户端可继续通过原服务地址获取更高版本。打包和发布时沿用客户端已信任的激活密钥。

1. **网页端直接上传（推荐）**。在 `/admin` 的「版本管理」选择打包生成的 `manifest.json`、Setup EXE 和 Unpacked ZIP。服务校验上传的制品并签署更新清单，写入 `private/activation/updates`。上传默认进入灰度测试，可选继承名单、全量发布或停用。
2. **`distribution` 目录自动监听**：将同一批次的安装 EXE、解包 ZIP 和 `manifest.json` 复制到 `distribution` 目录：

```text
distribution/
  PerfLens-Setup-X.Y.Z-x64.exe
  PerfLens-Unpacked-X.Y.Z-win-x64.zip
  manifest.json
```

服务每 5 秒检查 `distribution`，校验激活公钥指纹、制品大小和 SHA-256 后，将文件**移动**到 `private/activation/updates/<version>/`（同盘零拷贝，并自动删除已消费的 `distribution/manifest.json`，避免双份存储），并默认进入 **灰度测试** 阶段（自动复制当前「默认灰度名单」）。若存在历史遗留文件，可在管理页「版本管理」中一键清理冗余。

3. **手动 CLI 发布**：使用部署环境的 Python 并指定服务数据目录（默认复制保留源文件并进入灰度测试、复制默认灰度名单；附加 `--move` 移走源文件、`--full` 直接全量发布、`--inherit-from none|<version>` 指定继承源）：

```text
python -m activation_server publish-update --data-dir private/activation --release-dir <发行目录>
```

### 版本生命周期与灰度测试机制

- **三态生命周期**：版本支持 **灰度测试（`canary`）**、**全量发布（`released`）** 与 **已停用（`disabled`）** 三种状态，可在管理页「版本管理」一键切换。
- **灰度路由规则**：桌面客户端请求 `/api/v1/updates/windows-x64/latest` 与安装包下载时，通过 `X-PerfLens-UID` 请求头携带本机 64 位 UID（未携带或格式无效视为普通客户端）：
  - 普通客户端：仅匹配版本号最高的「全量发布」版本；
  - 灰度客户端：在版本号最高的「全量发布」版本与自身所在白名单的「灰度测试」版本中取最高版本。
- **双层灰度名单管理**：
  - **默认灰度名单**：可在管理页「灰度名单」标签页直接维护（支持提前导入未激活设备的 64 位 UID 或从已登记客户端批量挑选，亦可在「客户端管理」行内一键加入/移出），用于所有新发布灰度版本的初始模板。
  - **版本独立灰度名单**：每个版本拥有独立的灰度名单，新版本创建时复制继承源（互不影响后续编辑）；可在「版本管理」每行点击「灰度名单」弹窗独立增删、从默认/历史版本继承（替换或合并），或将某版本的稳定测试名单反向覆盖设为新的默认名单。删除版本时会自动清理对应的版本灰度记录。
- **下线与停用**：将版本设为「已停用」后，`/latest` 自动回落，且公共下载接口 `/api/v1/updates/windows-x64/{version}/{kind}` 对所有客户端（含灰度设备）返回 `404`，管理页仍可通过鉴权入口下载；再次转回「灰度测试」时保留该版本原有的灰度名单。
- 已发布版本保持不可变，如需重传同版本号需先在版本列表删除旧版本。

## 验证

`python -B -m unittest discover -s tests -v` 在本机回环地址验证签发和管理接口。
