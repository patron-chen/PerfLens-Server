# PerfLens-Server

PerfLens 的独立内网激活服务器。客户端以现有 UID 登记，首次请求自动签发，适用于受控内网。管理页按 UID 停发或恢复签发。

## 环境初始化

在全新机器上部署前，运行 setup 脚本初始化环境。脚本优先检测本机的 64 位 Python 3.13；若未安装，会自动下载官方独立便携版 CPython 3.13 到 `private/python`（无需安装系统级软件包或管理员权限），随后创建 `private/activation-venv`、安装依赖包并初始化签名密钥与数据库。

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

初始化成功后，在 `deploy.bat` / `deploy.sh` 顶部填写 `PERFLENS_ADMIN_USERNAME` 和 `PERFLENS_ADMIN_PASSWORD` 即可开始部署。

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

部署脚本默认监听 `0.0.0.0:8787`。可在 BAT 中修改 `ACTIVATION_HOST` 和 `ACTIVATION_PORT`，在 Bash 中修改 `listen_host` 和 `listen_port`。将端口的访问范围限制在使用 PerfLens 的内网。

## 管理与打包

- 默认在服务主机打开 `http://127.0.0.1:8787/admin` 登录。其他内网机器通过 HTTPS 登录。在 BAT 中填写 `ACTIVATION_TLS_CERTFILE` 和 `ACTIVATION_TLS_KEYFILE`，或在 Bash 中填写 `tls_certfile` 和 `tls_keyfile` 启用 HTTPS。浏览器和 PerfLens 客户端需信任签发 TLS 证书的 CA，访问地址需匹配证书。
- 部署脚本默认将 `PERFLENS_ADMIN_ALLOW_HTTP` 设为 `0`。在可信内网需要使用 HTTP 管理时，将脚本中的值改为 `1`，保持 TLS 配置为空，然后重启服务。HTTP 下 Basic Auth 凭据未经加密。
- 管理页显示登记 UID、计算机名、本机 IP、客户端版本、首次登记、最近请求、最近签发到期和签发开关。默认每次授权 1440 分钟，修改从下一次签发起生效。停发后，客户端已领取的授权有效至到期。
- 将服务器的 `private/activation/activation-public.pem` 复制到客户端仓库的 `private/activation-public.pem`。在客户端 `buildscript/package.bat` 中填写 `PERFLENS_PACKAGE_ACTIVATION_IP` 和 `PERFLENS_PACKAGE_ACTIVATION_PORT`，使用客户端可达的服务器 IP 和端口。启用 HTTPS 时将 `PERFLENS_PACKAGE_ACTIVATION_SCHEME` 改为 `https`。运行 `buildscript\package.bat --check --no-pause` 校验，再运行 `buildscript\package.bat` 打包。
- 将数据目录限制给运行服务和发布更新的账号。停机备份 `activation.sqlite3`、`activation-private.pem`、`activation-public.pem` 和已发布的 `updates` 目录。恢复时使用同一套密钥，以便已打包客户端继续验签。首次初始化后可用相同数据目录重复运行 `init` 校验或补导公钥。

客户端调用 `POST /api/v1/activate`，发送 `{"uid":"<64位小写十六进制UID>"}`。成功返回 `200` 和 `{"code":"..."}`，停发返回 `403`，UID 格式错误返回 `422`。客户端按签名中的 UTC 到期时间续期。建议用系统时间同步服务保持客户端和服务器的时钟一致。

激活请求可附带 `computer_name`、`local_ip`（IPv4 或 IPv6）和 `client_version`。服务在成功签发时按 UID 保存最近一次提供的值。桌面客户端启动时上报一次，即使本机已有有效授权缓存。服务启动时自动升级 SQLite，历史记录的未知字段显示「—」，旧客户端可继续按 UID 激活。

## 发布与管理在线更新

支持以下三种方式发布更高或新的稳定版本 `X.Y.Z`（要求打包时使用同一激活服务器地址与公钥）：

1. **网页端直接上传（推荐）**：登录 `/admin` 切换到「版本管理」标签页，选择或拖入打包输出目录（或 `manifest.json`、Setup EXE 和 Unpacked ZIP），分片流式校验签名后直接写入 `private/activation/updates`，不产生 `distribution` 副本。上传时可选择「上传后立即启用」或先以「停用」状态入库内测。
2. **`distribution` 目录自动监听**：将同一批次的安装 EXE、解包 ZIP 和 `manifest.json` 复制到 `distribution` 目录：

```text
distribution/
  PerfLens-Setup-X.Y.Z-x64.exe
  PerfLens-Unpacked-X.Y.Z-win-x64.zip
  manifest.json
```

服务每 5 秒检查 `distribution`，校验公钥指纹、产物大小和 SHA-256 后，将其**移动**到 `private/activation/updates/<version>/`（同盘零拷贝，并自动删除已消费的 `distribution/manifest.json`，避免双份存储）。若存在历史遗留文件，可在管理页「版本管理」中一键清理冗余。

3. **手动 CLI 发布**：使用部署环境的 Python 并指定服务数据目录（默认复制保留源文件；附加 `--move` 可移走源文件）：

```text
python -m activation_server publish-update --data-dir private/activation --release-dir <发行目录>
```

### 版本管理与下线策略

- 管理页顶部显示当前的推送版本，点击直达「版本管理」查看已发布版本、发布来源、文件大小、SHA-256、客户端分布及管理员下载入口。
- `/api/v1/updates/windows-x64/latest` 返回版本号最高的**已启用**版本；无可用版本时返回 `204`。
- 在管理页将某版本设为「停用」后，`/latest` 自动回落到次高已启用版本，且公共下载接口 `/api/v1/updates/windows-x64/{version}/{kind}` 一并屏蔽返回 `404`（防止已弹窗客户端继续拉取），管理页仍可通过鉴权入口下载。
- 已发布版本保持不可变，如需重传同版本号需先在版本列表删除旧版本。

## 验证

`python -B -m unittest discover -s tests -v` 在本机回环地址验证签发和管理接口。
