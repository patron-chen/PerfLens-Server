# PerfLens-Server

PerfLens 的独立内网激活服务器。客户端以现有 UID 登记，首次请求自动签发，适用于受控内网。管理页按 UID 停发或恢复签发。

## 部署

准备带有 `venv` 和 `pip` 的 Python 3.13。在对应脚本顶部填写 `PERFLENS_ADMIN_USERNAME` 和 `PERFLENS_ADMIN_PASSWORD`。两项默认留空，填好后才能部署。使用 ASCII 字符，用户名不能含冒号。实际凭据仅填写在部署机的脚本中，并限制文件访问权限。

### Windows（BAT）

`deploy.bat` 直接用 CMD 运行。`ACTIVATION_PYTHON` 默认使用 PATH 中的 `python.exe`，也可填写 Python 3.13 的绝对路径。凭据中的 `%` 在 BAT 中写成 `%%`。

```bat
deploy.bat
```

### Linux（Bash）

`deploy.sh` 默认使用 `python3.13`，可修改 `python_exe` 指向实际解释器。

```bash
bash deploy.sh
```

脚本创建或复用 `private/activation-venv`，按 `activation_server/requirements.txt` 安装依赖，并初始化 `private/activation` 中的签名密钥。重跑复用原密钥和数据库。服务以前台方式运行，按 `Ctrl+C` 停止。

部署脚本默认监听 `0.0.0.0:8787`。可在 BAT 中修改 `ACTIVATION_HOST` 和 `ACTIVATION_PORT`，在 Bash 中修改 `listen_host` 和 `listen_port`。将端口的访问范围限制在使用 PerfLens 的内网。

## 管理与打包

- 默认在服务主机打开 `http://127.0.0.1:8787/admin` 登录。其他内网机器通过 HTTPS 登录。在 BAT 中填写 `ACTIVATION_TLS_CERTFILE` 和 `ACTIVATION_TLS_KEYFILE`，或在 Bash 中填写 `tls_certfile` 和 `tls_keyfile` 启用 HTTPS。浏览器和 PerfLens 客户端需信任签发 TLS 证书的 CA，访问地址需匹配证书。
- 管理页显示登记 UID、首次登记、最近请求、最近签发到期和签发开关。默认每次授权 1440 分钟，修改从下一次签发起生效。停发后，客户端已领取的授权有效至到期。
- 将脚本输出的 `private/activation/activation-public.pem` 复制到客户端仓库的 `private/activation-public.pem`。在客户端 `buildscript/package.bat` 中填写 `PERFLENS_PACKAGE_ACTIVATION_IP` 和 `PERFLENS_PACKAGE_ACTIVATION_PORT`，使用客户端可达的服务器 IP 和端口。启用 HTTPS 时将 `PERFLENS_PACKAGE_ACTIVATION_SCHEME` 改为 `https`。运行 `buildscript\package.bat --check --no-pause` 校验，再运行 `buildscript\package.bat` 打包。
- 将数据目录限制给运行服务的账号。停机备份 `activation.sqlite3`、`activation-private.pem` 和 `activation-public.pem`。恢复时使用同一套密钥，以便已打包客户端继续验签。首次初始化后可用相同数据目录重复运行 `init` 校验或补导公钥。

客户端调用 `POST /api/v1/activate`，发送 `{"uid":"<64位小写十六进制UID>"}`。成功返回 `200` 和 `{"code":"..."}`，停发返回 `403`，UID 格式错误返回 `422`。客户端按签名中的 UTC 到期时间续期。建议用系统时间同步服务保持客户端和服务器的时钟一致。

## 验证

`python -B -m unittest discover -s tests -v` 在本机回环地址验证签发和管理接口。
