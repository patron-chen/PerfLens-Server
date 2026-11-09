# PerfLens-Server

PerfLens 的独立内网激活服务器。在 Windows 或 Linux 上，从本仓库根目录使用 Python 3.13 启动。客户端以现有 UID 登记，首次请求自动签发，适用于受控内网。管理页按 UID 停发或恢复签发。

## Windows（PowerShell 7）

```powershell
python -m venv private/activation-venv
$activationPython = ".\private\activation-venv\Scripts\python.exe"
& $activationPython -m pip install -r activation_server/requirements.txt
& $activationPython -m activation_server init --data-dir private/activation
$env:PERFLENS_ADMIN_USERNAME = Read-Host "管理账号"
$env:PERFLENS_ADMIN_PASSWORD = Read-Host "管理密码" -MaskInput
& $activationPython -m activation_server serve --data-dir private/activation --host 0.0.0.0 --port 8787
```

## Linux（Bash）

```bash
python3.13 -m venv private/activation-venv
activation_python=private/activation-venv/bin/python
"$activation_python" -m pip install -r activation_server/requirements.txt
"$activation_python" -m activation_server init --data-dir private/activation
read -rp '管理账号 ' PERFLENS_ADMIN_USERNAME
read -rsp '管理密码 ' PERFLENS_ADMIN_PASSWORD
printf '\n'
export PERFLENS_ADMIN_USERNAME PERFLENS_ADMIN_PASSWORD
"$activation_python" -m activation_server serve --data-dir private/activation --host 0.0.0.0 --port 8787
```

账号和密码使用 ASCII 字符。默认监听 `127.0.0.1:8787`。使用 `--host` 开放内网访问时，将该端口的访问范围限制在使用 PerfLens 的网络。

## 管理与打包

- 服务主机通过 `http://127.0.0.1:8787/admin` 登录。其他内网机器通过 HTTPS 登录。启动时同时传入 `--ssl-certfile <证书>` 和 `--ssl-keyfile <TLS私钥>` 启用 HTTPS。浏览器和 PerfLens 客户端需信任签发 TLS 证书的 CA，访问地址需匹配证书。
- 管理页显示登记 UID、首次登记、最近请求、最近签发到期和签发开关。默认每次授权 1440 分钟，修改从下一次签发起生效。停发后，客户端已领取的授权有效至到期。
- 打包 PerfLens 客户端时，将客户端可达的服务 URL（含端口）传给 `--activation-server`，将 `activation-public.pem` 路径传给 `--activation-public-key`。启用 HTTPS 时填写 `https://` 地址。
- 将数据目录限制给运行服务的账号。停机备份 `activation.sqlite3`、`activation-private.pem` 和 `activation-public.pem`。恢复时使用同一套密钥，以便已打包客户端继续验签。首次初始化后可用相同数据目录重复运行 `init` 校验或补导公钥。

客户端调用 `POST /api/v1/activate`，发送 `{"uid":"<64位小写十六进制UID>"}`。成功返回 `200` 和 `{"code":"..."}`，停发返回 `403`，UID 格式错误返回 `422`。客户端按签名中的 UTC 到期时间续期。建议用系统时间同步服务保持客户端和服务器的时钟一致。

## 验证

`python -B -m unittest discover -s tests -v` 在本机回环地址验证签发和管理接口。
