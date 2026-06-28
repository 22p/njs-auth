# njs WebAuthn 认证中间件

基于 [njs](https://nginx.org/en/docs/njs/)（nginx 内嵌 JavaScript，QuickJS 引擎）实现的**单用户 WebAuthn / Passkey 认证中间件**，用 nginx 的 `auth_request` 保护任意后端。

零外部依赖，纯 njs（QuickJS 引擎）实现：自带 CBOR 解码器、COSE 公钥解析、DER 签名转换，使用 njs 内置 WebCrypto（`crypto.subtle`）完成 ES256 验签。

## 文件

| 文件 | 说明 |
|------|------|
| `auth.js` | 核心模块：路由分发、CBOR/COSE/DER、WebAuthn 验证、会话管理 |
| `login.html` | 登录与注册页面，自动判断当前状态 |
| `nginx.conf` | 示例配置（整站保护 + 单路径保护两种模式） |

## 依赖

- nginx 编译/加载了 `ngx_http_js_module`（njs 模块）
- 推荐 njs ≥ 1.0.0，使用 **QuickJS 引擎**（`js_engine qjs;`）。最低 ≥ 0.8.10（QuickJS 在 0.8.6–0.8.10 期间陆续补齐了 `Buffer`/`fs`/WebCrypto）。

## 安装

### 1. 放置文件

将 `auth.js` 和 `login.html` 放到同一目录（默认 `/etc/nginx/njs/`）。

### 2. http 块配置

```nginx
http {
    js_engine qjs;
    js_path "/etc/nginx/njs/";
    js_import auth from auth.js;

    js_shared_dict_zone zone=authsess:1m timeout=86400s;
    js_shared_dict_zone zone=authchal:1m timeout=300s;

    # ... server 块
}
```

### 3. 认证端点（两种模式通用）

```nginx
location ^~ /auth/ {
    auth_request off;
    client_max_body_size 16k;
    js_content auth.route;
}
location = /auth/verify {
    internal;
    auth_request off;
    error_page 401 403 = @verify_pass;   # 整站模式必须
    js_content auth.verify;
}
location @verify_pass   { return 401; }
location @auth_redirect { return 302 /auth/login?next=$request_uri; }
```

### 4. 选择保护模式

**模式 A：整站要求登录**

在 `server {}` 顶部加全局 `auth_request`，所有 location 自动继承：

```nginx
server {
    auth_request /auth/verify;
    error_page 401 403 = @auth_redirect;

    # ... 上面的认证端点 ...
    # ... 你的其他 location ...
}
```

需要放行的公开路径单独加 `auth_request off;`：

```nginx
location = /generate_204 { auth_request off; return 204; }
location = /ncsi.txt     { auth_request off; return 200 "Microsoft NCSI"; }
```

**模式 B：仅保护某个路径**

不在 server 顶部加全局 `auth_request`，只在需要保护的 location 内单独声明：

```nginx
server {
    # ... 上面的认证端点 ...

    location /protected/ {
        auth_request /auth/verify;
        error_page 401 403 = @auth_redirect;
    }

    location / {
        # 公开访问，不验证
    }
}
```

`auth_request` **不会**自动继承到同级其他 location，每个需要保护的顶层 location 都要单独加。

## 首次使用

1. 浏览器访问 `/auth/login`（或访问受保护路径被自动跳转过来）。
2. 因为还没有凭据文件，页面进入**注册**模式 → 完成生物识别 / 通行密钥注册。
3. 页面弹出一段凭据 JSON，复制并保存为 `<rpId>.json`（放在凭据目录下）：

```sh
vi /etc/nginx/njs/example.com.json    # 粘贴页面给出的 JSON
chmod 644 /etc/nginx/njs/example.com.json
```

4. 刷新页面 → 进入**登录**模式 → 用通行密钥登录，获得会话 Cookie。

凭据文件对 nginx **只读**即可，无需写权限。每个站点按 RP ID 命名凭据文件，多个站点可共用同一个 `auth.js`。

## 端点

所有用户端点由 `auth.route` 按 `r.uri` 分发，nginx 侧只需一条 `location ^~ /auth/`。

| 路径 | 方法 | 说明 |
|------|------|------|
| `/auth/login` | GET | 登录/注册页面 |
| `/auth/state` | GET | 返回 `{registered, authenticated}` |
| `/auth/register/begin` | POST | 获取注册选项 |
| `/auth/register/finish` | POST | 提交注册凭据，返回待保存的 JSON |
| `/auth/login/begin` | POST | 获取登录挑战 |
| `/auth/login/finish` | POST | 提交断言并建立会话 |
| `/auth/logout` | POST | 注销并清除会话 |
| `/auth/verify` | internal | 供 `auth_request` 使用，已登录返回 204，否则 401 |

## 配置项

在 `auth.js` 顶部修改：

| 常量 | 默认值 | 说明 |
|------|--------|------|
| `CRED_DIR` | `/etc/nginx/njs` | 凭据目录（文件名为 `<rpId>.json`） |
| `LOGIN_FILE` | `/etc/nginx/njs/login.html` | 登录页文件路径 |
| `RP_NAME` | `njs-auth` | Relying Party 名称 |
| `RP_ID` | `""` | Relying Party ID（为空时从 `$host` 自动获取） |
| `ORIGIN` | `""` | 期望的 Origin（为空时由 `$scheme` + `$http_host` 自动推导） |
| `SESSION_TTL` | `86400` | 会话滑动有效期，每次有效请求刷新（秒） |
| `SESSION_MAX_LIFETIME` | `604800` | 会话绝对上限，自创建起超过此时长无论是否活跃都会销毁（秒） |
| `CHALLENGE_TTL` | `300` | 挑战有效期（秒） |
| `COOKIE` | `njs_session` | 会话 Cookie 名 |
| `MAX_BODY` | `16384` | finish 端点请求体上限，超出返回 413（字节） |

`RP_ID` 通常留空即可，自动从 nginx 的 `$host` 获取，`$host` 反映**实际访问的域名**。注意当没有 `server_name` 命中时 `$host` 会回退到客户端 `Host` 头，因此应配置一个 `default_server` 拒绝未知 Host。仅当 RP ID 与 server_name 不同时才需显式设置：

```js
const RP_ID = 'auth.example.com';
```

Origin 自动推导为 `$scheme://$http_host` 可用 `ORIGIN` 覆盖：

```js
const ORIGIN = 'https://auth.example.com:8443';
```

## 安全特性

- 所有 Cookie：`HttpOnly; Secure; SameSite=Strict`
- 挑战一次性使用，按类型隔离（注册/登录），通过 `:taken` 标记防重放（原挑战条目按 TTL 过期）
- 注册：每次 `register/begin` 会轮换过期的 challenge cookie（作废旧挑战并签发新挑战）；已存在凭据文件时阻止重复注册
- CBOR 解码器：深度限制（16 层）、字节/文本长度限制（64KB）、越界检查
- authData 解析：长度校验、溢出检查
- COSE 公钥：kty (EC2)、crv (P-256)、alg (ES256) 及坐标长度完整校验
- DER 签名解析：完整长度校验、越界检查
- rpIdHash 常量时间比较
- 错误信息会返回给客户端用于排查；不暴露敏感内部状态（文件路径、密钥材料等）
- 注销仅接受 POST（防 CSRF）
- 会话：滑动过期（每次有效请求刷新 TTL），并有 `SESSION_MAX_LIFETIME` 绝对上限
- RP ID / Origin：从 nginx server 变量（`$host`、`$scheme`、`$http_host`）派生，反映实际访问域名以支持多域名；建议配 `default_server` 拒绝未知 Host；可通过 `RP_ID` / `ORIGIN` 常量覆盖
- 登录页 `next` 参数校验（仅允许相对路径，拒绝 `//evil.com`）

## 注意事项

- **必须 HTTPS**：WebAuthn 仅在安全上下文工作（`localhost` 除外）。生产环境请配置 TLS，确保反代正确传递 `Host` 与 `X-Forwarded-Proto`。
- 仅支持 **ES256（alg -7）** 与 **`none` attestation**，覆盖绝大多数平台认证器（Touch ID、Windows Hello、手机通行密钥、安全密钥等）。
- 不回写 `signCount`，对单用户自用场景安全性足够。
- 重置 / 重新注册：删除对应的 `<rpId>.json` 文件即可。
- 单用户模式：仅保存一个凭据，适合个人服务 / 后台保护场景。
