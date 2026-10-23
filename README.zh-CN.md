<p align="center"><a href="README.md">English</a> · <b>简体中文</b> · <a href="README.tr.md">Türkçe</a> · <a href="README.ar.md">العربية</a></p>
<p align="center">视频教程：<a href="https://www.youtube.com/@pwfauth">youtube.com/@pwfauth</a></p>

# PWF Auth 原生 C++ 桌面示例

这是一个用原生 C++17 编写的 Windows 桌面客户端（英文界面），许可证流程与 C# 和 Python 示例完全一致：

- 加密的许可证登录与 HWID 绑定；
- 实时心跳，由服务器决定何时终止会话（即远程停用（kill switch））；
- 将许可证迁移到新电脑；
- 完整的许可证概要、展平后的响应字段表以及原始 JSON；
- 显式退出登录，释放服务器上的会话

![登录后的仪表板页面](docs/dashboard.png)

PWF Auth 官网没有提供 C++ 包，因此本示例直接用 Windows API 实现了文档中的协议：

- 用 WinHTTP 处理 HTTPS；
- 用 Windows CNG 实现 SHA-256、AES-256-CBC、HMAC-SHA256 以及安全的 IV 生成；
- 用 Windows 加密配置中的 `MachineGuid` 作为硬件 ID（HWID），与 .NET、Python 和 Node 包使用的是同一个值，因此一台电脑只算一台设备；
- `nlohmann-json`，通过随附的 vcpkg 清单自动还原

`PwfClient.h` / `PwfClient.cpp` 是可复用的部分：直接复制到你自己的应用中即可

## 功能演示

- **用许可证密钥登录。** `Login` 会把密钥绑定到当前电脑。随后仪表板页面会显示密钥的状态、类型、到期时间和剩余时间、售出该密钥的人，以及响应中的所有字段
- **远程停用。** 登录后会运行 `StartHeartbeat`。当你在后台封禁、暂停或重置该密钥，或者密钥到期时，客户端会调用会话结束回调，应用随即返回登录页并显示原因
  - 只有加密的响应才算作有效应答。连续三次心跳都没有收到有效应答时，会话会以 `NETWORK_LOST` 结束；如果服务器一直拒绝这台电脑的时钟，则以 `CLOCK_SKEW` 结束。因此，修改电脑时钟并不能让已被封禁的密钥继续运行
  - HTTP 429 有单独且更宽松的额度（10 次心跳），因为共享 IP 被限流是正常现象
- **时钟错误会自动修正。** 当电脑时钟偏差超过五分钟导致服务器拒绝请求时，服务器会返回自己的时间。客户端按差值调整时间戳，然后重新发送一次请求
- **将许可证迁移到新电脑。** 当密钥已绑定到另一台电脑（`HWID_MISMATCH` 或 `DEVICE_LIMIT`）时，登录页会提供 **Move this license to this PC** 选项。它会调用 `ResetHardwareId`，然后重新登录。两次迁移之间受开发者设置的冷却时间限制（默认 12 小时）

  ![Move this license to this PC](docs/move-license.png)

- **独立的服务器身份验证。** 每个响应都必须带有有效的服务器 RSA 签名，并且该签名与本次请求严格绑定。仅知道应用密钥（app secret）无法伪造该签名。未签名、被篡改或被重放的响应会在解析之前被拒绝
- **清晰的错误提示**：无网络连接（`PwfNetworkError`）、应用密钥被拒绝（HTTP 401），以及响应不是 API 的 JSON（`PwfHttpError`）

## 配置

替换 `main.cpp` 顶部附近的占位符：

```cpp
constexpr char APP_SECRET[] = "YOUR_64_CHARACTER_APP_SECRET";
```

所有构建配置都禁用了运行时环境变量覆盖。客户端只使用 `https://pwfauth.com`，拒绝通过构造函数传入的其他源，也不跟随任何重定向。请在构建时配置应用密钥，切勿把真实密钥提交到仓库

`ServerPublicKey.h` 中包含与服务器部署相匹配的固定（pinned）公钥，用于验证签名。把 PwfClient 复制到其他项目时，请一并引入它和 `ProductionPolicy.h`。与之匹配的服务器签名功能已部署在 pwfauth.com 上。签名私钥只保存在服务器上，绝不会随客户端分发

## 构建与运行

在 Visual Studio 中打开 `PWFAuthCpp.slnx`，选择 `Debug | x64`，然后按 `F5`。首次构建时，项目会在本地还原 vcpkg 依赖

可执行文件的输出路径：

```text
bin\Debug\PWFAuthCpp.exe
```

应用在显示登录窗口之前，会先离线运行一次 AES/HMAC 往返自检。真正登录仍需要应用密钥和有效的许可证密钥

## 网络被屏蔽：2026-10-13（1.4）

部分网络会屏蔽 `pwfauth.com` 这个域名（阿联酋的 Etisalat 会返回“域名不存在”），导致应用在不使用 VPN 的情况下无法连接许可证服务器。现在，当 `pwfauth.com` 完全没有响应时，`PwfClient` 会改用同一服务器的第二个域名 `https://pwfauth.net`：

- 仅在可以确定请求从未到达任何服务器时（域名无法解析、无法建立连接、安全连接被拒绝），或者在本客户端尚未收到过任何响应就发生超时的情况下才会切换；
- 只要收到了响应，即使是错误响应，也绝不会转发到另一个域名；
- 一旦 `pwfauth.net` 有了响应，客户端会一直使用它，直到程序关闭；
- 两个域名都固定写在 `ProductionPolicy.h` 中，服务器、签名密钥以及所有响应校验都完全相同

把新的 `PwfClient.cpp`、`PwfClient.h` 和 `ProductionPolicy.h` 复制到你的应用中并重新构建即可，其他无需改动

## 连接中断：2026-10-12（1.3.1）

当请求完全没有收到响应时（通常是连接在途中被关闭，即 Windows 错误 10054 或 WinHTTP 错误 12030），`PwfClient` 现在会在 300 ms 后通过新连接再发送一次相同的请求。以前这种调用会直接失败，抛出 `PwfNetworkError`“Cannot reach the license server”。只有这种情况会重试：已收到的响应（包括错误响应）、读取过程中中断的响应以及超时，都不会重复发送。其他方面没有变化：签名密钥和函数都保持不变

## 客户账号：2026-10-12（1.3）

除了许可证密钥之外，你的客户还可以拥有用户名加密码的账号（需要在后台为该应用开启客户账号）。`PwfClient` 新增了以下函数：

| 函数 | 作用 |
|---|---|
| `RegisterAccount(username, password, email)` | 创建账号 |
| `RegisterAccountWithKey(username, password, key, email)` | 创建一个获得密钥时长的账号（该密钥随即被用掉） |
| `AccountLogin(username, password)` | 在本机登录该账号；之后像 `Login` 一样启动心跳 |
| `ChangeAccountPassword(username, current, new)` | 修改密码（该账号的所有会话都会被登出） |
| `RedeemKey(username, password, key)` / `RedeemKey(key)` | 将密钥时长添加到账号（第二种写法使用当前已登录的会话） |

```cpp
PwfClient client(appSecret);

PwfResponse made = client.RegisterAccount("alice", "a-strong-password", "alice@example.com");
if (!made.Success() && made.ErrorCode() != "USERNAME_EXISTS")
    return ShowError(made.Message());          // written for the customer

PwfResponse login = client.AccountLogin("alice", "a-strong-password");
if (!login.Success())
    return ShowError(login.Message());         // INVALID_CREDENTIALS, BANNED, EXPIRED, ...

client.SetSessionEndedCallback([](const std::string& code, const std::string& message) {
    // banned, paused, expired, signed out from the panel: close your app here
});
client.StartHeartbeat();

// later: a key bought from a reseller adds its time to the account
PwfResponse added = client.RedeemKey("XXXXX-XXXXX-XXXXX-XXXXX");
```

把新的 `PwfClient.h` 和 `PwfClient.cpp` 复制到你的项目中；`ServerPublicKey.h` 和 `ProductionPolicy.h` 与 1.2 版相同，无需更换

## 新的服务器密钥：2026-10-11（1.2）

PWF Auth 现在使用新密钥为响应签名。请把新的 `ServerPublicKey.h`（以及 `PwfClient.cpp`）复制到你的项目中并重新构建：使用旧密钥构建的程序会拒绝当前服务器的所有响应

## 安全更新：2026-10-09

请重新构建并重新分发嵌入了旧版本示例代码的应用。已有的 EXE 不会自动获得这项保护。无论 Debug 还是 Release，都不再支持通过 PWFAUTH_BASE_URL 和 PWFAUTH_SECRET 环境变量覆盖配置。可复用客户端只接受正式环境的 HTTPS 源，并禁用重定向

每个 HTTP 请求都会附带一个全新的 256 位 nonce。在解析响应之前，客户端会用固定的公钥验证 RSA-3072 / PKCS#1 v1.5 / SHA-256 签名。签名内容绑定了 nonce、请求方法、端点、请求体哈希、响应状态码和响应体哈希。原有的 AES/HMAC 校验依然保留。未签名的代理或 CDN 错误同样会被拒绝，可能表现为验证失败

验证工作包括：Release x64 编译、PHP 与 Windows CNG 的互操作、拒绝被篡改和被重放的响应，以及在生产环境中通过 HTTPS 使用有效和无效的合成许可证进行真实登录、心跳和退出登录。原客户端会接受来自所报告的本地模拟器的无效密钥；更新后的客户端忽略了模拟器设置的环境变量覆盖，也没有向其发送任何请求

此次更新堵住了所报告的重定向/模拟攻击路径。但它无法保证能抵御在自己控制的电脑上直接修改可执行文件的攻击者
