# RDP 二次认证当前主链路时序图

下图只描述当前项目已经落地或已经按当前代码结构预留好的主链路，重点反映 `credential_provider`、`remote_auth`、`auth_ipc` 和 `auth_api` 的职责边界。

```mermaid
sequenceDiagram
    autonumber
    participant C as RDP 客户端 mstsc
    participant W as Winlogon / LogonUI
    participant CP as credential_provider.dll
    participant RA as remote_auth.exe
    participant CFG as 加密配置 / helper 内存态
    participant API as 认证服务端
    participant U as 用户

    C->>W: 发起 RDP / NLA 登录
    W->>CP: 枚举 Provider 并回调 UpdateRemoteCredential / SetSerialization
    Note right of CP: CP 只接收 inbound serialization、展示 UI、发短超时 IPC。<br/>不直接读复杂配置，不直接发网络请求。
    CP->>RA: get_policy_snapshot(session_id)
    RA->>CFG: 解密配置并聚合策略
    RA-->>CP: 返回脱敏策略快照<br/>auth methods / masked phone choices / timeout
    W->>CP: 展示二次认证 Tile

    alt 短信验证码
        U->>CP: 选择脱敏手机号并点击发送验证码
        CP->>RA: send_sms(session_id, phone_choice_id, phone_choices_version)
        Note right of CP: IPC 只传 phone_choice_id 和 version，<br/>不传完整手机号。
        RA->>CFG: 解析 phone_choice_id -> 完整手机号
        alt 已接真实 API
            RA->>API: POST send_sms(phone, host context)
            API-->>RA: SmsChallenge(challenge_token, expires_in, resend_after)
            RA->>CFG: 仅在 helper 内存保存 challenge_token / TTL / status
        else 占位服务地址
            RA->>RA: 使用 mock challenge fallback
        end
        RA-->>CP: 返回发送结果
        Note right of CP: 首次发送成功后，MFA 页面等待窗口重置为 300 秒。<br/>但没有 inbound serialization 仍然不能放行。

        U->>CP: 输入短信验证码并提交
        CP->>RA: verify_sms(session_id, phone_choice_id, phone_choices_version, code)
        RA->>CFG: 校验 session、choice version 和 challenge 状态
        alt 已接真实 API
            RA->>API: POST verify_sms(challenge_token, code)
            API-->>RA: 返回验证结果
        else 占位服务地址
            RA->>RA: 使用 mock verify fallback
        end
        RA-->>CP: 返回验证结果
    else 二次密码
        U->>CP: 输入二次密码并提交
        CP->>RA: verify_second_password(session_id, second_password)
        alt 已接真实 API
            RA->>API: POST verify_second_password(host context, second_password)
            API-->>RA: 返回验证结果
        else 占位服务地址
            RA->>RA: 使用 mock-password fallback
        end
        RA-->>CP: 返回验证结果
    end

    alt 二次认证成功且存在 inbound serialization
        CP->>CP: 重新打包 Windows 登录 serialization
        CP-->>W: GetSerialization 返回 packed credential
        W-->>C: 继续 Windows 登录链路
    else 二次认证失败 / helper 异常 / 无 inbound serialization
        CP-->>W: fail closed，不返回可放行凭证
        W-->>C: 保持在登录前界面或断开当前 RDP 会话
    end
```

## 图外约束

- `credential_provider` 只保留轻量内存态，不保存完整手机号、验证码、密码、`challenge_token` 或 serialization 内容。
- `remote_auth` 持有手机号明文映射、session 状态、challenge 状态和 API 调用逻辑；敏感值不进入 IPC、日志或错误文本。
- `phone_choice_id` 与 `phone_choices_version` 只用于 helper 内部选择和防错配，组合框中只展示脱敏手机号。
- 当前微信扫码仍是后续任务，不在这张主链路图里展示，避免把未接通逻辑画成已完成能力。
