```Mermaid
sequenceDiagram
    autonumber
    participant C as 客户端 mstsc
    participant W as Winlogon / LogonUI
    participant CP as 自定义 Credential Provider DLL
    participant REG as 注册表 / reginfo.ini
    participant RA as RemoteAuthentication.exe
    participant API as 认证服务端
    participant U as 用户手机 / 微信

    C->>W: 发起 RDP 连接，完成基础连接建立
    W->>CP: 枚举并加载 Credential Provider
    Note right of CP: DLL 内含 2fa_phone / 2fa_pwd / 2fa_wechat<br/>以及 Submit / Checkbox / Combobox / CommandLink / tab2 / BTN2
    CP->>REG: 读取本地配置
    Note right of REG: SOFTWARE\\dexunyun.com\\DexunGuard<br/>hostuuid / serveraddr / ClientIp / r_ip_range / r_time_range / r_region<br/>以及 reginfo.ini 路径
    CP-->>RA: 可能拉起/协同 RemoteAuthentication.exe
    Note right of RA: DLL 中出现 %s\\bin64\\RemoteAuthentication.exe

    W->>CP: 展示登录 Tile / 二次认证 UI
    U->>CP: 选择认证方式
    alt 手机认证 2fa_phone
        U->>CP: 输入手机号/请求验证码
        CP->>API: POST /api/host_instance/getSSHLoginCode
        Note right of API: JSON 包含 {"phone": "...", "host_uuid": "..."}
        API-->>U: 下发短信验证码
        U->>CP: 输入短信验证码并提交
        CP->>API: 校验验证码（具体路径未直接暴露）
        API-->>CP: 返回成功/失败
        CP->>API: POST /api/host_instance/postSSHLoginLog
        Note right of API: desc 里出现 Mobile login failed/successful
    else 二次密码认证 2fa_pwd / SPWD
        U->>CP: 输入二次密码
        CP->>REG: 读取策略/本地参数
        CP->>API: 发起二次密码校验请求
        API-->>CP: 返回成功/失败
        CP->>API: POST /api/host_instance/postSSHLoginLog
        Note right of API: desc 里出现 Second Password login failed/successful
    else 微信认证 2fa_wechat
        U->>CP: 选择微信认证
        CP->>API: GET wechat_login_oauth_bmp?host_uuid=...
        API-->>CP: 返回二维码 BMP
        Note right of CP: 保存到 C:\\ProgramData\\DexunGuard\\testhttp.bmp / failed.bmp / nomo.bmp
        CP->>U: 展示二维码
        U->>API: 手机微信扫码并完成授权
        API-->>CP: 通过 wechat_login_oauth_callback?ticket=... 回传结果
        CP->>API: POST /api/host_instance/postSSHLoginLog
    end

    alt 二次认证通过
        CP-->>W: 返回认证通过 / 放行
        W-->>C: 进入会话选择或直接进入桌面
    else 二次认证失败
        CP-->>W: 返回失败，不放行
        W-->>C: 停留在登录前界面 / 提示失败
    end
```