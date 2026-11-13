# Bandizip 7.47 离线注册（Professional）破解

| 项目 | 值 |
|---|---|
| 目标 | `D:\Program Files\Bandizip\Bandizip.exe` |
| 版本 | 7.47.0.1 / BuildNo 71912 |
| 结果 | 标题变为 **Bandizip (Professional)**，广告子进程不再启动，Pro 功能解锁 |
| 原版 SHA256 | `2D733A26500A8CFF7DB04291C396B3D48E9D7275753E2A06BF3564C9F9591DC8` |
| 补丁版 SHA256 | `E0D8170B17822AB611E87E7C021B83E22EAE6564C75B9E2BF8CFCCDB4B53D6AA` |

---

## 1. 一键使用（推荐）

双击 **`BandizipPatcher.exe`**（会请求管理员权限）：

1. 启动后自动定位安装目录（注册表 `HKLM\SOFTWARE\Bandizip\ProgramFolder` → App Paths → 运行中的进程 → `%ProgramFiles%\Bandizip`），找不到可以用「浏览…」或直接把安装文件夹拖进窗口；
2. 状态栏会显示 `版本 7.47.0.1 状态：官方原版，可以打补丁`；
3. 点 **一键打补丁** → 确认 → 自动结束 Bandizip、生成 `Bandizip.exe.bak`、写入补丁、校验哈希、关闭自动更新、并启动 Bandizip；
4. 需要恢复原版就点 **还原官方原版**（用 `.bak` 覆盖）。

界面已完成的状态检测：官方原版 / 已破解 / 未识别版本（只对 7.47.0.1 生效，避免误改其它版本）。

### 命令行 / 批处理

```
BandizipPatcher.exe                      启动图形界面
BandizipPatcher.exe "D:\Program Files\Bandizip" /patch  /quiet
BandizipPatcher.exe "D:\Program Files\Bandizip" /restore /quiet
BandizipPatcher.exe /patch /quiet         不带目录 = 自动检测
```

- `/silent` 结束后弹提示框（60 秒自动关闭），`/quiet` 完全不弹窗，用退出码表示结果（0 成功 / 1 失败）；
- 也可以把文件夹或 `Bandizip.exe` 直接拖到 exe 图标上。

---

## 2. 授权机制（逆向结论）

| RVA | 内容 |
|---|---|
| `0x2A6AB0` | `HKLM\SOFTWARE\$app$\Edition` |
| `0x2A6AE8` | `SOFTWARE\$app$\l`（HKCU 下的 license 子键） |
| `0x2A6B0C…0x2A6B50` | `l` `k` `P` `m` `t` `h` `g` `c` `r` `u` 等 license 字段名 |
| `0x2A6B28/0x2A6B30/0x2A6B38/0x2A6B40` | `ENT` / `PRV` / `PRO` / `ok` |
| `0x2A6B60`、`0x2A6BC0` | 在线校验 `email=…&productKey=…`、`checkProductKey.php` |
| `0xD0370` | `LoadLicense()`：打开 `HKCU\Software\Bandizip\l`、解析 license、填充 app 对象 |
| `0x1316C0` | **edition 映射函数**（补丁目标） |
| `0x130F90` | edition 数值 → 显示名（Standard / Professional / Enterprise） |
| `0xCF570` / `0x131030` | 两个全局单例对象的 getter |

`LoadLicense()` 解析完成后，全局 app 对象上是：

- `app+0x60` = `L"ok"` ⇒ license 有效
- `app+0x28` = `L"PRO"` / `L"ENT"` ⇒ 版本
- `app+0x50` = 32 字符 license code，`app+0x58` = 时间戳

`0x1316C0` 读这两个字符串，位混淆后写入单例 `+0x120`：

```
out = ((v >> 1) & 0x55555555) | ((v & 0xd5555555) << 1)

PRO -> v=0x3D4  -> out=1000   -> "Professional"
ENT -> v=0x1B20 -> out=10000  -> "Enterprise"
其它 -> v=0x98  -> out=100    -> "Standard"
```

窗口标题、广告开关、Pro 功能开关都读 `+0x120`。未注册时 license 字段为空，`HKLM\...\Edition = STD`，`+0x120` 保持 `0x98` ⇒ 标题 `Bandizip (Standard)`。

---

## 3. 补丁内容

把 `0x1316C0` 函数开头 78 字节替换为（函数原长 `0x157`，空间足够）：

```asm
push rbx
sub  rsp, 0x20                  ; x64 shadow space（漏掉会崩在 assign 内部）
mov  rbx, rcx                   ; this
call 0xCF570                    ; 取 app 单例
lea  rcx, [rax+0x60]
lea  rdx, [rip+0x2A6B40]        ; L"ok"
mov  r8d, 2
call 0x18F50                    ; std::wstring::assign
call 0xCF570
lea  rcx, [rax+0x28]
lea  rdx, [rip+0x2A6B38]        ; L"PRO"
mov  r8d, 3
call 0x18F50
mov  dword [rbx+0x120], 0x3D4   ; Professional
add  rsp, 0x20
pop  rbx
ret
```

要点：

- 复用程序自身的 `std::wstring::assign`（`0x18F50`），不手工拼 `std::wstring` 布局；
- `sub rsp,0x20` 必须保留（Windows x64 调用约定的 32 字节 shadow space）；
- 只改字节、不加节、不改 PE 头，文件大小不变，RIP 相对寻址与 ASLR 无关；
- 数字签名失效，不影响运行。

运行时验证（Frida 读内存）：

```
app+0x28 = "PRO"
app+0x50 = "00000000000000000000000000000000"
app+0x58 = "1793344742"
app+0x60 = "ok"
单例+0x120 = 980  (0x3D4 -> 1000 -> Professional)
```

---

## 4. 文件清单

```
BandizipPatcher.exe     图形化一键补丁器（.NET Framework 4.x，需管理员）
apply_patch.py          Python 版补丁脚本（apply / --restore）
src\BandizipPatcher.cs  补丁器源码（C# 5）
src\app.manifest        需要管理员权限的清单
ui.png                  界面截图
README.md               本文档
```

自行编译：

```
csc /nologo /target:winexe /platform:x64 /codepage:65001 ^
    /win32manifest:app.manifest /optimize+ /out:BandizipPatcher.exe BandizipPatcher.cs
```

---

## 5. 注意事项

- 覆盖安装 / 自动更新会把官方 exe 还原，需要重新打一次补丁（本工具默认帮你把 `HKCU\Software\Bandizip\update` 置 0）；
- `Bandizip.exe.bak` 是本工具创建的原始备份，`还原官方原版` 依赖它，别删；
- 只支持 7.47.0.1 (build 71912)；其它版本会被判定为「未识别」，不会乱改；
- `bz.exe`（命令行）、`Bandiview`、`Uninstall.exe` 等组件不受影响；
- 签名失效 + 代码段被修改，可能被杀软/主动防御报为可疑，加信任即可。
