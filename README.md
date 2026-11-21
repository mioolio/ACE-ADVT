# ACE-ADVT.sys — 逆向、字节保真重建与协议还原

对一个 1,168,048 字节、已由 **Microsoft WHCP 签名**的 x64 内核驱动（腾讯 ACE 的 `ACE-ADVT.sys`）做完整逆向：
**反汇编 → 重新汇编 → 逐字节重建（哈希与原文件相同）**，并把这个驱动的设备接口、协议、命令表、语义逐层还原成文档。

> 法律与用途声明见文末。仓库**不包含**任何 `.sys` 二进制（原文件与重建产物都不提供）。

---

## 1. 结果

| 项目 | 原文件 | 重建产物 | 判定 |
|---|---|---|---|
| 大小 | 1,168,048 | 1,168,048 | 是 |
| SHA-256 | `4c144c62acb297ce536f89caa9727ecd6aabc5d048a66a53eb9a937e51523ff8` | 同左 | 是 |
| MD5 | `a58a193204c35947eb6cca919e4484f6` | 同左 | 是 |
| 逐字节差异 | — | **0** | 是 |
| PE 校验和 | `0x124E80` | 重算 `0x124E80` | 是 |
| Authenticode | Valid（WHCP） | **Valid** | 是 |

重建覆盖率：**42,528 条指令中 41,934 条（98.6%）由助记符汇编通过**，594 条（1.4%）按原始字节回落。
两套不同版本的微软汇编器（VS 2022 `ml64 14.52` 与 EWDK 25H2 `ml64 14.50`）产出**完全相同**的字节流。

---

## 2. 逆向结论速览

| 层 | 结论 |
|---|---|
| 设备 | `\Device\ACE-ADVT` ↔ `\DosDevices\Global\ACE-ADVT`，`FILE_DEVICE_UNKNOWN (0x22)` |
| 派发 | CREATE / CLOSE / DEVICE_CONTROL / SHUTDOWN / Unload；单客户端 + 引用计数 + 全局门禁 |
| 门禁 | `loc_2090`：`g_KillSwitch(0x35650)==0` 才放行（一把闸关掉 CREATE + IOCTL） |
| 控制码 | `0x00222824` / `0x0022282C` / `0x00222834`（BUFFERED）+ 2 个 METHOD_NEITHER |
| 封套 | 588 字节：`+0x00` status / `+0x24` len≤0x200 / `+0x28` payload / `+0x228` key[8] / `+0x248` key_select |
| 编码 | XOR + 二次同余状态机（模 `0xDC6A2367`），可逆，见 `tools/envelope.py` |
| 命令 | `token = 0x63AE442D + k`（main）/ `0x623782AB + k`（aux），掩码 `0x907` |
| 命令表 | `.data 0x35020`：50 条 `{magic 0x013500CA, flag, token}` 记录，两个家族 |
| 语义 | main = 状态查询（每 token 谓词已还原）；aux = 缓冲区字节混合（22 条形态已分类） |
| 回包 | 48 字节：`{0x01343BEB, 0x30, status, ...}` |
| 保护段 | `.tvm0` 917,504 字节，975 处计算型跳转（`movabs+add+jmp`），111 个登记函数 |

完整推导见 `docs/01`–`docs/13`。

---

## 3. 仓库结构

```
├─ README.md               本文件
├─ BUILD.md                编译方法（一键 / 手工 / 排错）
├─ build.ps1               一键构建与验收
├─ docs/                   13 份报告
│  ├─ 01-PE结构.md          段表、目录、头部字段、双异常表
│  ├─ 02-反汇编与分区.md     函数边界恢复、代码/数据切分
│  ├─ 03-TVM保护段.md       .tvm0 结构、熵分布、混淆特征
│  ├─ 04-重建管线.md        平铺 RVA 空间、ml64 vs NASM 编码差异
│  ├─ 05-验证报告.md        验收数据与复现命令
│  ├─ 06-功能分析与接口.md   生命周期、门禁、IOCTL 面、能力清单
│  ├─ 07-绕过面分析.md      攻击面与失败模式
│  ├─ 08-信封协议与操作码表.md 封套、编码、token、派发链、回包签名
│  ├─ 09-命令表与分派全图.md  50 条记录、45 个比较站点、位图写入者
│  ├─ 10-aux命令语义.md     22 条命令逐条语义
│  ├─ 11-用户态组件与协议对接.md  ACE 套件 18 个组件与客户端映射
│  ├─ 12-ACE-BASE分析.md    基座驱动的能力字典
│  └─ 13-套件总报告.md      总报告与覆盖率矩阵
├─ tools/                  48 个 Python 工具（分析 / 反混淆 / 提取 / 构建 / 验收）
├─ src/
│  ├─ masm/ace_advt.asm     MASM 源码（108,011 行，主力工具链）
│  └─ asm/                  NASM 源码（parts/ 下 108 个部件，备用工具链）
└─ out/
   ├─ listing/ACE-ADVT.txt  全量反汇编清单（47,270 行）
   ├─ listing/token_chain.txt
   ├─ model.json            分区模型（43,363 单元 / 3,902 标签）
   └─ *.json               各阶段结构化产物
```

---

## 4. 快速开始

### 4.1 准备

1. **你自己的 `ACE-ADVT.sys` 副本**（仓库不提供），放到任意路径。
2. 工具链（见 `BUILD.md`）：
   - Python 3.10+，`pip install capstone pefile`
   - 微软 `ml64.exe`（VS 2022 或 EWDK 任选）
   - 可选：`nasm`（备用工具链）

### 4.2 指定目标文件

所有流水线脚本读取环境变量 `ADVT_TARGET`：

```powershell
$env:ADVT_TARGET = 'D:\samples\ACE-ADVT.sys'
```

### 4.3 一键构建

```powershell
cd ACE-ADVT
.\build.ps1 -Fresh        # 从零分析 + 汇编 + 重打包 + 验收（约 2 分钟）
```

输出：`out\rebuild\ACE-ADVT.rebuilt.sys`，脚本末行打印与原文件的 SHA-256 对比。

### 4.4 只做验收

```powershell
python tools\verify.py
```

期望输出：

```
identical   True  differing bytes 0
checksum    stored 0x124e80 recomputed 0x124e80
signature   Valid  CN=Microsoft Windows Hardware Compatibility Publisher ...
coverage    42528 instructions, 41934 from mnemonics (98.6%), 594 raw
```

---

## 5. 工具怎么用（常用）

```powershell
# 反汇编与清单
python tools\analyze.py                       # 重建分区模型 -> out/model.json
python tools\fn.py 1da0                       # 单函数带注释反汇编
python tools\xdis.py 6cf71 0x120              # 任意 RVA 反汇编

# 混淆与控制流
python tools\obfscan.py                       # 975 处计算型跳转定位
python tools\trace.py 61dc6 4000              # 常量传播追踪（还原真实控制流）

# 协议
python tools\ioctl_extract.py                 # 控制码常量
python tools\token_chain.py                   # 命令派发链
python tools\cmdtable_full.py                 # 50 条命令记录
python tools\envelope.py                      # 封套编解码器（含自测）

# 其他组件（需自行准备对应文件）
python tools\component_profile.py <bin>       # 导入/字符串/保护段画像
python tools\trace_any.py <bin> <rva>         # 任意 ACE 组件的控制流折叠
```

---

## 6. 方法论（为什么能做到字节保真）

1. **严格分区**：把 `.text`/`INIT` 切成 43,363 个字节单元，和 = 段大小，无空洞无重叠（`analyze.py` 断言）。
2. **平铺 RVA 空间**：`org 0x1000` 铺到 `0x129000`，段间虚拟空洞用 `db` 填充，使所有 RIP 相对引用与分支目标自然正确。
3. **单段汇编 + 迷你链接器**：MASM 单段输出只留 1,950 条 REL32 重定位，由 `tools/coff.py` 回填（不需要 link.exe）。
4. **字段级头部重建**：DOS/COFF/可选头/16 目录/段表逐字段写入，824 字节结构 + 填充 = 1024 字节，与原件零差异。
5. **差异收敛**：长度缺陷 → 编码缺陷 → 语法缺陷 三轮闭环，把不一致行降级为 `db <原始字节>`，偏移不变，单调收敛。

细节见 `docs/04-重建管线.md`。

---

## 7. 声明与边界

- 本仓库**只包含**文本（源码、脚本、文档、反汇编清单）与结构化 JSON，**不包含**任何可执行的 `.sys`/`.dll` 二进制，也不包含签名材料。
- 用途限定为**安全研究与教学**：理解商业反作弊驱动的接口设计、混淆手法与完整性保护机制；所有分析与重建均针对**自有副本**进行。
- 重建产物会保留原始厂商签名（因为字节相同），因此**不得用于分发或绕过任何软件的服务条款**；作者不对任何滥用负责。
- 商标与产品名归其所有者。

---

## 8. 许可

代码与文档采用仓库内 `LICENSE` 所载许可。
