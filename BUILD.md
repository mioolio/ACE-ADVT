# 编译方法（BUILD）

本文给出三种构建方式：**一键脚本**、**手工分步**、**只用验收**。三种方式产出同一个文件，SHA-256 必须等于：

```
4c144c62acb297ce536f89caa9727ecd6aabc5d048a66a53eb9a937e51523ff8
```

---

## 0. 前置条件

| 组件 | 版本要求 | 说明 |
|---|---|---|
| Python | 3.10+（实测 3.14） | 流水线本体 |
| `capstone` | 5.x | 反汇编引擎 |
| `pefile` | 2023+ | PE 结构解析 |
| `ml64.exe` | MSVC 14.38+（实测 14.50 / 14.52） | **主力汇编器** |
| `nasm` | 2.15+（可选） | 备用汇编器 |
| Windows | 10/11 x64 | 路径与脚本按 Windows 编写 |

安装：

```powershell
pip install capstone pefile
```

`ml64.exe` 三种来源任选：

```text
1) Visual Studio 2022 / 2026 自带
   C:\Program Files\Microsoft Visual Studio\2022\*\VC\Tools\MSVC\<ver>\bin\Hostx64\x64\ml64.exe
2) EWDK 挂载镜像（推荐，自带完整 WDK）
   <ISO>\Program Files\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\<ver>\bin\Hostx64\x64\ml64.exe
3) 任意 MSVC Build Tools
```

`nasm.exe` 可选，仅备用工具链需要。

---

## 1. 准备目标文件

仓库**不包含** `ACE-ADVT.sys`。把它放到任意位置，然后用环境变量指向它：

```powershell
$env:ADVT_TARGET = 'D:\samples\ACE-ADVT.sys'
```

> 所有流水线脚本（`analyze.py` / `emit_masm.py` / `build_masm.py` / `mkheaders.py` / `gen_assets.py` / `verify.py`）都读这个变量；不设也能跑，但会回退到作者机器的路径。

自检：

```powershell
(Get-FileHash $env:ADVT_TARGET -Algorithm SHA256).Hash
# 应为 4C144C62ACB297CE536F89CAA9727ECD6AABC5D048A66A53EB9A937E51523FF8
```

---

## 2. 方式 A：一键构建（推荐）

```powershell
cd <repo>
.\build.ps1 -Fresh
```

`build.ps1` 依次执行 6 个阶段：

| 阶段 | 动作 | 产物 |
|---|---|---|
| 1 | 转录 DOS stub 与签名块 | `out/assets/dos_stub.bin`、`authenticode.bin` |
| 2 | 逐字段重建 PE 头并自校验 | `out/assets/headers.bin` |
| 3 | 函数边界恢复 + 递归下降 + 严格分区 | `out/model.json` |
| 4 | `ml64` 汇编 + COFF 重定位回填 + 切段 + 打包 + 收敛 | `build/ace_advt.obj`、`out/rebuild/*.sys` |
| 5 | 验收（哈希 / 校验和 / 签名 / 覆盖率） | `out/verification.json` |
| 6 | 汇总打印 | 终端输出 |

参数：

| 参数 | 作用 |
|---|---|
| `-Fresh` | 清空 `out/model.json` 与 `out/emit_overrides.json`，从零重建（约 4 轮收敛） |
| `-Nasm` | 改用 NASM 备用工具链（同一产物，助记符覆盖率 73%） |
| `-SkipVerify` | 跳过验收阶段 |

指定汇编器（可选）：

```powershell
$env:ML64 = 'F:\Program Files\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe'
.\build.ps1
```

---

## 3. 方式 B：手工分步

按顺序执行，任一步失败都不会产出错误文件（每步都有断言）。

### 3.1 资产转录

```powershell
python tools\gen_assets.py
# dos stub 176 B / authenticode 21168 B，两次 round-trip 必须 OK
```

### 3.2 头部重建

```powershell
python tools\mkheaders.py
# 期望：headers built 1024 bytes, reference 1024 / header bytes: identical to reference
```

### 3.3 分析（生成分区模型）

```powershell
python tools\analyze.py
# 期望：items=43363 insns=42528 pad_bytes=29597 data_items=248 labels=3902 funcs=1146
```

### 3.4 生成汇编源码

```powershell
python tools\emit_masm.py
# 期望：masm: 42493 mnemonic lines, 35 raw, 60174 data lines, ... 108013 source lines
```

### 3.5 汇编

```powershell
cd src\masm
<path>\ml64.exe /c /nologo /Fo..\..\build\ace_advt.obj /Fl..\..\build\ace_advt.lst ace_advt.asm
cd ..\..
```

第一轮会报少量语法/操作数错误（正常）；`build_masm.py` 会自动把这些行降级为 `db` 原始字节后重试。

### 3.6 打包与收敛

```powershell
python tools\build_masm.py
# 期望末尾：byte-identical image produced by ml64
```

### 3.7 验收

```powershell
python tools\verify.py
# identical True / differing bytes 0 / signature Valid
```

---

## 4. 方式 C：只用验收

已有 `out\rebuild\ACE-ADVT.rebuilt.sys` 时：

```powershell
python tools\verify.py
```

或直接对比：

```powershell
Get-FileHash .\out\rebuild\ACE-ADVT.rebuilt.sys -Algorithm SHA256
Get-AuthenticodeSignature .\out\rebuild\ACE-ADVT.rebuilt.sys | Format-List Status
```

---

## 5. 需要的外部工具（可选，用于交叉验证）

```powershell
# 头部与导入表
dumpbin /headers out\rebuild\ACE-ADVT.rebuilt.sys
dumpbin /imports out\rebuild\ACE-ADVT.rebuilt.sys

# 反汇编对照（NASM 附带）
ndisasm -b64 -o0x140001000 out\rebuild\ACE-ADVT.rebuilt.sys
```

---

## 6. 排错

| 现象 | 原因 | 处理 |
|---|---|---|
| `nasm/ml64 找不到` | 环境变量未设 | 设 `$env:ML64`；或把 `nasm` 加入 PATH |
| `header bytes: N differ` | `ADVT_TARGET` 指向的文件不是目标版本 | 核对 SHA-256 是否等于上面那串 |
| `flat size 0x... != expected` | 汇编器版本导致编码差异 | 正常，收敛循环会修正；若持续失败，换回 14.50/14.52 |
| `in-place mismatches: N` 反复不降 | `out/emit_overrides.json` 被手工改坏 | 删除该文件后重跑（`-Fresh`） |
| `nasm failed: ...` | 备用工具链语法差异 | 用默认 `ml64` 路线 |
| 收敛轮次很多 | 首次从零构建（无降级表） | 正常，4 轮内收敛 |

---

## 7. 产物校验清单

构建完成后应满足：

| 检查 | 期望 |
|---|---|
| 文件大小 | 1,168,048 |
| SHA-256 | `4c144c62…23ff8` |
| PE 校验和 | `0x124E80` |
| 入口点 | `0x46000` |
| 段数 | 8（`.text`/`.rdata`/`.data`/`.pdata`/`INIT`/`.rsrc`/`.reloc`/`.tvm0`） |
| Authenticode | Valid，主体 `Microsoft Windows Hardware Compatibility Publisher` |
| 助记符覆盖率 | 98.6%（41,934 / 42,528） |

---

## 8. 附：只用分析、不做重建

```powershell
$env:ADVT_TARGET = 'D:\samples\ACE-ADVT.sys'
python tools\analyze.py            # 分区模型 + out/listing/ACE-ADVT.txt
python tools\obfscan.py            # 975 处混淆跳转
python tools\ioctl_extract.py      # 控制码
python tools\cmdtable_full.py      # 50 条命令表
python tools\envelope.py           # 封套编解码自测
```
