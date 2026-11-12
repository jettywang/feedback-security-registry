# python-registry 时间证据评审（安全事件时间线）

本目录交付一套**不合并时间来源**的注册表时间证据后端、可复跑样本与输出契约。
核心原则：每个时间字段按其在 Windows 注册表格式中的真实含义独立报告，保留原始
整数、字节位置、解释结果与不确定原因；**不产生统一的“事件发生时间”，也不从日志
序号推导墙钟时刻**。

## 1. 四类时间/顺序字段的真实语义

所有结论均可在仓库源码与下方字节位置处复核。

### 1.1 REGF 基块头（主 hive 与 .LOG1/.LOG2 共用同一头部布局）
| 字段 | 字节偏移 | 源码接口 | 真正表示什么 | 缺失/失真点 |
|---|---|---|---|---|
| `hive_sequence1` | `0x04` | `REGFBlock.hive_sequence1()` | 写主文件**前**自增的事务计数器 | 纯计数器，无时间分量；不可换算成时刻 |
| `hive_sequence2` | `0x08` | `REGFBlock.hive_sequence2()` | 主文件一次写入**完成后**置成与 seq1 相同 | seq1≠seq2 表示更新中途崩溃，磁盘数据滞后 |
| 修改时间 FILETIME | `0x0C` | `REGFBlock.modification_timestamp()` | 该 hive 映像**整体最后一次 flush 到磁盘**的时间 | 全文件只有一个，非逐键；事务日志头常原样快照此值导致三处相同；`RegistryLog` 恢复只重写 seq/hbins_size/flags/checksum，**不更新**它 |
| 重组时间 FILETIME | `0xA8` | `REGFBlock.reorganized_timestamp()` |  hive 重组（碎片整理）时间，Win8 起使用 | 库文档明确：Win8 之前该字段是垃圾值 |

要点（实测 `testing/reg_samples/new_log_1`）：`SYSTEM`、`SYSTEM.LOG1`、
`SYSTEM.LOG2` 三个文件 `0x0C` 的原始 FILETIME 完全相同
（`130216567421081762` → 2013-08-22 14:52:22.108176）。这证明日志头只快照主文件
头，**日志本身不携带其生成时刻**。

### 1.2 键（NK 记录）最后写入时间
- 位置：NK 记录内 `0x04` 的 8 字节 FILETIME；记录起始由 `NKRecord.offset()` 给出，
  因此文件绝对偏移 = `nk.offset() + 0x4`。接口：`RegistryKey.timestamp()` /
  `NKRecord.timestamp()`（`Registry/RegistryParse.py:1517`）。
- 真正含义：配置管理器在该键、其值或安全描述符被创建/修改/写入时更新的**键级**时间。
- 失真点：
  - 粒度只到“键”。标准 hive 的值（VK）**没有**独立时间戳；只改值会更新父键时间，
    但无法指出是哪一个值、也无法给单次值变更单独定时（见 `value_only_change` 场景）。
  - 取自主机时钟，时钟回拨/偏移/篡改无法仅凭该字段识别（见 `clock_rollback`）。
  - 库不做合法性校验：`0` 被静默解释成 1601-01-01；超出 `datetime` 范围的值直接抛
    `OverflowError`（见 `invalid_filetime`）。

### 1.3 事务日志序号（REGF seq 与 HvLE `0x0C`）
- HvLE 头布局：签名 `HvLE`(`0x00`)、大小(`0x04`)、hive flags(`0x08`)、
  **序号(`0x0C`)**、hbins_size(`0x10`)、脏页数(`0x14`)、Hash-1(`0x18`)、Hash-2(`0x20`)。
  接口：`HvLEBlock.sequence()`（`Registry/RegistryParse.py:1862`）。
- 整个 HvLE 结构**没有任何 FILETIME 字段**。序号只用于：判断日志是否匹配主文件、
  给脏页条目排序、检测序号回绕（`is_starting_log` 用 `c_uint32` 处理 32 位回绕）。
- 因此序号只能建立**先后顺序**，本工具在 `sequence_state.wallclock_inference` 恒为
  `null`，显式拒绝把序号转成墙钟时间。

### 1.4 库中的“值时间戳”接口
- 高层 `RegistryValue.timestamp()` → `VKRecord.timestamp()`
  （`Registry/RegistryParse.py:995`）。
- `VKRecord.has_timestamp()` 的判定（同文件 `:989`）：值类型含 `0x100`
  AppContainer 复合标志 **且** 数据长度 ≥ 8；时间取 `raw_data()` 末尾 8 字节。
- 适用范围极窄：仅 AppContainer `settings.dat` 复合值。普通
  SYSTEM/SOFTWARE/NTUSER.DAT 值调用 `timestamp()` 会抛 `ValueError`。
  见 `appcontainer_value_timestamp` 场景的正反对比。

## 2. FILETIME 的有效性分层（观察事实 vs 推测）

`reg_evidence/extract.py::interpret_filetime` 永不抛异常，输出四类：

| kind | 条件 | 调查含义 |
|---|---|---|
| `valid` | 可渲染且 ≥ 1980-01-01 | 结构与合理性都通过，仍受主机时钟约束 |
| `implausible` | 可渲染但早于 1980 | 保留解码值，但标注不可信（回拨/损坏/未初始化） |
| `zero_epoch` | 原始值为 0 | 库渲染成 1601-01-01，通常表示“从未写入”，不是真实事件 |
| `unrenderable` | 超出 datetime 范围 | 库会抛 `OverflowError`；保留原始字节，UTC 为 `null` |

每条记录都同时给出 `raw_uint64`/`raw_hex`（观察事实）、`interpreted_utc`
（解释）、`uncertainty_reasons`（不确定原因），调查人员可据此区分事实与推断。

## 3. 复跑方法

```bash
# 仓库自带虚拟环境；无需联网
.venv/bin/python forensic_timeline/run_demo.py
```

产物：
- `forensic_timeline/samples/`：受控微型 hive 与一个可被库校验通过的 `.LOG1`。
- `forensic_timeline/output/timeline_evidence_report.json`：五类场景的分离证据报告。
- `forensic_timeline/output/recovery_recovered.hive`：内存恢复后的 hive（不污染原始样本）。
- `forensic_timeline/output_contract.schema.json`：后端输出契约（JSON Schema）。

另可对真实样本运行同一后端：
```bash
.venv/bin/python - <<'PY'
import sys; sys.path.insert(0,"forensic_timeline")
from reg_evidence.extract import extract_all
import json; print(json.dumps(extract_all("testing/reg_samples/new_log_1/SYSTEM"), indent=1)[:1200])
PY
```

## 4. 场景与“恢复前→恢复后”字段变化

| 场景 | 观察到的事实 | 不能下的结论 |
|---|---|---|
| `clock_rollback` | B（seq 8）采集晚于 A（seq 7），但 NK FILETIME 从 2019 变成 1970，被标 `implausible` | 不能说事件发生在 1970 |
| `invalid_filetime` | 子键 NK 原始值 `0xFFFFFFFFFFFFFFFF`，`timestamp()` 抛 `OverflowError` | 不能丢弃该字节或强行赋一个时间 |
| `value_only_change` | `ConfigFlag` 7→9，但父键 NK FILETIME 字节完全相同，值时间戳接口 `available=false` | 不能给这次值变更确认独立时间 |
| `appcontainer_value_timestamp` | 仅 0x100 复合值的末尾 8 字节可解析出值时间 | 不能外推到普通 hive 的值 |
| `transaction_log_recovery` | 脏主文件 seq 6/5；HvLE(seq 6，无时间字段) 脏页把子键 NK 时间从 2019 改成 2020；恢复后 seq 6/6、`recover_data=false`，而头部 `0x0C` 仍是 2019 | 不能从序号 6 推导墙钟时刻；不能把头部时间当作恢复发生时间 |

真实大样本佐证（`testing/reg_samples/new_log_1`，双日志完整恢复）：键数
19811→19908，198 个键变化（含新增键与 NK 时间被脏页替换），但 REGF 头 `0x0C`
在恢复前后字节不变（始终 `130216567421081762`）。

## 5. 源码与字节位置索引

- `Registry/RegistryParse.py:99` `parse_timestamp` / `:119` `parse_windows_timestamp`（纯算术，无范围校验）
- `Registry/RegistryParse.py:331-362` seq1/seq2、`0x0C` 修改时间、`0xA8` 重组时间
- `Registry/RegistryParse.py:486-499` `recovery_required`（checksum/seq 判定恢复路径）
- `Registry/RegistryParse.py:989-1002` 值时间戳接口与 `0x100` 判定
- `Registry/RegistryParse.py:1517` NK `timestamp()`（记录内 `0x04`）
- `Registry/RegistryParse.py:1740-1900` HvLE 头、Marvin32 双哈希、`0x0C` 序号
- `Registry/RegistryLog.py:132-153` `update_regf_header`（只改 seq/size/flags/checksum）
- `Registry/RegistryLog.py:162-203` `recover_hive` / `recover_hive_continue`
