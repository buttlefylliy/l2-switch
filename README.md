# l2-switch

二层以太网交换的行为仿真与配置框架。

## 约束

* 仅使用 Python 标准库，不联网，不依赖第三方包。
* 行为必须确定：相同输入多次运行产生逐字节一致的输出；时间相关行为由显式注入的时钟驱动，不读墙上时钟。
* 所有结论可由公开接口与落盘产物独立验收。

## 公开入口

* 入口文件：`l2_switch.py` 
* 命令行：`python l2_switch.py --help` 
* 使用说明与行为契约以本文件为准；入口的签名、键序与既有语义在迭代中保持兼容。

### `ports`

读取 UTF-8 JSON 配置，校验物理端口，向标准输出写入单行确定性快照。

### `frame`

读取 UTF-8 JSON 单帧描述，做离线合法性判定 (runt/oversize/bad_fcs 等)，
向标准输出写入单行 JSON 判定结果；不涉及学习、查表和转发。

### `forward`

从一个 UTF-8 JSON 场景文件读取现有 `ports` 配置与按顺序排列的 `events`；
每个事件包含 `ingress_port` 与 `frame` 子命令接受的完整帧描述。
场景可选顶层 `static_table` 数组提供静态 MAC 表项，每项只含 `vid`、`mac`、
`port` 三个字段：`vid` 为 0 到 4094 的整数；`mac` 为非零单播 MAC 地址，
规范化为小写；`port` 必须引用场景 `ports` 中的端口名。同一 `vid` 与规范化
`mac` 组合只允许出现一次，静态表项总数不超过 10000。字段缺失、额外字段、
类型或取值错误以及重复组合均以 ConfigError (退出码 3) 失败并给出输入路径；
`port` 引用不存在的端口时以 StateError (退出码 5) 失败。静态表项从场景开始
到结束始终有效：不参与老化，不被源 MAC 学习、刷新或迁移覆盖；合法帧的单播
目的查表优先命中静态项——命中其他可转发端口时只向该端口转发，命中入端口时
`filtered` 且无出口，目标端口 down 或 blocking 时 `dropped` 且无出口，均不
改按未知单播泛洪；源 MAC 在某 VLAN 已有静态项时，该键不创建也不更新动态项
(帧合法性、目的查表与计数不受影响)；广播、组播与未命中单播的泛洪不受影响。
提供非空 `static_table` 时，成功输出在 `dynamic_table` 后追加 `static_table`
快照 (只含 `vid`、`mac`、`port`，按 `vid` 数值升序再按 `mac` 码点升序)，
`counters` 位于其后；空数组等价于省略，输出与基线逐字节一致。
场景可选顶层 `aging_time_ms`（1 到 9223372036854775807 的整数）启用动态
MAC 老化；启用后每个事件必须包含 `time_ms`（0 到 9223372036854775807 的
整数），并按事件顺序单调不减。未提供 `aging_time_ms` 的场景不得出现
`time_ms`。
先校验完整场景，再按事件顺序处理：

* 未标记帧归入 VLAN 1；带标签帧按 `vid` 隔离，`vid` 0 也是独立域。
* 仅合法、未被丢弃且入端口 `can_learn` 为真的帧，按 (VLAN, 规范化小写单播源 MAC)
  学习；同一键从另一端口出现时迁移到新端口。
* 广播、组播与未命中单播泛洪到除入端口外所有 `can_forward` 为真的端口
  (按端口 name 的 Unicode 码点升序)；命中单播仅发往表项端口；
  命中入端口时 `filtered` 且出口为空。
* runt、oversize 或 bad_fcs 帧，以及入端口不可转发的事件，一律 `dropped`：
  不学习、不查表、无出口。
* 启用老化时，每个事件在其 `time_ms` 到达后、处理该帧之前，删除所有满足
  `time_ms - 最后刷新时间 >= aging_time_ms` 的动态表项 (恰好到期即失效，
  对其单播访问按未知单播泛洪)；坏帧、不可转发入端口与禁止学习端口的事件
  时间仍触发到期清理，但不新建或刷新表项。刷新时间取学习/迁移事件的
  `time_ms`；不同 VLAN 的同名 MAC 独立老化。处理不按时间跨度循环推进。
* 输出为单行固定键序 JSON：版本标识、与输入一一对应的结果
  (event、vid、src_mac、dst_mac、decision、egress_ports) 以及最终动态表快照
  (按 VLAN 数值升序、再按 MAC 的 Unicode 码点升序；仅含最后事件时刻仍有效
  的表项)。
* 场景可选顶层 `include_counters`（布尔）：为 true 时在 `dynamic_table` 后
  追加 `counters`，汇总本次场景的端口与 VLAN 帧计数；缺省或为 false 时输出
  与此前逐字节一致。`include_counters` 不是布尔值时在处理任何事件前以
  ConfigError (退出码 3，路径 `$.include_counters`) 失败。
  * `counters.ports` 按端口 name 的 Unicode 码点升序，每个已配置端口都出现
    (即使计数全为零)，字段依次为 name、ingress_frames、egress_frames、
    dropped_frames。ingress_frames 统计以该端口为入口的全部事件 (含随后因
    坏帧或端口不可转发而丢弃的)；egress_frames 按 egress_ports 中的实际交付
    逐端口累计 (泛洪到多个端口时分别计数)；dropped_frames 只在 decision 为
    dropped 时计入入口端口 (filtered 不算丢弃)。
  * `counters.vlans` 按 vid 数值升序，只包含事件实际归属过的 VLAN
    (未标记帧归入 VLAN 1，带标签帧使用其 vid，含 vid 0)，字段为 vid 与相同
    的三个计数字段；egress_frames 为该 VLAN 实际出口交付的总数。
  * 老化清理不产生帧计数；统计不改变学习、迁移、查表、转发决定或最终动态表。
* 静态表项只参与查表与学习抑制，不出现在 `dynamic_table` 中；无端口模式或跨进程持久化。

## 退出码与错误

| 退出码 | 类型 | 含义 |
| --- | --- | --- |
| 0 | — | 成功，标准输出为单行 JSON |
| 2 | InputError | 文件读取、UTF-8 解码或 JSON 解析错误 |
| 3 | ConfigError | 端口配置或 `static_table`、`aging_time_ms`、`include_counters` 的结构、字段、类型或取值错误 |
| 4 | FrameError | 事件或帧的结构、字段、类型、范围或格式错误 |
| 5 | StateError | 引用了未配置的物理端口 (未知 ingress_port 或静态表项 port) |

任何错误都在处理首个事件前发现；失败时标准输出不写入任何部分结果，
标准错误写入固定键序 `(type, message, path)` 的单行 JSON。

## 上限

* 端口数量：4096；单个端口 name 长度：64 个字符。
* `forward` 场景事件数量：10000；静态表项数量：10000。
* 单帧描述文件：131072 字节；`payload_hex`：最多 65535 字节。

## 状态

功能按增量需求持续构建；当前包含 ports、frame、forward 三个子命令。
