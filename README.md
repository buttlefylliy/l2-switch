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

## 状态

仓库初始为空，功能按增量需求持续构建。

## 子命令

### `ports`

`python l2_switch.py ports --config FILE`

校验物理端口配置，输出 schema 为 `l2-switch/ports-v1` 的确定性状态快照。
结构/字段/类型/取值错误输出 `ConfigError` (退出码 3)；文件不可读、非 UTF-8 或
JSON 无效输出 `InputError` (退出码 2)。

### `frame`

`python l2_switch.py frame --input FILE`

判定单个以太帧是否合法，不涉及学习、查表与转发。输入为 UTF-8 JSON 对象，必须
依次包含 `dst_mac`、`src_mac`、`vlan`、`ether_type`、`payload_hex`、`fcs_valid`：

* `dst_mac`/`src_mac`：六组两位十六进制的冒号格式，输出统一小写；`src_mac`
  必须为非零单播地址。
* `vlan`：`null` 或仅含 `vid` (0–4094)、`pcp` (0–7)、`dei` (0–1) 的对象。
* `ether_type`：1536–65535 的整数。
* `payload_hex`：偶数长度的十六进制字符串，最多表示 65535 字节，输出小写。
* `fcs_valid`：布尔值。

成功时向标准输出写入一行 JSON，schema 为 `l2-switch/frame-v1`，键序为
`schema, dst_mac, src_mac, vlan, ether_type, payload_hex, frame_length,
destination_type, valid, error_kind`；`vlan` 子对象按 `vid, pcp, dei` 排列。

`frame_length` = 两个 MAC (12) + 可选 4 字节 802.1Q 标签 + 以太类型 (2) +
载荷 + FCS (4)。`destination_type` 为 `unicast`、`multicast` 或 `broadcast`。

`error_kind` 在多种问题并存时按以下顺序唯一选择：

1. `runt`：长度小于 64；
2. `oversize`：未标记帧超过 1518，或带标签帧超过 1522；
3. `bad_fcs`：长度合规但 `fcs_valid` 为 `false`；
4. 其余为 `valid: true`、`error_kind: null`。

输入文件不可读、超过 131072 字节、非 UTF-8 或 JSON 无效时输出 `InputError`
(退出码 2)；结构、字段、类型、范围或格式无效时输出 `FrameError` (退出码 4)，
`path` 从 `$` 开始指向首个失败位置。错误时标准输出为空，错误 JSON 沿用
`type, message, path` 键序写入标准错误。

