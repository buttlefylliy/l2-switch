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
每个端口可选 `access_vid` 字段（1 到 4094 的整数，布尔值不算整数）声明
接入 VLAN 归属；提供时快照中该字段位于 `duplex` 之后、`can_forward` 之前，
省略时不补默认键，既有快照的键序与逐字节内容不变。`access_vid` 只定义
VLAN 归属，不改变由管理状态、转发状态和 `learning` 推导出的
`can_forward`/`can_learn`。类型或范围错误以 ConfigError（退出码 3，
路径 `$.ports[i].access_vid`）失败。

每个端口可选 `trunk_vids` 字段（1 到 4094 的整数组成的非空数组，布尔值
不算整数，数组内不得重复）声明中继端口允许承载的 802.1Q VLAN；
`trunk_vids` 与 `access_vid` 互斥，二者都省略时保持不受接入口/中继
限制的兼容语义。提供时快照中该字段位于 `access_vid` 之后（`access_vid`
省略时位于 `duplex` 之后）、`can_forward` 之前，VID 规范化为数值升序；
省略时不补默认键。`trunk_vids` 不是数组、为空、元素为布尔值或非整数、
超出范围、重复，或与 `access_vid` 同时出现时，以 ConfigError（退出码 3，
路径 `$.ports[i].trunk_vids` 或对应元素路径）失败。

每个端口可选 `dynamic_mac_limit` 字段（1 到 10000 的整数，布尔值不算
整数）声明该端口动态 MAC 学习数量上限，模拟最基本的端口安全；省略时
不补默认键并保持无限制语义，不改变 `can_forward`/`can_learn` 的推导。
提供时快照中原样保留该数值，字段稳定位于 VLAN 模式字段（`access_vid`/
`trunk_vids`，二者均省略时位于 `duplex`）之后、`can_forward` 之前。
类型或范围错误以 ConfigError（退出码 3，路径
`$.ports[i].dynamic_mac_limit`）失败。

### `frame`

读取 UTF-8 JSON 单帧描述，做离线合法性判定 (runt/oversize/bad_fcs 等)，
向标准输出写入单行 JSON 判定结果；不涉及学习、查表和转发。

### `forward`

从一个 UTF-8 JSON 场景文件读取现有 `ports` 配置与按顺序排列的 `events`；
每个事件包含 `ingress_port` 与 `frame` 子命令接受的完整帧描述。
场景可选顶层 `aging_time_ms`（1 到 9223372036854775807 的整数）启用动态
MAC 老化；启用后每个事件必须包含 `time_ms`（0 到 9223372036854775807 的
整数），并按事件顺序单调不减。未提供 `aging_time_ms` 的场景不得出现
`time_ms`。
先校验完整场景，再按事件顺序处理：

* 未标记帧归入 VLAN 1；带标签帧按 `vid` 隔离，`vid` 0 也是独立域。
* 配置了 `access_vid` 的端口为接入口：其上的未标记帧（含坏帧的结果 vid
  与 VLAN 计数）归入该接入 VLAN，学习、查找、动态表老化与 VLAN 计数都使用
  这个内部 VLAN；其上任何带 802.1Q 标签的帧（含 VID 0 或与 `access_vid`
  相同的标签）都作为接入口策略违例 `dropped`，结果 vid 与 VLAN 计数使用
  帧标签 VID，不学习、不查表、无出口。帧自身的结构和长度仍先按既有规则
  判定。泛洪只可选择 `access_vid` 与帧内部 VLAN 相同的接入口，其他接入口
  不出现在 `egress_ports`；命中动态或静态单播表项但目标接入口 VLAN 不匹配
  时也 `dropped`，不退回泛洪。向匹配接入口成功交付在公开语义上表示标签
  已剥除，`egress_ports` 仍只返回端口名。未配置 `access_vid` 的端口遵循
  既有语义，可与接入口共存；从这类端口进入的帧只有内部 VLAN 匹配时才能
  发往接入口。
* 配置了 `trunk_vids` 的端口为中继端口：只接收带标签且 VID 位于允许数组
  中的帧。未标记帧仍按缺省 VLAN 1 生成结果 vid 与 VLAN 计数，但作为中继
  策略违例 `dropped`；VID 0 或不在允许数组中的标签帧同样 `dropped`。
  这些违例事件不学习源 MAC、不查询转发表且无出口。合法且被允许的标签帧
  按其 VID 学习、老化、查表与计数。中继端口仅在内部 VLAN 位于允许数组时
  才能成为泛洪或单播出口；动态或静态单播命中一个不允许该 VLAN 的中继
  端口时结果为 `dropped`，不退回泛洪。`trunk_vids` 与 `access_vid`
  互斥；未声明两种 VLAN 模式的端口行为不变。
* 仅合法、未被丢弃且入端口 `can_learn` 为真的帧，按 (VLAN, 规范化小写单播源 MAC)
  学习；同一键从另一端口出现时迁移到新端口。
* 端口配置了 `dynamic_mac_limit` 时启用最基本的端口安全：上限按当前绑定到
  该入端口的动态表项总数计算，不区分 VLAN，静态表项不占额度。只有原本满足
  学习条件的合法帧才触发检查——源键在同 VLAN 已有静态项、入端口禁止学习、
  帧不合法或已被接入/中继 VLAN 策略拒绝的事件都不产生端口安全违例。已在同一
  端口的动态源允许照常刷新，不新增额度；首次学习或从其他端口迁入的源需要一个
  新额度。检查发生在该事件时刻的老化清理之后，刚到期的表项立即释放额度。若仍
  已满，本事件结果固定为 `dropped` 且 `egress_ports` 为空：不做目的查表，
  不新增、刷新或迁移任何动态项；跨端口迁入因额度不足失败时，旧端口上的原表项
  保持原状。若有空余，则沿用现有学习、迁移、查表与转发规则。未配置
  `dynamic_mac_limit` 的端口无限制。
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
  (event、vid、src_mac、dst_mac、decision、egress_ports；提供
  `ingress_mirror` 时在 egress_ports 后追加 mirror_ports；提供
  `egress_mirror` 时再追加 egress_mirror_ports，未启用入口镜像时该键紧随
  egress_ports) 以及最终动态表快照
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
* 场景可选顶层 `static_table` 数组（最多 10000 项）声明静态 MAC 转发表；
  每项仅含 `vid`、`mac`、`port`：`vid` 为 0 到 4094 的整数，`mac` 为非零
  单播 MAC 地址（规范化为小写），`port` 引用 `ports` 中的端口名；同一
  (vid, 规范化 mac) 组合只能出现一次。字段缺失、额外字段、类型或取值错误
  以及重复组合均为 ConfigError；`port` 引用不存在的端口为 StateError。
* 静态项从场景开始到结束始终有效：不参与 `aging_time_ms` 老化，不被源 MAC
  学习、刷新或迁移覆盖；源 MAC 在某 VLAN 已有静态项时，该键不再创建或更新
  动态项（帧合法性、目的查表与计数仍按既有规则处理）。合法帧的单播目的
  查找优先匹配静态项：命中其他可转发端口时仅向该端口转发；命中入端口时
  `filtered` 且无出口；目标端口 down 或 blocking 时 `dropped` 且无出口，
  不退回未知单播泛洪。广播、组播与未命中单播的泛洪不受影响。
* 提供非空 `static_table` 时，输出在 `dynamic_table` 后追加 `static_table`
  快照（仅含 vid、mac、port，按 vid 数值升序、再按 mac 的 Unicode 码点
  升序）；`include_counters` 为真时 `counters` 位于其后。空数组等价于
  省略，省略时输出键、顺序与逐字节内容和此前一致。
* 场景可选顶层 `include_fdb_events`（布尔）：为 true 时在现有所有输出区段
  （含 `counters`）之后追加 `fdb_events` 数组，按输入事件顺序审计动态转发表
  的实际变化；缺省或为 false 时输出与此前逐字节一致。`include_fdb_events`
  不是布尔值时在处理任何事件前以 ConfigError（退出码 3，路径
  `$.include_fdb_events`）失败，标准输出不写入部分结果。
  * 每条记录按键序 event、kind、vid、mac、from_port、to_port；event 为与
    results 相同的零基事件序号，mac 为规范化小写形式，kind 只取
    `aged`、`learned`、`refreshed`、`moved`。老化删除记录 from_port 为原
    端口、to_port 为 null；首次学习 from_port 为 null、to_port 为新端口；
    同端口刷新两个端口字段都为当前端口；跨端口迁移为旧端口与新端口。
  * 一个事件触发多条到期删除时，先按 vid 数值、再按 mac 的 Unicode 码点
    升序记录全部 `aged`，随后再记录该帧产生的学习、刷新或迁移，因此同一键
    可在一个事件中先 `aged` 再 `learned`。
  * 只有实际提交到动态表的变化才写入：坏帧、不可转发或 VLAN 策略拒绝的帧、
    禁止学习的端口、源键已有静态项，以及因 `dynamic_mac_limit` 已满而拒绝的
    首次学习或迁移都不产生记录（额度不足的迁移保留旧项，不伪造 `moved`）；
    老化即使由随后被丢弃的帧时刻触发也要记录；静态表从不进入该数组。
    空事件或没有变化时为空数组；记录总数不超过事件数的两倍。
  * 该审计开关不改变学习、转发、计数或最终表状态；相同场景的记录内容、
    顺序与整行 JSON 逐字节一致。
* 场景可选顶层 `ingress_mirror` 对象声明唯一一个入口镜像会话，仅含
  `source_ports` 与 `destination_port` 两个字段（额外字段一律拒绝）：
  `source_ports` 为已配置端口名组成的非空、不重复数组，且元素个数不得超过
  已配置端口总数；`destination_port` 为另一个已配置端口，且不得出现在
  `source_ports` 中。仅支持一个入口镜像会话。结构错误、字段缺失或多余、
  `source_ports` 为空或超过端口总数、元素非字符串或重复，以及目的端口同时
  属于源端口时，在处理任何事件前以 ConfigError（退出码 3，路径
  `$.ingress_mirror...`）失败；源或目的名称未引用现有端口时以 StateError
  （退出码 5，路径 `$.ingress_mirror.source_ports[i]` 或
  `$.ingress_mirror.destination_port`）失败。失败时标准输出不写入部分结果。
  * 完整场景校验成功后，凡 `ingress_port` 属于 `source_ports` 的事件，都
    独立尝试向 `destination_port` 交付一份入口帧副本；即使原帧因 runt、
    oversize、bad_fcs、入口端口状态、VLAN 策略或端口安全而被丢弃，也仍
    尝试镜像。仅当目的端口 `can_forward` 为真时交付；目的端口的
    `access_vid` 或 `trunk_vids` 不限制这份原始入口副本。
  * 镜像不触发额外学习、刷新、迁移或老化，不改变 decision、egress_ports、
    动态表、static_table、fdb_events 与 VLAN/端口计数；每个事件最多产生一个
    镜像副本，`include_counters` 的 egress_frames 只统计普通转发，不统计
    镜像副本。
  * 提供 `ingress_mirror` 时，每条 results 记录在 `egress_ports` 之后追加
    `mirror_ports`：成功交付时为仅含 `destination_port` 的数组，否则为空数组
    （入口不属于源端口，或目的端口不可转发）。省略 `ingress_mirror` 时，
    现有校验、输出键序及逐字节结果保持不变。
* 场景可选顶层 `egress_mirror` 对象声明唯一一个出口镜像会话，仅含
  `source_ports` 与 `destination_port` 两个字段（额外字段一律拒绝）：
  `source_ports` 为已配置端口名组成的非空、不重复数组，且元素个数不得超过
  已配置端口总数 (源端口数量继续受现有 4096 个端口上限约束)；
  `destination_port` 为另一个已配置端口，且不得出现在 `source_ports` 中。
  仅支持一个出口镜像会话。结构错误、字段缺失或多余、`source_ports` 为空或
  超过端口总数、元素非字符串或重复，以及目的端口同时属于源端口时，在处理
  任何事件前以 ConfigError（退出码 3，路径 `$.egress_mirror...`）失败；
  源或目的名称未引用现有端口时以 StateError（退出码 5，路径
  `$.egress_mirror.source_ports[i]` 或 `$.egress_mirror.destination_port`）
  失败。失败时标准输出不写入部分结果。
  * 每个事件沿用当前的学习、老化、查表、VLAN 策略与普通转发规则，再根据
    最终 `egress_ports` 判定出口镜像：只要至少一个实际交付端口属于
    `source_ports`，就尝试向 `destination_port` 发送一份原始帧副本；泛洪
    命中多个源端口也只生成一份副本。`dropped`、`filtered` 或没有任何实际
    出口的事件不生成出口镜像；镜像目的端口 `can_forward` 为假时也不交付。
    目的端口的 `access_vid` 或 `trunk_vids` 不限制这份副本。
  * 出口镜像副本不再次触发镜像 (入口与出口镜像均不被另一份副本触发)，也不
    引起学习、刷新、迁移、老化、转发表变化或额外的 fdb_events 审计记录；
    不改变 decision、egress_ports、mirror_ports、static_table 与
    VLAN/端口计数；每个事件最多产生一个出口镜像副本，`include_counters` 的
    egress_frames 只统计普通转发，不统计镜像副本。
  * 入口镜像与出口镜像可同时存在并各自独立判定，现有 `mirror_ports` 的含义
    与键序不变；两个会话目的端口相同时也分别报告且互不触发。提供
    `egress_mirror` 时，每条 results 记录在 `mirror_ports` 之后
    （未启用入口镜像时紧随 `egress_ports`）追加 `egress_mirror_ports`：成功
    交付时为仅含 `destination_port` 的数组，否则为空数组（无实际出口、实际
    出口均不属于源端口，或目的端口不可转发）。省略 `egress_mirror` 时，
    ports、frame、forward 的校验、输出键序、退出码及逐字节结果保持不变。
* 场景可选顶层 `ingress_acl` 数组（最多 4096 条规则）声明有序无状态入口
  过滤：每条规则为仅含 `action` 与匹配字段的对象，`action` 取 `allow`、
  `drop` 或 `remark_pcp`，并至少给出 `src_mac`、`dst_mac`、`vid`、`ether_type`、`pcp`
  中一个匹配字段；多个字段须同时精确匹配，省略字段视为通配，首条命中
  规则决定动作，均未命中时允许。`remark_pcp` 规则另须携带 `set_pcp`
  （0 到 7 的整数，布尔值不算整数）且必须含 `pcp` 匹配字段（保证只命中
  带 802.1Q 标签的帧）；`set_pcp` 不允许出现在 `allow`、`drop` 规则中。
  规则对象存在缺失或多余字段、非法动作、`remark_pcp` 缺少 `pcp` 或
  `set_pcp`、`set_pcp` 类型或范围错误、`allow`/`drop` 规则携带
  `set_pcp`、错误 MAC、布尔值冒充整数、数值越界、空匹配条件或规则数量
  超限时，在处理任何事件前以 ConfigError（退出码 3，路径
  `$.ingress_acl...`）失败，标准输出不写入部分结果。
  * ACL 仅对已经通过帧合法性、入端口转发状态及 VLAN 入站策略检查的事件
    求值，并在 MAC 学习、端口安全检查和目的地址查表前执行。`vid` 匹配
    内部 VLAN：接入口未标记帧使用 `access_vid`，其他未标记帧使用
    VLAN 1；`pcp` 只能匹配带 802.1Q 标签的帧（未标记帧不命中任何带
    `pcp` 条件的规则）。
  * `allow` 沿用既有学习、迁移、静态表优先、泛洪和单播行为；`drop`
    固定返回 `dropped` 和空 `egress_ports`，不学习或刷新源 MAC，不查
    目的表，也不产生 `learned`、`refreshed` 或 `moved` 记录。显式事件
    时钟触发的老化仍先完成，并可产生 `aged` 记录。
  * `remark_pcp` 命中时把该带标签帧的 PCP 重标记为规则的 `set_pcp`：
    源 MAC 学习、端口安全、静态或动态目的查找、泛洪和计数都按既有路径
    执行，只有普通出口帧及由它触发的出口镜像副本使用新的 PCP，入口镜像
    仍复制重标记前的原始帧。重标记不改变内部 VLAN，也不重新执行 ACL。
  * 提供 `ingress_acl` 时，每条 results 记录在既有字段后追加
    `matched_acl_rule`，值为首条命中规则的零基索引；未命中或事件未
    进入 ACL 求值时为 `null`。随后在 `matched_acl_rule` 之后追加
    `effective_pcp`：带标签帧为最终 PCP（命中 `remark_pcp` 时为重标记
    值；未进入 ACL 求值或未命中重标记规则时为原始 PCP，丢弃路径同样有
    确定值），未标记帧为 `null`。ACL 丢弃计入既有端口和 VLAN 入站及丢弃
    计数，入口镜像仍复制原始帧，出口镜像不交付。省略 `ingress_acl`
    时输出与此前逐字节一致（不新增 `effective_pcp`）；仅使用 `allow`、
    `drop` 规则时转发决定、学习结果和审计内容不变，只按上述约定追加
    `effective_pcp`。每个事件至多顺序检查 4096 条规则，
    不累积 ACL 状态。
* 只做场景内转发表；无端口模式或跨进程持久化。

## 退出码与错误

| 退出码 | 类型 | 含义 |
| --- | --- | --- |
| 0 | — | 成功，标准输出为单行 JSON |
| 2 | InputError | 文件读取、UTF-8 解码或 JSON 解析错误 |
| 3 | ConfigError | 端口配置或 `aging_time_ms`、`include_counters`、`include_fdb_events`、`static_table`、`ingress_mirror`、`egress_mirror`、`ingress_acl` 的结构、字段、类型或取值错误 |
| 4 | FrameError | 事件或帧的结构、字段、类型、范围或格式错误 |
| 5 | StateError | 引用了未配置的物理端口 (未知 ingress_port、静态项 port，或镜像源/目的端口) |

任何错误都在处理首个事件前发现；失败时标准输出不写入任何部分结果，
标准错误写入固定键序 `(type, message, path)` 的单行 JSON。

## 上限

* 端口数量：4096；单个端口 name 长度：64 个字符。
* `forward` 场景事件数量：10000；静态表项数量：10000；入口 ACL 规则数量：4096。
* 单帧描述文件：131072 字节；`payload_hex`：最多 65535 字节。

## 状态

功能按增量需求持续构建；当前包含 ports、frame、forward 三个子命令。
