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

## 命令

### `python l2_switch.py ports --config FILE`

校验物理端口配置并输出确定性状态快照。

* `FILE` 为 UTF-8 JSON，顶层为 `{"ports": [...]}`。每个端口对象必须恰好包含：
  * `name`：非空字符串，端口间唯一，长度不超过 64 个 Unicode 字符；
  * `kind`：固定为 `"physical"`；
  * `admin_state`：`"up"` 或 `"down"`；
  * `forwarding_state`：`"forwarding"` 或 `"blocking"`；
  * `learning`：布尔值；
  * `speed_mbps`：正整数；
  * `duplex`：`"half"` 或 `"full"`。
* 端口数量上限 1024，超限按 ConfigError 处理。
* 成功：标准输出单行 JSON 并换行，无其他内容。顶层键序为 `schema`、`ports`，`schema` 固定为 `l2-switch/ports-v1`；端口按 `name` 的 Unicode 码点升序；每项按输入字段顺序后接 `can_forward`、`can_learn`。`can_forward` 仅在 `admin_state` 为 `up` 且 `forwarding_state` 为 `forwarding` 时为 `true`；`can_learn` 仅在 `can_forward` 与 `learning` 均为 `true` 时为 `true`。
* 失败：标准输出为空，标准错误输出单行错误 JSON（键序 `type`、`message`、`path`，`path` 为自 `$` 起的 JSON 路径，按输入顺序报告首个错误）。
  * 文件不存在、不可读、非合法 UTF-8 或 JSON：`type` 为 `InputError`，退出码 2；
  * 结构、字段、类型或取值不合法：`type` 为 `ConfigError`，退出码 3。

## 状态

仓库初始为空，功能按增量需求持续构建。
