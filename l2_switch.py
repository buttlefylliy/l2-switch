#!/usr/bin/env python3
"""l2-switch: 二层以太网交换的行为仿真与配置框架。

当前提供物理端口配置校验与确定性状态快照：

    python l2_switch.py ports --config FILE

FILE 为 UTF-8 JSON，顶层为 {"ports": [...]}。每个端口对象必须恰好包含
name, kind, admin_state, forwarding_state, learning, speed_mbps, duplex
七个字段。成功时向标准输出写入单行 JSON 快照；失败时向标准错误写入
单行错误 JSON 并以非零码退出。

限制（超出按 ConfigError 处理）：
    端口数量上限 MAX_PORTS = 1024
    端口名称长度上限 MAX_NAME_LEN = 64（Unicode 字符数）
"""

import argparse
import json
import sys

SCHEMA = "l2-switch/ports-v1"

MAX_PORTS = 1024
MAX_NAME_LEN = 64

# 端口字段的规范顺序（用于缺失字段与取值校验的报错顺序）。
FIELD_ORDER = (
    "name",
    "kind",
    "admin_state",
    "forwarding_state",
    "learning",
    "speed_mbps",
    "duplex",
)
FIELD_SET = frozenset(FIELD_ORDER)

ADMIN_STATES = ("up", "down")
FORWARDING_STATES = ("forwarding", "blocking")
DUPLEX_MODES = ("half", "full")


class InputError(Exception):
    """输入文件无法读取或不是合法 UTF-8/JSON（退出码 2）。"""

    def __init__(self, message, path="$"):
        super().__init__(message)
        self.message = message
        self.path = path


class ConfigError(Exception):
    """配置结构、字段、类型或取值不合法（退出码 3）。"""

    def __init__(self, message, path="$"):
        super().__init__(message)
        self.message = message
        self.path = path


def _reject_constant(value):
    raise InputError("invalid JSON constant: %s" % value)


def load_config(path):
    """读取并解析配置文件，失败抛出 InputError。"""
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        detail = exc.strerror if exc.strerror else str(exc)
        raise InputError("cannot read config file: %s" % detail)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise InputError("config file is not valid UTF-8")
    try:
        return json.loads(text, parse_constant=_reject_constant)
    except InputError:
        raise
    except json.JSONDecodeError as exc:
        raise InputError("config file is not valid JSON: %s" % exc)


def _validate_port(item, index, path):
    """校验单个端口对象，按输入顺序报告首个错误。"""
    if not isinstance(item, dict):
        raise ConfigError("port entry must be an object", path)

    # 额外字段：按输入中出现的顺序检查。
    for key in item:
        if key not in FIELD_SET:
            raise ConfigError(
                "unexpected field %r" % key, "%s.%s" % (path, key)
            )

    # 缺失字段：按规范字段顺序检查。
    for field in FIELD_ORDER:
        if field not in item:
            raise ConfigError("missing required field %r" % field, path)

    # 取值校验：按规范字段顺序进行。
    name = item["name"]
    if not isinstance(name, str):
        raise ConfigError("name must be a string", path + ".name")
    if not name:
        raise ConfigError("name must not be empty", path + ".name")
    if len(name) > MAX_NAME_LEN:
        raise ConfigError(
            "name exceeds %d characters" % MAX_NAME_LEN, path + ".name"
        )

    kind = item["kind"]
    if kind != "physical":
        raise ConfigError("kind must be \"physical\"", path + ".kind")

    admin_state = item["admin_state"]
    if admin_state not in ADMIN_STATES:
        raise ConfigError(
            "admin_state must be one of %s" % list(ADMIN_STATES),
            path + ".admin_state",
        )

    forwarding_state = item["forwarding_state"]
    if forwarding_state not in FORWARDING_STATES:
        raise ConfigError(
            "forwarding_state must be one of %s" % list(FORWARDING_STATES),
            path + ".forwarding_state",
        )

    learning = item["learning"]
    if not isinstance(learning, bool):
        raise ConfigError("learning must be a boolean", path + ".learning")

    speed = item["speed_mbps"]
    if isinstance(speed, bool) or not isinstance(speed, int):
        raise ConfigError(
            "speed_mbps must be an integer", path + ".speed_mbps"
        )
    if speed <= 0:
        raise ConfigError(
            "speed_mbps must be a positive integer", path + ".speed_mbps"
        )

    duplex = item["duplex"]
    if duplex not in DUPLEX_MODES:
        raise ConfigError(
            "duplex must be one of %s" % list(DUPLEX_MODES), path + ".duplex"
        )


def validate_config(config):
    """校验整体配置结构，返回端口对象列表（保持输入顺序）。"""
    if not isinstance(config, dict):
        raise ConfigError("top level must be an object")

    for key in config:
        if key != "ports":
            raise ConfigError(
                "unexpected field %r" % key, "$.%s" % key
            )
    if "ports" not in config:
        raise ConfigError("missing required field 'ports'")

    ports = config["ports"]
    if not isinstance(ports, list):
        raise ConfigError("ports must be an array", "$.ports")
    if len(ports) > MAX_PORTS:
        raise ConfigError(
            "ports exceeds maximum of %d entries" % MAX_PORTS, "$.ports"
        )

    seen_names = set()
    for index, item in enumerate(ports):
        path = "$.ports[%d]" % index
        _validate_port(item, index, path)
        name = item["name"]
        if name in seen_names:
            raise ConfigError("duplicate port name %r" % name, path + ".name")
        seen_names.add(name)

    return ports


def build_snapshot(ports):
    """由校验通过的端口列表构建确定性快照。"""
    snapshot_ports = []
    for item in sorted(ports, key=lambda p: p["name"]):
        can_forward = (
            item["admin_state"] == "up"
            and item["forwarding_state"] == "forwarding"
        )
        can_learn = can_forward and item["learning"]
        entry = dict(item)  # 保留输入字段顺序
        entry["can_forward"] = can_forward
        entry["can_learn"] = can_learn
        snapshot_ports.append(entry)
    return {"schema": SCHEMA, "ports": snapshot_ports}


def _dump(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def cmd_ports(config_path):
    try:
        config = load_config(config_path)
    except InputError as exc:
        sys.stderr.write(_dump({
            "type": "InputError",
            "message": exc.message,
            "path": exc.path,
        }) + "\n")
        return 2

    try:
        ports = validate_config(config)
    except ConfigError as exc:
        sys.stderr.write(_dump({
            "type": "ConfigError",
            "message": exc.message,
            "path": exc.path,
        }) + "\n")
        return 3

    sys.stdout.write(_dump(build_snapshot(ports)) + "\n")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="l2_switch.py",
        description=(
            "二层以太网交换的行为仿真与配置框架。"
            "端口数量上限 %d，名称长度上限 %d 字符，超限按 ConfigError 处理。"
            % (MAX_PORTS, MAX_NAME_LEN)
        ),
    )
    subparsers = parser.add_subparsers(dest="command")

    ports_parser = subparsers.add_parser(
        "ports",
        help="校验物理端口配置并输出确定性状态快照",
        description=(
            "读取 UTF-8 JSON 配置（顶层 ports 数组，每项含 name/kind/"
            "admin_state/forwarding_state/learning/speed_mbps/duplex），"
            "成功时向标准输出写入单行 JSON 快照（schema 为 %s，"
            "端口按 name 的 Unicode 码点升序，各项追加 can_forward、"
            "can_learn）。端口数量上限 %d，名称长度上限 %d 字符。"
            "输入不可读或非 UTF-8/JSON 时以 InputError 退出（码 2）；"
            "结构、字段、类型或取值不合法时以 ConfigError 退出（码 3）。"
            % (SCHEMA, MAX_PORTS, MAX_NAME_LEN)
        ),
    )
    ports_parser.add_argument(
        "--config",
        required=True,
        metavar="FILE",
        help="UTF-8 JSON 配置文件路径",
    )
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "ports":
        return cmd_ports(args.config)
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
