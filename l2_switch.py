#!/usr/bin/env python3
"""l2-switch: 二层以太网交换的行为仿真与配置框架。

当前仅提供物理端口配置校验与确定性状态快照 (ports 子命令)。
仅使用 Python 标准库，不联网，行为确定。
"""

import argparse
import json
import sys

# 受限输入的有限上限 (在 --help 中公开)。
MAX_PORTS = 4096
MAX_PORT_NAME_LEN = 64

SCHEMA = "l2-switch/ports-v1"

# 每个端口允许的字段及其规范顺序；额外字段一律拒绝。
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

ADMIN_STATES = frozenset(("up", "down"))
FORWARDING_STATES = frozenset(("forwarding", "blocking"))
DUPLEX_VALUES = frozenset(("half", "full"))


class ConfigError(Exception):
    """结构、字段、类型或取值不合法。path 为从 $ 开始的 JSON 路径。"""

    def __init__(self, message, path):
        super().__init__(message)
        self.message = message
        self.path = path


def emit_error(type_, message, path=None):
    """向标准错误写固定键序 (type, message, path) 的单行错误 JSON (UTF-8)。"""
    envelope = {"type": type_, "message": message, "path": path}
    sys.stderr.buffer.write(
        (json.dumps(envelope, ensure_ascii=False) + "\n").encode("utf-8")
    )


def read_config(path):
    """读取并解析 UTF-8 JSON；读取/解码/解析失败抛 ValueError。"""
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError:
        # 使用固定消息，避免平台/locale 文本差异影响确定性。
        raise ValueError("cannot read config file")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("config file is not valid UTF-8")
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        # JSONDecodeError 是 ValueError 的子类；超长整数等解析限制同样归为输入错误。
        raise ValueError("config file is not valid JSON")


def _check_name(value, path):
    if not isinstance(value, str):
        raise ConfigError("'name' must be a string", path)
    if len(value) == 0:
        raise ConfigError("'name' must be non-empty", path)
    if len(value) > MAX_PORT_NAME_LEN:
        raise ConfigError(
            "'name' exceeds maximum length of %d" % MAX_PORT_NAME_LEN, path
        )
    return value


def _check_kind(value, path):
    if not isinstance(value, str) or value != "physical":
        raise ConfigError("'kind' must be 'physical'", path)
    return value


def _check_admin_state(value, path):
    if not isinstance(value, str) or value not in ADMIN_STATES:
        raise ConfigError("'admin_state' must be 'up' or 'down'", path)
    return value


def _check_forwarding_state(value, path):
    if not isinstance(value, str) or value not in FORWARDING_STATES:
        raise ConfigError(
            "'forwarding_state' must be 'forwarding' or 'blocking'", path
        )
    return value


def _check_learning(value, path):
    if not isinstance(value, bool):
        raise ConfigError("'learning' must be a boolean", path)
    return value


def _check_speed_mbps(value, path):
    # bool 是 int 的子类型，必须显式排除。
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ConfigError("'speed_mbps' must be a positive integer", path)
    return value


def _check_duplex(value, path):
    if not isinstance(value, str) or value not in DUPLEX_VALUES:
        raise ConfigError("'duplex' must be 'half' or 'full'", path)
    return value


FIELD_CHECKS = {
    "name": _check_name,
    "kind": _check_kind,
    "admin_state": _check_admin_state,
    "forwarding_state": _check_forwarding_state,
    "learning": _check_learning,
    "speed_mbps": _check_speed_mbps,
    "duplex": _check_duplex,
}


def validate_port(item, index, seen):
    """校验单个端口，按输入字段顺序返回 (有序字段, can_forward, can_learn)。

    按字段在输入中出现的顺序报告首个错误 (未知字段、非法值或重复 name 立即
    报告)；仅当所有出现字段均合法后，才按规范字段顺序报告首个缺失字段。
    """
    base = "$.ports[%d]" % index

    if not isinstance(item, dict):
        raise ConfigError("port must be an object", base)

    values = {}
    for field, value in item.items():
        path = base + "." + field
        if field not in FIELD_SET:
            raise ConfigError("unexpected field '%s'" % field, path)
        checked = FIELD_CHECKS[field](value, path)
        if field == "name":
            if checked in seen:
                raise ConfigError(
                    "duplicate port name '%s'" % checked, path
                )
            seen.add(checked)
        values[field] = checked

    for field in FIELD_ORDER:
        if field not in values:
            raise ConfigError("missing field '%s'" % field, base + "." + field)

    admin_state = values["admin_state"]
    forwarding_state = values["forwarding_state"]
    learning = values["learning"]
    can_forward = admin_state == "up" and forwarding_state == "forwarding"
    can_learn = can_forward and learning

    ordered = [(field, values[field]) for field in FIELD_ORDER]
    return ordered, can_forward, can_learn


def validate(config):
    """校验整个配置，返回按 name 的 Unicode 码点升序排列的快照对象。"""
    if not isinstance(config, dict):
        raise ConfigError("top-level config must be an object", "$")

    # 按顶层键在输入中出现的顺序报告首个错误；遍历后再报告缺失的 ports。
    ports_present = False
    for field, value in config.items():
        if field == "ports":
            ports_present = True
        else:
            raise ConfigError("unexpected field '%s'" % field, "$." + field)

    if not ports_present:
        raise ConfigError("missing field 'ports'", "$.ports")

    ports = config["ports"]
    if not isinstance(ports, list):
        raise ConfigError("'ports' must be an array", "$.ports")

    if len(ports) > MAX_PORTS:
        raise ConfigError(
            "number of ports exceeds maximum of %d" % MAX_PORTS, "$.ports"
        )

    records = []
    seen = set()
    for index, item in enumerate(ports):
        ordered, can_forward, can_learn = validate_port(item, index, seen)
        records.append((ordered, can_forward, can_learn))

    # Python 字符串按 Unicode 码点逐字符比较，即码点升序。
    records.sort(key=lambda record: record[0][0][1])

    output_ports = []
    for ordered, can_forward, can_learn in records:
        entry = {}
        for field, value in ordered:
            entry[field] = value
        entry["can_forward"] = can_forward
        entry["can_learn"] = can_learn
        output_ports.append(entry)

    return {"schema": SCHEMA, "ports": output_ports}


def cmd_ports(args):
    try:
        config = read_config(args.config)
    except ValueError as exc:
        emit_error("InputError", str(exc))
        return 2

    try:
        result = validate(config)
    except ConfigError as exc:
        emit_error("ConfigError", exc.message, exc.path)
        return 3

    sys.stdout.buffer.write(
        (json.dumps(result, ensure_ascii=False) + "\n").encode("utf-8")
    )
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="l2_switch.py",
        description=(
            "l2-switch: 二层以太网交换的行为仿真与配置框架。"
            "当前支持物理端口配置校验与确定性状态快照。"
        ),
        epilog=(
            "限制: 端口数量上限为 %d；单个端口 name 长度上限为 %d 个字符。"
            "仅使用 Python 标准库，不联网。"
            % (MAX_PORTS, MAX_PORT_NAME_LEN)
        ),
    )
    subparsers = parser.add_subparsers(dest="command", metavar="command")

    ports_parser = subparsers.add_parser(
        "ports",
        help="校验物理端口配置并输出确定性状态快照",
        description=(
            "读取 UTF-8 JSON 配置，校验物理端口，并向标准输出写入单行 JSON 快照。"
        ),
        epilog=(
            "限制: 端口数量上限为 %d；单个端口 name 长度上限为 %d 个字符。"
            "端口按 name 的 Unicode 码点升序排列；相同输入的输出逐字节一致。"
            % (MAX_PORTS, MAX_PORT_NAME_LEN)
        ),
    )
    ports_parser.add_argument(
        "--config",
        required=True,
        metavar="FILE",
        help="UTF-8 JSON 配置文件路径，顶层包含 ports 数组",
    )
    ports_parser.set_defaults(func=cmd_ports)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
