#!/usr/bin/env python3
"""l2-switch: 二层以太网交换的行为仿真与配置框架。

当前提供物理端口配置校验与确定性状态快照 (ports 子命令)，以及以太帧合法性
判定 (frame 子命令)。仅使用 Python 标准库，不联网，行为确定。
"""

import argparse
import json
import re
import sys

# 受限输入的有限上限 (在 --help 中公开)。
MAX_PORTS = 4096
MAX_PORT_NAME_LEN = 64

# frame 子命令的输入与帧格式上限。
MAX_INPUT_BYTES = 131072
MAX_PAYLOAD_BYTES = 65535
MIN_FRAME_LENGTH = 64
MAX_FRAME_UNTAGGED = 1518
MAX_FRAME_TAGGED = 1522
ETHER_TYPE_MIN = 1536
ETHER_TYPE_MAX = 65535

SCHEMA = "l2-switch/ports-v1"
FRAME_SCHEMA = "l2-switch/frame-v1"

# MAC 地址: 六组两位十六进制，冒号分隔。
MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")
HEX_STRING_RE = re.compile(r"^[0-9A-Fa-f]*$")

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


class FrameError(Exception):
    """帧输入的结构、字段、类型、范围或格式不合法。"""

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


def read_frame_input(path):
    """读取并解析 UTF-8 JSON 帧输入；读取/超长/解码/解析失败抛 ValueError。"""
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError:
        # 使用固定消息，避免平台/locale 文本差异影响确定性。
        raise ValueError("cannot read frame input file")
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError(
            "frame input exceeds maximum size of %d bytes" % MAX_INPUT_BYTES
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("frame input is not valid UTF-8")
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        raise ValueError("frame input is not valid JSON")


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


# frame 输入允许的顶层字段及其规范顺序；额外字段一律拒绝。
FRAME_FIELD_ORDER = (
    "dst_mac",
    "src_mac",
    "vlan",
    "ether_type",
    "payload_hex",
    "fcs_valid",
)
FRAME_FIELD_SET = frozenset(FRAME_FIELD_ORDER)

VLAN_FIELD_ORDER = ("vid", "pcp", "dei")
VLAN_FIELD_SET = frozenset(VLAN_FIELD_ORDER)
VLAN_RANGES = {"vid": (0, 4094), "pcp": (0, 7), "dei": (0, 1)}


def _check_mac(value, path, field_name):
    """校验冒号格式 MAC，返回统一小写形式。"""
    if not isinstance(value, str):
        raise FrameError("'%s' must be a string" % field_name, path)
    if MAC_RE.match(value) is None:
        raise FrameError(
            "'%s' must be six colon-separated pairs of hex digits" % field_name,
            path,
        )
    return value.lower()


def _check_vlan(value, path):
    """vlan 为 null，或仅含 vid/pcp/dei 且取值合规的对象。"""
    if value is None:
        return None
    if not isinstance(value, dict):
        raise FrameError("'vlan' must be null or an object", path)

    # 与端口校验一致: 按输入出现顺序完整校验每个字段，再按规范顺序报告缺失字段。
    values = {}
    for field, field_value in value.items():
        field_path = path + "." + field
        if field not in VLAN_FIELD_SET:
            raise FrameError("unexpected field '%s'" % field, field_path)
        # bool 是 int 的子类型，必须显式排除。
        if isinstance(field_value, bool) or not isinstance(field_value, int):
            raise FrameError("'%s' must be an integer" % field, field_path)
        low, high = VLAN_RANGES[field]
        if not low <= field_value <= high:
            raise FrameError(
                "'%s' must be between %d and %d" % (field, low, high),
                field_path,
            )
        values[field] = field_value

    for field in VLAN_FIELD_ORDER:
        if field not in values:
            raise FrameError("missing field '%s'" % field, path + "." + field)

    return {"vid": values["vid"], "pcp": values["pcp"], "dei": values["dei"]}


def _check_ether_type(value, path):
    # bool 是 int 的子类型，必须显式排除。
    if isinstance(value, bool) or not isinstance(value, int):
        raise FrameError("'ether_type' must be an integer", path)
    if not ETHER_TYPE_MIN <= value <= ETHER_TYPE_MAX:
        raise FrameError(
            "'ether_type' must be between %d and %d"
            % (ETHER_TYPE_MIN, ETHER_TYPE_MAX),
            path,
        )
    return value


def _check_payload_hex(value, path):
    """偶数长度的十六进制字符串，最多表示 65535 字节；返回小写形式。"""
    if not isinstance(value, str):
        raise FrameError("'payload_hex' must be a string", path)
    if len(value) % 2 != 0:
        raise FrameError("'payload_hex' must have even length", path)
    if HEX_STRING_RE.match(value) is None:
        raise FrameError("'payload_hex' must contain only hex digits", path)
    byte_count = len(value) // 2
    if byte_count > MAX_PAYLOAD_BYTES:
        raise FrameError(
            "payload exceeds maximum length of %d bytes" % MAX_PAYLOAD_BYTES,
            path,
        )
    return value.lower()


def _check_fcs_valid(value, path):
    if not isinstance(value, bool):
        raise FrameError("'fcs_valid' must be a boolean", path)
    return value


def validate_frame(frame):
    """校验单个帧输入，返回固定键序的判定结果对象。

    与端口校验一致: 按字段在输入中出现的顺序报告首个错误 (未知字段或非法值立即
    报告)；仅当所有出现字段均合法后，才按规范字段顺序报告首个缺失字段。
    """
    if not isinstance(frame, dict):
        raise FrameError("frame input must be an object", "$")

    values = {}
    for field, value in frame.items():
        path = "$." + field
        if field not in FRAME_FIELD_SET:
            raise FrameError("unexpected field '%s'" % field, path)
        if field == "dst_mac":
            values[field] = _check_mac(value, path, "dst_mac")
        elif field == "src_mac":
            mac = _check_mac(value, path, "src_mac")
            # 源地址必须是非零单播地址 (首字节最低位为 I/G 位: 0 单播, 1 组播)。
            if int(mac[:2], 16) & 1:
                raise FrameError("'src_mac' must be a unicast address", path)
            if mac == "00:00:00:00:00:00":
                raise FrameError("'src_mac' must be non-zero", path)
            values[field] = mac
        elif field == "vlan":
            values[field] = _check_vlan(value, path)
        elif field == "ether_type":
            values[field] = _check_ether_type(value, path)
        elif field == "payload_hex":
            values[field] = _check_payload_hex(value, path)
        else:  # fcs_valid
            values[field] = _check_fcs_valid(value, path)

    for field in FRAME_FIELD_ORDER:
        if field not in values:
            raise FrameError("missing field '%s'" % field, "$." + field)

    dst_mac = values["dst_mac"]
    src_mac = values["src_mac"]
    vlan = values["vlan"]
    ether_type = values["ether_type"]
    payload_hex = values["payload_hex"]
    fcs_valid = values["fcs_valid"]

    dst_first_octet = int(dst_mac[:2], 16)
    if dst_mac == "ff:ff:ff:ff:ff:ff":
        destination_type = "broadcast"
    elif dst_first_octet & 1:
        destination_type = "multicast"
    else:
        destination_type = "unicast"

    # 两个 MAC (12) + 可选 802.1Q 标签 (4) + 以太类型 (2) + 载荷 + FCS (4)。
    frame_length = (
        12 + 2 + len(payload_hex) // 2 + 4 + (4 if vlan is not None else 0)
    )

    # 多种问题并存时按 runt、oversize、bad_fcs 的顺序选择唯一 error_kind。
    max_length = MAX_FRAME_TAGGED if vlan is not None else MAX_FRAME_UNTAGGED
    if frame_length < MIN_FRAME_LENGTH:
        valid, error_kind = False, "runt"
    elif frame_length > max_length:
        valid, error_kind = False, "oversize"
    elif not fcs_valid:
        valid, error_kind = False, "bad_fcs"
    else:
        valid, error_kind = True, None

    return {
        "schema": FRAME_SCHEMA,
        "dst_mac": dst_mac,
        "src_mac": src_mac,
        "vlan": vlan,
        "ether_type": ether_type,
        "payload_hex": payload_hex,
        "frame_length": frame_length,
        "destination_type": destination_type,
        "valid": valid,
        "error_kind": error_kind,
    }


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


def cmd_frame(args):
    try:
        frame = read_frame_input(args.input)
    except ValueError as exc:
        emit_error("InputError", str(exc))
        return 2

    try:
        result = validate_frame(frame)
    except FrameError as exc:
        emit_error("FrameError", exc.message, exc.path)
        return 4

    sys.stdout.buffer.write(
        (json.dumps(result, ensure_ascii=False) + "\n").encode("utf-8")
    )
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="l2_switch.py",
        description=(
            "l2-switch: 二层以太网交换的行为仿真与配置框架。"
            "当前支持物理端口配置校验、确定性状态快照与以太帧合法性判定。"
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

    frame_parser = subparsers.add_parser(
        "frame",
        help="判定单个以太帧输入是否合法",
        description=(
            "读取 UTF-8 JSON 帧描述，校验字段与帧长/FCS，"
            "并向标准输出写入单行 JSON 判定结果；不涉及学习、查表与转发。"
        ),
        epilog=(
            "限制: 输入文件上限为 %d 字节；载荷上限为 %d 字节。"
            "未标记帧长度区间为 %d 至 %d，带标签帧为 %d 至 %d；"
            "相同输入的输出逐字节一致。"
            % (
                MAX_INPUT_BYTES,
                MAX_PAYLOAD_BYTES,
                MIN_FRAME_LENGTH,
                MAX_FRAME_UNTAGGED,
                MIN_FRAME_LENGTH,
                MAX_FRAME_TAGGED,
            )
        ),
    )
    frame_parser.add_argument(
        "--input",
        required=True,
        metavar="FILE",
        help="UTF-8 JSON 帧描述文件路径",
    )
    frame_parser.set_defaults(func=cmd_frame)

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
