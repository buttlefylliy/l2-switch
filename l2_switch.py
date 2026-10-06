#!/usr/bin/env python3
"""l2-switch: 二层以太网交换的行为仿真与配置框架。

提供物理端口配置校验与确定性状态快照 (ports 子命令)、
以太帧的离线合法性判定 (frame 子命令)，
以及场景内 MAC 学习、查表与转发的确定性仿真 (forward 子命令)。
仅使用 Python 标准库，不联网，行为确定。
"""

import argparse
import json
import re
import sys

# 受限输入的有限上限 (在 --help 中公开)。
MAX_PORTS = 4096
MAX_PORT_NAME_LEN = 64
MAX_FRAME_FILE_BYTES = 131072
MAX_PAYLOAD_BYTES = 65535
MAX_EVENTS = 10000

SCHEMA = "l2-switch/ports-v1"
FRAME_SCHEMA = "l2-switch/frame-v1"
FORWARD_SCHEMA = "l2-switch/forward-v1"

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
    """帧的结构、字段、类型、范围或格式不合法。path 为从 $ 开始的 JSON 路径。"""

    def __init__(self, message, path):
        super().__init__(message)
        self.message = message
        self.path = path


class StateError(Exception):
    """事件引用了不存在的端口等状态引用错误。path 为从 $ 开始的 JSON 路径。"""

    def __init__(self, message, path):
        super().__init__(message)
        self.message = message
        self.path = path


# 帧模型常量。
MAC_PATTERN = re.compile(r"[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}")
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"

MIN_ETHER_TYPE = 1536
MAX_ETHER_TYPE = 65535

MIN_FRAME_LENGTH = 64
MAX_UNTAGGED_FRAME_LENGTH = 1518
MAX_TAGGED_FRAME_LENGTH = 1522

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
VLAN_FIELD_RANGES = {"vid": (0, 4094), "pcp": (0, 7), "dei": (0, 1)}


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


def read_frame_input(path):
    """读取并解析 UTF-8 JSON 帧描述；读取/超限/解码/解析失败抛 ValueError。"""
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError:
        # 使用固定消息，避免平台/locale 文本差异影响确定性。
        raise ValueError("cannot read input file")
    if len(raw) > MAX_FRAME_FILE_BYTES:
        raise ValueError(
            "input file exceeds maximum size of %d bytes" % MAX_FRAME_FILE_BYTES
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("input file is not valid UTF-8")
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        # JSONDecodeError 是 ValueError 的子类；超长整数等解析限制同样归为输入错误。
        raise ValueError("input file is not valid JSON")


def _check_mac(value, path, field):
    if not isinstance(value, str):
        raise FrameError("'%s' must be a string" % field, path)
    if not MAC_PATTERN.fullmatch(value):
        raise FrameError(
            "'%s' must be six colon-separated two-digit hex octets" % field, path
        )
    # 输出统一小写。
    return value.lower()


def _check_dst_mac(value, path):
    return _check_mac(value, path, "dst_mac")


def _check_src_mac(value, path):
    mac = _check_mac(value, path, "src_mac")
    if mac == ZERO_MAC:
        raise FrameError("'src_mac' must be non-zero", path)
    if int(mac.split(":")[0], 16) & 1:
        raise FrameError("'src_mac' must be a unicast address", path)
    return mac


def _check_vlan(value, path):
    if value is None:
        return None
    if not isinstance(value, dict):
        raise FrameError("'vlan' must be null or an object", path)

    values = {}
    for field, item in value.items():
        item_path = path + "." + field
        if field not in VLAN_FIELD_SET:
            raise FrameError("unexpected field '%s'" % field, item_path)
        low, high = VLAN_FIELD_RANGES[field]
        # bool 是 int 的子类型，必须显式排除。
        if isinstance(item, bool) or not isinstance(item, int):
            raise FrameError("'%s' must be an integer" % field, item_path)
        if item < low or item > high:
            raise FrameError(
                "'%s' must be between %d and %d" % (field, low, high), item_path
            )
        values[field] = item

    for field in VLAN_FIELD_ORDER:
        if field not in values:
            raise FrameError("missing field '%s'" % field, path + "." + field)

    # 输出子对象按 vid、pcp、dei 的规范顺序排列。
    return {field: values[field] for field in VLAN_FIELD_ORDER}


def _check_ether_type(value, path):
    if isinstance(value, bool) or not isinstance(value, int):
        raise FrameError("'ether_type' must be an integer", path)
    if value < MIN_ETHER_TYPE or value > MAX_ETHER_TYPE:
        raise FrameError(
            "'ether_type' must be between %d and %d"
            % (MIN_ETHER_TYPE, MAX_ETHER_TYPE),
            path,
        )
    return value


def _check_payload_hex(value, path):
    if not isinstance(value, str):
        raise FrameError("'payload_hex' must be a string", path)
    if len(value) % 2 != 0:
        raise FrameError("'payload_hex' must have even length", path)
    if not re.fullmatch(r"[0-9A-Fa-f]*", value):
        raise FrameError("'payload_hex' must contain only hex digits", path)
    if len(value) // 2 > MAX_PAYLOAD_BYTES:
        raise FrameError(
            "'payload_hex' exceeds maximum of %d bytes" % MAX_PAYLOAD_BYTES, path
        )
    return value


def _check_fcs_valid(value, path):
    if not isinstance(value, bool):
        raise FrameError("'fcs_valid' must be a boolean", path)
    return value


FRAME_FIELD_CHECKS = {
    "dst_mac": _check_dst_mac,
    "src_mac": _check_src_mac,
    "vlan": _check_vlan,
    "ether_type": _check_ether_type,
    "payload_hex": _check_payload_hex,
    "fcs_valid": _check_fcs_valid,
}


def check_frame(frame, base_path="$"):
    """校验帧描述，返回规范化字段与派生判定 (不输出 schema)。

    base_path 为帧对象自身的 JSON 路径；frame 子命令传 "$"，
    forward 场景传 "$.events[i].frame"。
    """
    if not isinstance(frame, dict):
        raise FrameError("frame must be an object", base_path)

    # 按顶层键在输入中出现的顺序报告首个错误；遍历后再按规范顺序报告缺失字段。
    values = {}
    for field, value in frame.items():
        path = base_path + "." + field
        if field not in FRAME_FIELD_SET:
            raise FrameError("unexpected field '%s'" % field, path)
        values[field] = FRAME_FIELD_CHECKS[field](value, path)

    for field in FRAME_FIELD_ORDER:
        if field not in values:
            raise FrameError(
                "missing field '%s'" % field, base_path + "." + field
            )

    tagged = values["vlan"] is not None
    payload_bytes = len(values["payload_hex"]) // 2
    # 两个 MAC、可选四字节标签、两字节以太类型、载荷与四字节 FCS。
    frame_length = 6 + 6 + (4 if tagged else 0) + 2 + payload_bytes + 4

    dst_mac = values["dst_mac"]
    if dst_mac == BROADCAST_MAC:
        destination_type = "broadcast"
    elif int(dst_mac.split(":")[0], 16) & 1:
        destination_type = "multicast"
    else:
        destination_type = "unicast"

    # 问题并存时按 runt、oversize、bad_fcs 的顺序选择唯一 error_kind。
    if frame_length < MIN_FRAME_LENGTH:
        valid, error_kind = False, "runt"
    elif frame_length > (
        MAX_TAGGED_FRAME_LENGTH if tagged else MAX_UNTAGGED_FRAME_LENGTH
    ):
        valid, error_kind = False, "oversize"
    elif not values["fcs_valid"]:
        valid, error_kind = False, "bad_fcs"
    else:
        valid, error_kind = True, None

    values["tagged"] = tagged
    values["frame_length"] = frame_length
    values["destination_type"] = destination_type
    values["valid"] = valid
    values["error_kind"] = error_kind
    return values


def evaluate_frame(frame):
    """校验帧描述并返回判定结果对象 (键序固定)。"""
    values = check_frame(frame)
    return {
        "schema": FRAME_SCHEMA,
        "dst_mac": values["dst_mac"],
        "src_mac": values["src_mac"],
        "vlan": values["vlan"],
        "ether_type": values["ether_type"],
        "payload_hex": values["payload_hex"],
        "frame_length": values["frame_length"],
        "destination_type": values["destination_type"],
        "valid": values["valid"],
        "error_kind": values["error_kind"],
    }


def cmd_frame(args):
    try:
        frame = read_frame_input(args.input)
    except ValueError as exc:
        emit_error("InputError", str(exc))
        return 2

    try:
        result = evaluate_frame(frame)
    except FrameError as exc:
        emit_error("FrameError", exc.message, exc.path)
        return 4

    sys.stdout.buffer.write(
        (json.dumps(result, ensure_ascii=False) + "\n").encode("utf-8")
    )
    return 0


# forward 场景：未标记帧归入的默认 VLAN。
DEFAULT_VLAN_VID = 1

EVENT_FIELD_ORDER = ("ingress_port", "frame")
EVENT_FIELD_SET = frozenset(EVENT_FIELD_ORDER)


def read_scenario(path):
    """读取并解析 UTF-8 JSON 场景；读取/解码/解析失败抛 ValueError。"""
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError:
        # 使用固定消息，避免平台/locale 文本差异影响确定性。
        raise ValueError("cannot read scenario file")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("scenario file is not valid UTF-8")
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        # JSONDecodeError 是 ValueError 的子类；超长整数等解析限制同样归为输入错误。
        raise ValueError("scenario file is not valid JSON")


def validate_event(item, index, port_names):
    """校验单个事件：返回 (ingress_port 名称, 规范化帧字段)。

    按事件字段在输入中出现的顺序报告首个错误；端口引用错误为 StateError，
    其余事件/帧错误为 FrameError。
    """
    base = "$.events[%d]" % index

    if not isinstance(item, dict):
        raise FrameError("event must be an object", base)

    values = {}
    for field, value in item.items():
        path = base + "." + field
        if field not in EVENT_FIELD_SET:
            raise FrameError("unexpected field '%s'" % field, path)
        if field == "ingress_port":
            if not isinstance(value, str):
                raise FrameError("'ingress_port' must be a string", path)
            if value not in port_names:
                raise StateError("unknown ingress_port '%s'" % value, path)
            values[field] = value
        else:
            values[field] = check_frame(value, path)

    for field in EVENT_FIELD_ORDER:
        if field not in values:
            raise FrameError("missing field '%s'" % field, base + "." + field)

    return values["ingress_port"], values["frame"]


def validate_scenario(scenario):
    """先全量校验整个场景，返回 (端口快照, 有序事件列表)。

    任何结构、字段或引用错误都在此阶段抛出，处理首个事件前即可发现。
    """
    if not isinstance(scenario, dict):
        raise ConfigError("top-level scenario must be an object", "$")

    # 按顶层键在输入中出现的顺序报告首个错误。
    for field in scenario:
        if field not in ("ports", "events"):
            raise ConfigError("unexpected field '%s'" % field, "$." + field)

    if "ports" not in scenario:
        raise ConfigError("missing field 'ports'", "$.ports")

    # 复用 ports 子命令的全部校验规则与错误路径 ($.ports[...])。
    snapshot = validate({"ports": scenario["ports"]})

    if "events" not in scenario:
        raise FrameError("missing field 'events'", "$.events")

    events = scenario["events"]
    if not isinstance(events, list):
        raise FrameError("'events' must be an array", "$.events")
    if len(events) > MAX_EVENTS:
        raise FrameError(
            "number of events exceeds maximum of %d" % MAX_EVENTS, "$.events"
        )

    port_names = frozenset(port["name"] for port in snapshot["ports"])

    checked_events = []
    for index, item in enumerate(events):
        checked_events.append(validate_event(item, index, port_names))

    return snapshot, checked_events


def simulate(snapshot, events):
    """按事件顺序执行场景内动态学习与转发，返回固定键序的结果对象。"""
    # 快照已按 name 的 Unicode 码点升序排列。
    port_info = {
        port["name"]: (port["can_forward"], port["can_learn"])
        for port in snapshot["ports"]
    }
    forwarding_ports = [
        port["name"] for port in snapshot["ports"] if port["can_forward"]
    ]

    # (vid, 小写单播源 MAC) -> 最新出现端口名；同键从另一端口出现即迁移。
    table = {}
    results = []

    for index, (ingress, frame) in enumerate(events):
        vid = frame["vlan"]["vid"] if frame["tagged"] else DEFAULT_VLAN_VID
        src_mac = frame["src_mac"]
        dst_mac = frame["dst_mac"]

        result = {
            "event": index,
            "vlan": vid,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "decision": None,
            "egress_ports": [],
        }

        can_forward, can_learn = port_info[ingress]

        # runt、oversize、bad_fcs 一律 dropped：不学习、不查表、没有出口。
        # 入端口不能转发同样确定为 dropped。
        if not frame["valid"] or not can_forward:
            result["decision"] = "dropped"
            results.append(result)
            continue

        # 合法帧的源 MAC 已由帧校验保证为非零单播；先学习 (含迁移) 再查表。
        if can_learn:
            table[(vid, src_mac)] = ingress

        if frame["destination_type"] == "unicast":
            learned_port = table.get((vid, dst_mac))
            if learned_port is None:
                # 未命中单播与广播、组播同样泛洪。
                result["decision"] = "flooded"
                result["egress_ports"] = [
                    name for name in forwarding_ports if name != ingress
                ]
            elif learned_port == ingress:
                result["decision"] = "filtered"
            else:
                result["decision"] = "forwarded"
                result["egress_ports"] = [learned_port]
        else:
            result["decision"] = "flooded"
            result["egress_ports"] = [
                name for name in forwarding_ports if name != ingress
            ]

        results.append(result)

    # VLAN 数值升序，再按 MAC 字符串的 Unicode 码点升序。
    mac_table = [
        {"vlan": vid, "mac": mac, "port": port}
        for (vid, mac), port in sorted(table.items())
    ]

    return {"schema": FORWARD_SCHEMA, "results": results, "mac_table": mac_table}


def cmd_forward(args):
    try:
        scenario = read_scenario(args.scenario)
    except ValueError as exc:
        emit_error("InputError", str(exc))
        return 2

    try:
        snapshot, events = validate_scenario(scenario)
    except ValueError as exc:
        # 防御性归类：正常校验路径不应产生裸 ValueError。
        emit_error("InputError", str(exc))
        return 2
    except StateError as exc:
        emit_error("StateError", exc.message, exc.path)
        return 5
    except ConfigError as exc:
        emit_error("ConfigError", exc.message, exc.path)
        return 3
    except FrameError as exc:
        emit_error("FrameError", exc.message, exc.path)
        return 4

    result = simulate(snapshot, events)
    sys.stdout.buffer.write(
        (json.dumps(result, ensure_ascii=False) + "\n").encode("utf-8")
    )
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="l2_switch.py",
        description=(
            "l2-switch: 二层以太网交换的行为仿真与配置框架。"
            "支持物理端口配置校验与确定性状态快照、以太帧的离线合法性判定，"
            "以及场景内 MAC 学习、查表与转发的确定性仿真。"
        ),
        epilog=(
            "限制: 端口数量上限为 %d；单个端口 name 长度上限为 %d 个字符；"
            "帧描述文件大小上限为 %d 字节。仅使用 Python 标准库，不联网。"
            % (MAX_PORTS, MAX_PORT_NAME_LEN, MAX_FRAME_FILE_BYTES)
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
        help="判定单个以太帧是否合法并输出确定性结果",
        description=(
            "读取 UTF-8 JSON 帧描述，校验字段并向标准输出写入单行 JSON 判定结果。"
            "仅做合法性判定，不涉及学习、查表和转发。"
        ),
        epilog=(
            "限制: 输入文件大小上限为 %d 字节；payload_hex 最多表示 %d 字节。"
            "相同输入的输出逐字节一致。"
            % (MAX_FRAME_FILE_BYTES, MAX_PAYLOAD_BYTES)
        ),
    )
    frame_parser.add_argument(
        "--input",
        required=True,
        metavar="FILE",
        help=(
            "UTF-8 JSON 帧描述文件路径，顶层对象包含 dst_mac、src_mac、vlan、"
            "ether_type、payload_hex、fcs_valid"
        ),
    )
    frame_parser.set_defaults(func=cmd_frame)

    forward_parser = subparsers.add_parser(
        "forward",
        help="在场景内执行 MAC 学习、查表与转发并输出确定性结果",
        description=(
            "读取 UTF-8 JSON 场景 (ports 配置与按序排列的 events)，"
            "先完整校验场景，再按事件顺序仿真，向标准输出写入单行 JSON："
            "逐事件结果与最终动态表快照。动态表仅存在于本次场景内。"
        ),
        epilog=(
            "限制: 端口数量上限为 %d；事件数量上限为 %d。"
            "未标记帧归入 VLAN 1，带标签帧按 vid 隔离 (vid 0 为独立域)。"
            "出口按端口 name 的 Unicode 码点升序排列；表项按 VLAN 数值升序、"
            "再按 MAC 的 Unicode 码点升序排列；相同输入的输出逐字节一致。"
            % (MAX_PORTS, MAX_EVENTS)
        ),
    )
    forward_parser.add_argument(
        "--scenario",
        required=True,
        metavar="FILE",
        help=(
            "UTF-8 JSON 场景文件路径，顶层包含 ports 数组与 events 数组；"
            "每个事件包含 ingress_port 与完整帧描述"
        ),
    )
    forward_parser.set_defaults(func=cmd_forward)

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
