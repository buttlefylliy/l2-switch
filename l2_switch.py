#!/usr/bin/env python3
"""l2-switch: 二层以太网交换的行为仿真与配置框架。

提供物理端口配置校验与确定性状态快照 (ports 子命令)、
以太帧的离线合法性判定 (frame 子命令)，
以及场景内的动态 MAC 学习、静态表项、查表与转发 (forward 子命令)。
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
MAX_STATIC_ENTRIES = 10000
MAX_ACL_RULES = 4096

SCHEMA = "l2-switch/ports-v1"
FRAME_SCHEMA = "l2-switch/frame-v1"
FORWARD_SCHEMA = "l2-switch/forward-v1"
# 未标记帧归入 VLAN 1；带标签帧按 vid 隔离，vid 0 也是独立域。
UNTAGGED_VID = 1

# 每个端口允许的字段及其规范顺序；额外字段一律拒绝。
# access_vid 为可选的接入 VLAN 归属，trunk_vids 为可选的中继 VLAN 允许数组，
# 二者互斥，缺省时都不出现在快照中。
# dynamic_mac_limit 为可选的端口动态 MAC 学习数量上限 (端口安全)，
# 缺省时不出现在快照中且保持无限制语义。
FIELD_ORDER = (
    "name",
    "kind",
    "admin_state",
    "forwarding_state",
    "learning",
    "speed_mbps",
    "duplex",
    "access_vid",
    "trunk_vids",
    "dynamic_mac_limit",
)
FIELD_SET = frozenset(FIELD_ORDER)
OPTIONAL_FIELDS = frozenset(("access_vid", "trunk_vids", "dynamic_mac_limit"))

MIN_ACCESS_VID = 1
MAX_ACCESS_VID = 4094

MIN_TRUNK_VID = 1
MAX_TRUNK_VID = 4094

MIN_DYNAMIC_MAC_LIMIT = 1
MAX_DYNAMIC_MAC_LIMIT = 10000

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
    """引用了不存在的物理端口等运行期状态错误。path 为从 $ 开始的 JSON 路径。"""

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


def _check_access_vid(value, path):
    # bool 是 int 的子类型，必须显式排除。
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError("'access_vid' must be an integer", path)
    if value < MIN_ACCESS_VID or value > MAX_ACCESS_VID:
        raise ConfigError(
            "'access_vid' must be between %d and %d"
            % (MIN_ACCESS_VID, MAX_ACCESS_VID),
            path,
        )
    return value


def _check_trunk_vids(value, path):
    # 非空整数数组声明中继端口允许承载的 802.1Q VLAN；快照按数值升序规范化。
    if not isinstance(value, list):
        raise ConfigError("'trunk_vids' must be an array", path)
    if len(value) == 0:
        raise ConfigError("'trunk_vids' must be a non-empty array", path)
    seen = set()
    for index, item in enumerate(value):
        item_path = "%s[%d]" % (path, index)
        # bool 是 int 的子类型，必须显式排除。
        if isinstance(item, bool) or not isinstance(item, int):
            raise ConfigError(
                "'trunk_vids' elements must be integers", item_path
            )
        if item < MIN_TRUNK_VID or item > MAX_TRUNK_VID:
            raise ConfigError(
                "'trunk_vids' elements must be between %d and %d"
                % (MIN_TRUNK_VID, MAX_TRUNK_VID),
                item_path,
            )
        if item in seen:
            raise ConfigError(
                "'trunk_vids' must not contain duplicate values", item_path
            )
        seen.add(item)
    return sorted(value)


def _check_dynamic_mac_limit(value, path):
    # 可选的端口动态 MAC 学习数量上限；bool 是 int 的子类型，必须显式排除。
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError("'dynamic_mac_limit' must be an integer", path)
    if value < MIN_DYNAMIC_MAC_LIMIT or value > MAX_DYNAMIC_MAC_LIMIT:
        raise ConfigError(
            "'dynamic_mac_limit' must be between %d and %d"
            % (MIN_DYNAMIC_MAC_LIMIT, MAX_DYNAMIC_MAC_LIMIT),
            path,
        )
    return value


FIELD_CHECKS = {
    "name": _check_name,
    "kind": _check_kind,
    "admin_state": _check_admin_state,
    "forwarding_state": _check_forwarding_state,
    "learning": _check_learning,
    "speed_mbps": _check_speed_mbps,
    "duplex": _check_duplex,
    "access_vid": _check_access_vid,
    "trunk_vids": _check_trunk_vids,
    "dynamic_mac_limit": _check_dynamic_mac_limit,
}


def validate_port(item, index, seen):
    """校验单个端口，按输入字段顺序返回 (有序字段, can_forward, can_learn)。

    按字段在输入中出现的顺序报告首个错误 (未知字段、非法值或重复 name 立即
    报告)；仅当所有出现字段均合法后，才检查 access_vid 与 trunk_vids 互斥，
    再按规范字段顺序报告首个缺失字段 (可选字段不参与缺失检查)。
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

    if "access_vid" in values and "trunk_vids" in values:
        raise ConfigError(
            "'trunk_vids' and 'access_vid' are mutually exclusive",
            base + ".trunk_vids",
        )

    for field in FIELD_ORDER:
        if field not in values and field not in OPTIONAL_FIELDS:
            raise ConfigError("missing field '%s'" % field, base + "." + field)

    admin_state = values["admin_state"]
    forwarding_state = values["forwarding_state"]
    learning = values["learning"]
    can_forward = admin_state == "up" and forwarding_state == "forwarding"
    can_learn = can_forward and learning

    ordered = [(field, values[field]) for field in FIELD_ORDER if field in values]
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


def evaluate_frame(frame, base="$"):
    """校验帧描述并返回判定结果对象 (键序固定)。

    base 为帧对象在 JSON 中的路径前缀；frame 子命令使用 "$"，
    forward 场景中的嵌套帧使用 "$.events[i].frame"。
    """
    if not isinstance(frame, dict):
        raise FrameError("top-level frame must be an object", base)

    # 按顶层键在输入中出现的顺序报告首个错误；遍历后再按规范顺序报告缺失字段。
    values = {}
    for field, value in frame.items():
        path = base + "." + field
        if field not in FRAME_FIELD_SET:
            raise FrameError("unexpected field '%s'" % field, path)
        values[field] = FRAME_FIELD_CHECKS[field](value, path)

    for field in FRAME_FIELD_ORDER:
        if field not in values:
            raise FrameError("missing field '%s'" % field, base + "." + field)

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

    return {
        "schema": FRAME_SCHEMA,
        "dst_mac": dst_mac,
        "src_mac": values["src_mac"],
        "vlan": values["vlan"],
        "ether_type": values["ether_type"],
        "payload_hex": values["payload_hex"],
        "frame_length": frame_length,
        "destination_type": destination_type,
        "valid": valid,
        "error_kind": error_kind,
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


EVENT_FIELD_ORDER = ("ingress_port", "frame", "time_ms")
EVENT_FIELD_SET = frozenset(EVENT_FIELD_ORDER)

# 老化时钟的显式范围；bool 是 int 子类型，校验时必须显式排除。
MIN_AGING_TIME_MS = 1
MAX_AGING_TIME_MS = 9223372036854775807
MIN_EVENT_TIME_MS = 0
MAX_EVENT_TIME_MS = 9223372036854775807


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


def _check_include_counters(value, path):
    # include_counters 是场景级开关，类型错误归 ConfigError。
    if not isinstance(value, bool):
        raise ConfigError("'include_counters' must be a boolean", path)
    return value


def _check_include_fdb_events(value, path):
    # include_fdb_events 是场景级开关，类型错误归 ConfigError。
    if not isinstance(value, bool):
        raise ConfigError("'include_fdb_events' must be a boolean", path)
    return value


def _check_aging_time_ms(value, path):
    # aging_time_ms 是场景级配置字段，类型/范围错误归 ConfigError。
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError("'aging_time_ms' must be an integer", path)
    if value < MIN_AGING_TIME_MS or value > MAX_AGING_TIME_MS:
        raise ConfigError(
            "'aging_time_ms' must be between %d and %d"
            % (MIN_AGING_TIME_MS, MAX_AGING_TIME_MS),
            path,
        )
    return value


def _check_event_time_ms(value, path):
    # time_ms 是事件字段，类型/范围错误归 FrameError。
    if isinstance(value, bool) or not isinstance(value, int):
        raise FrameError("'time_ms' must be an integer", path)
    if value < MIN_EVENT_TIME_MS or value > MAX_EVENT_TIME_MS:
        raise FrameError(
            "'time_ms' must be between %d and %d"
            % (MIN_EVENT_TIME_MS, MAX_EVENT_TIME_MS),
            path,
        )
    return value


# 静态表项的字段及其规范顺序；额外字段一律拒绝。
STATIC_FIELD_ORDER = ("vid", "mac", "port")
STATIC_FIELD_SET = frozenset(STATIC_FIELD_ORDER)


def _check_static_vid(value, path):
    # 静态项属于场景级配置，类型/范围错误归 ConfigError。
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError("'vid' must be an integer", path)
    if value < 0 or value > 4094:
        raise ConfigError("'vid' must be between 0 and 4094", path)
    return value


def _check_static_mac(value, path):
    if not isinstance(value, str):
        raise ConfigError("'mac' must be a string", path)
    if not MAC_PATTERN.fullmatch(value):
        raise ConfigError(
            "'mac' must be six colon-separated two-digit hex octets", path
        )
    # 表内统一小写。
    mac = value.lower()
    if mac == ZERO_MAC:
        raise ConfigError("'mac' must be non-zero", path)
    if int(mac.split(":")[0], 16) & 1:
        raise ConfigError("'mac' must be a unicast address", path)
    return mac


def _check_static_port(value, path):
    if not isinstance(value, str):
        raise ConfigError("'port' must be a string", path)
    return value


STATIC_FIELD_CHECKS = {
    "vid": _check_static_vid,
    "mac": _check_static_mac,
    "port": _check_static_port,
}


def validate_static_table(static_table, port_by_name):
    """校验静态表，返回键为 (vid, 小写 mac)、值为端口 name 的映射。

    按表项在输入中出现的顺序报告首个错误：每项先按输入字段顺序检查未知
    字段与非法值，再按规范顺序报告缺失字段，然后检查 (vid, mac) 组合重复，
    最后检查 port 引用 (未知端口归 StateError)。
    """
    if not isinstance(static_table, list):
        raise ConfigError("'static_table' must be an array", "$.static_table")
    if len(static_table) > MAX_STATIC_ENTRIES:
        raise ConfigError(
            "number of static entries exceeds maximum of %d"
            % MAX_STATIC_ENTRIES,
            "$.static_table",
        )

    static_map = {}
    for index, item in enumerate(static_table):
        base = "$.static_table[%d]" % index
        if not isinstance(item, dict):
            raise ConfigError("static entry must be an object", base)

        values = {}
        for field, value in item.items():
            path = base + "." + field
            if field not in STATIC_FIELD_SET:
                raise ConfigError("unexpected field '%s'" % field, path)
            values[field] = STATIC_FIELD_CHECKS[field](value, path)

        for field in STATIC_FIELD_ORDER:
            if field not in values:
                raise ConfigError("missing field '%s'" % field, base + "." + field)

        key = (values["vid"], values["mac"])
        if key in static_map:
            raise ConfigError(
                "duplicate static entry for vid %d and mac '%s'" % key, base
            )
        port = values["port"]
        if port not in port_by_name:
            raise StateError("unknown port '%s'" % port, base + ".port")
        static_map[key] = port

    return static_map


# 镜像会话 (入口/出口) 的字段及其规范顺序；额外字段一律拒绝。
MIRROR_FIELD_ORDER = ("source_ports", "destination_port")
MIRROR_FIELD_SET = frozenset(MIRROR_FIELD_ORDER)
INGRESS_MIRROR_BASE = "$.ingress_mirror"
EGRESS_MIRROR_BASE = "$.egress_mirror"


def validate_mirror_session(mirror, base, session_field, port_by_name, port_count):
    """校验一个镜像会话，返回 (源端口 name 集合, 目的端口 name)。

    session_field 为顶层字段名，用于错误消息；base 为该字段的 JSON 路径。
    结构、字段、元素类型、非空、不重复、数量上限以及源/目的重叠均为
    ConfigError；源或目的名称未引用已配置端口为 StateError。
    """
    if not isinstance(mirror, dict):
        raise ConfigError("'%s' must be an object" % session_field, base)

    # 按字段在输入中出现的顺序报告首个错误。
    values = {}
    for field, value in mirror.items():
        path = base + "." + field
        if field not in MIRROR_FIELD_SET:
            raise ConfigError("unexpected field '%s'" % field, path)
        values[field] = value

    for field in MIRROR_FIELD_ORDER:
        if field not in values:
            raise ConfigError(
                "missing field '%s'" % field, base + "." + field
            )

    source_ports = values["source_ports"]
    source_path = base + ".source_ports"
    if not isinstance(source_ports, list):
        raise ConfigError("'source_ports' must be an array", source_path)
    if len(source_ports) == 0:
        raise ConfigError("'source_ports' must be a non-empty array", source_path)
    if len(source_ports) > port_count:
        raise ConfigError(
            "'source_ports' must not exceed the total number of ports (%d)"
            % port_count,
            source_path,
        )

    sources = []
    seen = set()
    for index, item in enumerate(source_ports):
        item_path = "%s[%d]" % (source_path, index)
        if not isinstance(item, str):
            raise ConfigError(
                "'source_ports' elements must be strings", item_path
            )
        if item in seen:
            raise ConfigError(
                "'source_ports' must not contain duplicate values", item_path
            )
        seen.add(item)
        sources.append(item)

    destination = values["destination_port"]
    destination_path = base + ".destination_port"
    if not isinstance(destination, str):
        raise ConfigError(
            "'destination_port' must be a string", destination_path
        )
    if destination in seen:
        raise ConfigError(
            "'destination_port' must not appear in 'source_ports'",
            destination_path,
        )

    # 结构全部合法后再检查端口引用 (未知端口归 StateError)。
    for index, name in enumerate(sources):
        if name not in port_by_name:
            raise StateError(
                "unknown port '%s'" % name, "%s[%d]" % (source_path, index)
            )
    if destination not in port_by_name:
        raise StateError(
            "unknown port '%s'" % destination, destination_path
        )

    return seen, destination


def validate_ingress_mirror(mirror, port_by_name, port_count):
    """校验唯一的入口镜像会话，返回 (源端口 name 集合, 目的端口 name)。"""
    return validate_mirror_session(
        mirror, INGRESS_MIRROR_BASE, "ingress_mirror",
        port_by_name, port_count,
    )


def validate_egress_mirror(mirror, port_by_name, port_count):
    """校验唯一的出口镜像会话，返回 (源端口 name 集合, 目的端口 name)。"""
    return validate_mirror_session(
        mirror, EGRESS_MIRROR_BASE, "egress_mirror",
        port_by_name, port_count,
    )


# 入口 ACL 规则的字段及其规范顺序；额外字段一律拒绝。
# action 为必填；src_mac、dst_mac、vid、ether_type、pcp 为可选匹配字段，
# 至少出现一个，省略的字段视为通配，出现的字段须同时精确匹配。
# set_pcp 仅允许出现在 action 为 remark_pcp 的规则中，给出重标记后的 PCP。
ACL_FIELD_ORDER = (
    "action",
    "src_mac",
    "dst_mac",
    "vid",
    "ether_type",
    "pcp",
    "set_pcp",
)
ACL_FIELD_SET = frozenset(ACL_FIELD_ORDER)
ACL_MATCH_FIELD_ORDER = ("src_mac", "dst_mac", "vid", "ether_type", "pcp")
ACL_ACTIONS = frozenset(("allow", "drop", "remark_pcp"))

MIN_ACL_VID = 0
MAX_ACL_VID = 4094
MIN_ACL_PCP = 0
MAX_ACL_PCP = 7


def _check_acl_action(value, path):
    if not isinstance(value, str) or value not in ACL_ACTIONS:
        raise ConfigError(
            "'action' must be 'allow', 'drop' or 'remark_pcp'", path
        )
    return value


def _check_acl_src_mac(value, path):
    return _check_acl_mac(value, path, "src_mac")


def _check_acl_dst_mac(value, path):
    return _check_acl_mac(value, path, "dst_mac")


def _check_acl_mac(value, path, field):
    # 匹配字段只做格式校验并规范化为小写；不限制单播/组播/广播。
    if not isinstance(value, str):
        raise ConfigError("'%s' must be a string" % field, path)
    if not MAC_PATTERN.fullmatch(value):
        raise ConfigError(
            "'%s' must be six colon-separated two-digit hex octets" % field,
            path,
        )
    return value.lower()


def _check_acl_vid(value, path):
    # vid 匹配内部 VLAN (含带标签帧的 vid 0)；bool 是 int 子类型，须显式排除。
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError("'vid' must be an integer", path)
    if value < MIN_ACL_VID or value > MAX_ACL_VID:
        raise ConfigError(
            "'vid' must be between %d and %d" % (MIN_ACL_VID, MAX_ACL_VID),
            path,
        )
    return value


def _check_acl_ether_type(value, path):
    # bool 是 int 的子类型，必须显式排除。
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError("'ether_type' must be an integer", path)
    if value < MIN_ETHER_TYPE or value > MAX_ETHER_TYPE:
        raise ConfigError(
            "'ether_type' must be between %d and %d"
            % (MIN_ETHER_TYPE, MAX_ETHER_TYPE),
            path,
        )
    return value


def _check_acl_pcp(value, path):
    # pcp 只匹配带 802.1Q 标签的帧；bool 是 int 子类型，须显式排除。
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError("'pcp' must be an integer", path)
    if value < MIN_ACL_PCP or value > MAX_ACL_PCP:
        raise ConfigError(
            "'pcp' must be between %d and %d" % (MIN_ACL_PCP, MAX_ACL_PCP),
            path,
        )
    return value


def _check_acl_set_pcp(value, path):
    # set_pcp 为 remark_pcp 规则重标记后的确定 PCP；bool 是 int 子类型，
    # 须显式排除。
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError("'set_pcp' must be an integer", path)
    if value < MIN_ACL_PCP or value > MAX_ACL_PCP:
        raise ConfigError(
            "'set_pcp' must be between %d and %d" % (MIN_ACL_PCP, MAX_ACL_PCP),
            path,
        )
    return value


ACL_FIELD_CHECKS = {
    "action": _check_acl_action,
    "src_mac": _check_acl_src_mac,
    "dst_mac": _check_acl_dst_mac,
    "vid": _check_acl_vid,
    "ether_type": _check_acl_ether_type,
    "pcp": _check_acl_pcp,
    "set_pcp": _check_acl_set_pcp,
}


def validate_ingress_acl(acl):
    """校验入口 ACL，返回按输入顺序排列的已校验规则列表。

    每条规则先按输入字段顺序报告首个错误 (未知字段或非法值)，再检查
    缺失的 action，然后按动作检查 set_pcp 与匹配字段的组合约束：
    remark_pcp 规则必须含 set_pcp 与 pcp 匹配字段 (pcp 保证只命中带
    802.1Q 标签的帧)，allow、drop 规则不得携带 set_pcp 且至少含一个
    匹配字段。规则数量上限为 MAX_ACL_RULES。
    """
    if not isinstance(acl, list):
        raise ConfigError("'ingress_acl' must be an array", "$.ingress_acl")
    if len(acl) > MAX_ACL_RULES:
        raise ConfigError(
            "number of acl rules exceeds maximum of %d" % MAX_ACL_RULES,
            "$.ingress_acl",
        )

    rules = []
    for index, item in enumerate(acl):
        base = "$.ingress_acl[%d]" % index
        if not isinstance(item, dict):
            raise ConfigError("acl rule must be an object", base)

        values = {}
        for field, value in item.items():
            path = base + "." + field
            if field not in ACL_FIELD_SET:
                raise ConfigError("unexpected field '%s'" % field, path)
            values[field] = ACL_FIELD_CHECKS[field](value, path)

        if "action" not in values:
            raise ConfigError("missing field 'action'", base + ".action")
        if values["action"] == "remark_pcp":
            if "set_pcp" not in values:
                raise ConfigError("missing field 'set_pcp'", base + ".set_pcp")
            if "pcp" not in values:
                raise ConfigError(
                    "remark_pcp rule must specify match field 'pcp'",
                    base + ".pcp",
                )
        else:
            if "set_pcp" in values:
                raise ConfigError(
                    "'set_pcp' is only allowed with action 'remark_pcp'",
                    base + ".set_pcp",
                )
            if not any(field in values for field in ACL_MATCH_FIELD_ORDER):
                raise ConfigError(
                    "acl rule must specify at least one match field", base
                )
        rules.append(values)

    return rules


def acl_rule_matches(rule, src_mac, dst_mac, vid, ether_type, pcp):
    """无状态精确匹配：规则中出现的字段全部相等才命中，省略字段视为通配。

    pcp 只匹配带 802.1Q 标签的帧；未标记帧 (pcp 为 None) 不命中任何
    带 pcp 条件的规则。
    """
    if "src_mac" in rule and rule["src_mac"] != src_mac:
        return False
    if "dst_mac" in rule and rule["dst_mac"] != dst_mac:
        return False
    if "vid" in rule and rule["vid"] != vid:
        return False
    if "ether_type" in rule and rule["ether_type"] != ether_type:
        return False
    if "pcp" in rule and (pcp is None or rule["pcp"] != pcp):
        return False
    return True


def validate_scenario(scenario):
    """先完整校验场景再处理；任何结构、字段、引用错误都在处理首个事件前抛出。

    返回 (port_by_name, validated_events, aging_time_ms, include_counters,
    static_map, include_fdb_events, mirror_sources, mirror_destination,
    egress_mirror_sources, egress_mirror_destination, acl_rules)：
    port_by_name 将端口 name 映射为
    {"can_forward", "can_learn", "access_vid", "trunk_vids",
    "dynamic_mac_limit"} (未配置对应 VLAN 模式或学习上限时为 None)；
    validated_events 每项为 (ingress_name, 帧判定结果, time_ms)，
    未启用老化时 aging_time_ms 与每项 time_ms 均为 None；
    include_counters 缺省或为 false 时为 False，输出不含 counters；
    static_map 键为 (vid, 小写 mac)、值为端口 name，未提供 static_table
    或其为空数组时为空映射，输出不含 static_table；
    include_fdb_events 缺省或为 false 时为 False，输出不含 fdb_events；
    mirror_sources 为入口镜像源端口 name 集合，mirror_destination 为镜像
    目的端口 name，未提供 ingress_mirror 时二者均为 None；
    egress_mirror_sources/egress_mirror_destination 对 egress_mirror 同义，
    未提供 egress_mirror 时二者均为 None；
    acl_rules 为按输入顺序排列的已校验入口 ACL 规则列表，
    未提供 ingress_acl 时为 None。
    """
    if not isinstance(scenario, dict):
        raise ConfigError("top-level scenario must be an object", "$")

    # 按顶层键在输入中出现的顺序报告首个错误；遍历后再按规范顺序报告缺失字段。
    seen_fields = set()
    aging_time_ms = None
    include_counters = False
    include_fdb_events = False
    for field, value in scenario.items():
        path = "$." + field
        if field == "ports":
            seen_fields.add(field)
        elif field == "events":
            seen_fields.add(field)
        elif field == "aging_time_ms":
            # 记录校验后的值；是否启用老化完全由该字段是否出现决定。
            aging_time_ms = _check_aging_time_ms(value, path)
            seen_fields.add(field)
        elif field == "include_counters":
            include_counters = _check_include_counters(value, path)
            seen_fields.add(field)
        elif field == "include_fdb_events":
            include_fdb_events = _check_include_fdb_events(value, path)
            seen_fields.add(field)
        elif field == "static_table":
            # 记录字段出现；结构与引用校验在 ports 校验完成后进行。
            seen_fields.add(field)
        elif field == "ingress_mirror":
            # 记录字段出现；结构与引用校验在 ports 校验完成后进行。
            seen_fields.add(field)
        elif field == "egress_mirror":
            # 记录字段出现；结构与引用校验在 ports 校验完成后进行。
            seen_fields.add(field)
        elif field == "ingress_acl":
            # 记录字段出现；结构校验在 ports 校验完成后进行。
            seen_fields.add(field)
        else:
            raise ConfigError("unexpected field '%s'" % field, path)

    if "ports" not in seen_fields:
        raise ConfigError("missing field 'ports'", "$.ports")
    if "events" not in seen_fields:
        raise FrameError("missing field 'events'", "$.events")

    ports = scenario["ports"]
    if not isinstance(ports, list):
        raise ConfigError("'ports' must be an array", "$.ports")
    if len(ports) > MAX_PORTS:
        raise ConfigError(
            "number of ports exceeds maximum of %d" % MAX_PORTS, "$.ports"
        )

    events = scenario["events"]
    if not isinstance(events, list):
        raise FrameError("'events' must be an array", "$.events")
    if len(events) > MAX_EVENTS:
        raise FrameError(
            "number of events exceeds maximum of %d" % MAX_EVENTS, "$.events"
        )

    port_names = set()
    port_by_name = {}
    for index, item in enumerate(ports):
        ordered, can_forward, can_learn = validate_port(item, index, port_names)
        fields = dict(ordered)
        name = fields["name"]
        port_by_name[name] = {
            "can_forward": can_forward,
            "can_learn": can_learn,
            # 未配置 access_vid 时为 None，表示不参与接入口 VLAN 限制。
            "access_vid": fields.get("access_vid"),
            # 未配置 trunk_vids 时为 None，表示不参与中继 VLAN 限制；
            # 配置时为按数值升序规范化后的允许 VID 数组。
            "trunk_vids": fields.get("trunk_vids"),
            # 未配置 dynamic_mac_limit 时为 None，表示动态学习数量无限制。
            "dynamic_mac_limit": fields.get("dynamic_mac_limit"),
        }

    # 静态表在 ports 之后、events 之前校验；端口引用检查依赖 port_by_name。
    static_map = {}
    if "static_table" in seen_fields:
        static_map = validate_static_table(
            scenario["static_table"], port_by_name
        )

    # 入口镜像会话同样在 ports 之后、events 之前校验。
    mirror_sources = None
    mirror_destination = None
    if "ingress_mirror" in seen_fields:
        mirror_sources, mirror_destination = validate_ingress_mirror(
            scenario["ingress_mirror"], port_by_name, len(port_by_name)
        )

    # 出口镜像会话同样在 ports 之后、events 之前校验。
    egress_mirror_sources = None
    egress_mirror_destination = None
    if "egress_mirror" in seen_fields:
        egress_mirror_sources, egress_mirror_destination = validate_egress_mirror(
            scenario["egress_mirror"], port_by_name, len(port_by_name)
        )

    # 入口 ACL 不引用端口，同样在 ports 之后、events 之前校验。
    acl_rules = None
    if "ingress_acl" in seen_fields:
        acl_rules = validate_ingress_acl(scenario["ingress_acl"])

    validated_events = []
    last_time_ms = None
    for index, item in enumerate(events):
        base = "$.events[%d]" % index
        if not isinstance(item, dict):
            raise FrameError("event must be an object", base)

        values = {}
        for field, value in item.items():
            path = base + "." + field
            if field not in EVENT_FIELD_SET:
                raise FrameError("unexpected field '%s'" % field, path)
            if field == "time_ms":
                if aging_time_ms is None:
                    # 未启用老化时不接受孤立的 time_ms，按既有未知字段约定拒绝。
                    raise FrameError("unexpected field 'time_ms'", path)
                value = _check_event_time_ms(value, path)
                # 时间按事件顺序单调不减；倒退在处理前即报错。
                if last_time_ms is not None and value < last_time_ms:
                    raise FrameError(
                        "'time_ms' must be non-decreasing across events", path
                    )
                last_time_ms = value
            values[field] = value

        for field in ("ingress_port", "frame"):
            if field not in values:
                raise FrameError(
                    "missing field '%s'" % field, base + "." + field
                )
        if aging_time_ms is not None and "time_ms" not in values:
            raise FrameError("missing field 'time_ms'", base + ".time_ms")

        ingress = values["ingress_port"]
        if not isinstance(ingress, str):
            raise FrameError("'ingress_port' must be a string", base + ".ingress_port")
        # 未知入端口在全部结构/帧校验完成后仍属于处理前引用检查。
        if ingress not in port_by_name:
            raise StateError(
                "unknown ingress port '%s'" % ingress, base + ".ingress_port"
            )

        verdict = evaluate_frame(values["frame"], base + ".frame")
        event_time = values["time_ms"] if aging_time_ms is not None else None
        validated_events.append((ingress, verdict, event_time))

    return (
        port_by_name,
        validated_events,
        aging_time_ms,
        include_counters,
        static_map,
        include_fdb_events,
        mirror_sources,
        mirror_destination,
        egress_mirror_sources,
        egress_mirror_destination,
        acl_rules,
    )


def run_scenario(scenario):
    """校验并按顺序处理场景，返回固定键序的结果对象。"""
    (
        port_by_name,
        events,
        aging_time_ms,
        include_counters,
        static_map,
        include_fdb_events,
        mirror_sources,
        mirror_destination,
        egress_mirror_sources,
        egress_mirror_destination,
        acl_rules,
    ) = validate_scenario(scenario)
    mirror_enabled = mirror_sources is not None
    egress_mirror_enabled = egress_mirror_sources is not None
    acl_enabled = acl_rules is not None

    # 可转发出口集合，按 name 的 Unicode 码点升序排列 (Python 字符串即码点序)。
    flood_ports = sorted(
        name
        for name, attrs in port_by_name.items()
        if attrs["can_forward"]
    )

    # 计数状态仅在 include_counters 为真时维护；只读取转发结果，
    # 不参与学习、迁移、查表或转发决定。
    # 端口计数覆盖全部已配置端口 (按 name 码点升序)，VLAN 计数只含事件实际归属的 VLAN。
    if include_counters:
        port_stats = {name: [0, 0, 0] for name in sorted(port_by_name)}
        vlan_stats = {}
    else:
        port_stats = None
        vlan_stats = None

    # 动态表：键为 (vid, 小写单播源 MAC)；
    # 启用老化时值为 (学习到的端口 name, 最后刷新时间)，未启用时刷新时间为 None。
    table = {}
    # 当前绑定到每个端口的动态表项总数 (不区分 VLAN)，供端口安全上限做 O(1)
    # 检查；随老化删除、首次学习与跨端口迁移同步增减，静态项从不计入。
    port_dynamic_counts = {name: 0 for name in port_by_name}
    results = []
    # fdb_events 仅在 include_fdb_events 为真时收集；只记录实际提交到动态表的
    # 变化 (老化删除、首次学习、同端口刷新、跨端口迁移)，静态项从不进入，
    # 只读审计，不参与学习、迁移、查表或转发决定。
    fdb_events = [] if include_fdb_events else None

    def vlan_allows(port_name, vid):
        # 接入口只承载与其 access_vid 相同的内部 VLAN；中继端口只承载
        # trunk_vids 允许的内部 VLAN；两种 VLAN 模式都未配置的端口不受
        # 接入/中继 VLAN 限制，按既有语义参与转发。
        attrs = port_by_name[port_name]
        access_vid = attrs["access_vid"]
        if access_vid is not None:
            return access_vid == vid
        trunk_vids = attrs["trunk_vids"]
        return trunk_vids is None or vid in trunk_vids

    for index, (ingress, verdict, time_ms) in enumerate(events):
        # 老化由显式事件时钟驱动：在处理该帧之前，一次性删除所有
        # 当前时间减去最后刷新时间大于等于 aging_time_ms 的表项。
        # 恰好到期的表项已失效；不按时间跨度循环推进。
        # 坏帧与不可转发事件的时间同样触发本次清理。
        if aging_time_ms is not None:
            # 到期删除按 vid 数值升序、再按 mac 的 Unicode 码点升序记录与执行；
            # 删除彼此独立，该顺序不影响最终表状态。
            expired = sorted(
                key
                for key, (_, refreshed_at) in table.items()
                if time_ms - refreshed_at >= aging_time_ms
            )
            for key in expired:
                # 刚到期的表项立即释放其端口的学习额度。
                old_port = table[key][0]
                del table[key]
                port_dynamic_counts[old_port] -= 1
                if fdb_events is not None:
                    # 老化由事件时刻触发即记录，即使该帧随后被丢弃。
                    fdb_events.append(
                        {
                            "event": index,
                            "kind": "aged",
                            "vid": key[0],
                            "mac": key[1],
                            "from_port": old_port,
                            "to_port": None,
                        }
                    )

        ingress_attrs = port_by_name[ingress]
        access_vid = ingress_attrs["access_vid"]
        trunk_vids = ingress_attrs["trunk_vids"]
        tagged = verdict["vlan"] is not None
        if tagged:
            # 带标签帧的内部 VLAN 取其标签 VID；在接入口上这也是违例事件的
            # 结果 vid 与 VLAN 计数归属。
            vid = verdict["vlan"]["vid"]
        elif access_vid is not None:
            # 接入口上的未标记帧 (含坏帧) 归入其接入 VLAN。
            vid = access_vid
        else:
            # 中继端口与其他端口上的未标记帧 (含坏帧) 归入缺省 VLAN 1。
            vid = UNTAGGED_VID
        src_mac = verdict["src_mac"]
        dst_mac = verdict["dst_mac"]

        egress = []
        # runt、oversize 或 bad_fcs：一律 dropped，不学习、不查表、无出口。
        # 入端口不能转发：该事件确定为 dropped。
        # 接入口收到任何带 802.1Q 标签的帧 (含 VID 0 或与 access_vid 相同)：
        # 接入策略违例，dropped，不学习、不查表、无出口。
        # 中继端口收到未标记帧，或标签 VID 为 0 或不在 trunk_vids 允许数组中：
        # 中继策略违例，dropped，不学习、不查表、无出口。
        # 未通过上述检查的事件不进入 ACL 求值，matched_acl_rule 为 null。
        pre_acl_ok = not (
            not verdict["valid"]
            or not ingress_attrs["can_forward"]
            or (tagged and access_vid is not None)
            or (
                trunk_vids is not None
                and (not tagged or vid not in trunk_vids)
            )
        )

        # 入口 ACL 仅对已通过帧合法性、入端口转发状态与 VLAN 入站策略检查的
        # 事件求值，并在 MAC 学习、端口安全检查与目的查表之前执行；首条命中
        # 规则决定动作，均未命中时允许。vid 匹配内部 VLAN (接入口未标记帧用
        # access_vid，其他未标记帧用 VLAN 1)；pcp 只匹配带标签帧。
        # remark_pcp 命中时把该帧的 PCP 重标记为规则的 set_pcp：不改变内部
        # VLAN，不重新执行 ACL，学习、查表、泛洪与计数沿既有路径执行，只有
        # 普通出口帧及由它触发的出口镜像副本使用新 PCP，入口镜像仍复制
        # 重标记前的原始帧。
        matched_acl_rule = None
        acl_drop = False
        remarked_pcp = None
        if acl_enabled and pre_acl_ok:
            pcp = verdict["vlan"]["pcp"] if tagged else None
            for rule_index, rule in enumerate(acl_rules):
                if acl_rule_matches(
                    rule, src_mac, dst_mac, vid, verdict["ether_type"], pcp
                ):
                    matched_acl_rule = rule_index
                    break
            if matched_acl_rule is not None:
                matched_action = acl_rules[matched_acl_rule]["action"]
                if matched_action == "drop":
                    # ACL 丢弃：固定 dropped 且出口为空；不学习或刷新源 MAC，
                    # 不查目的表，不产生 learned/refreshed/moved 记录；
                    # 仍计入端口与 VLAN 的入站及丢弃计数。
                    acl_drop = True
                elif matched_action == "remark_pcp":
                    # remark_pcp 规则必含 pcp 匹配字段，故只命中带标签帧。
                    remarked_pcp = acl_rules[matched_acl_rule]["set_pcp"]

        if not pre_acl_ok or acl_drop:
            decision = "dropped"
        else:
            # 仅在入端口 can_learn 且该 (VLAN, 规范化源 MAC) 无静态项时才
            # 考虑动态学习、刷新或迁移；源键已有静态项或端口禁止学习时不触发
            # 端口安全违例。
            learn_key = (vid, src_mac)
            will_learn = (
                ingress_attrs["can_learn"] and learn_key not in static_map
            )
            existing_entry = table.get(learn_key) if will_learn else None

            # 端口安全：已在同一端口的动态源只刷新、不占新额度；首次学习或
            # 从其他端口迁入需要一个新额度。上限按当前绑定到入端口的动态表项
            # 总数计算 (不区分 VLAN，静态项不占额度)；检查发生在本次老化清理
            # 之后，刚到期的表项已释放额度。
            port_security_violation = False
            if (
                will_learn
                and (existing_entry is None or existing_entry[0] != ingress)
                and ingress_attrs["dynamic_mac_limit"] is not None
                and port_dynamic_counts[ingress]
                >= ingress_attrs["dynamic_mac_limit"]
            ):
                # 上限已满：本事件固定 dropped 且出口为空；不做目的查表，
                # 不新增、刷新或迁移任何动态项 (迁入失败时旧端口原表项保持原状)。
                port_security_violation = True
                decision = "dropped"

            if not port_security_violation:
                if will_learn:
                    if existing_entry is None:
                        # 首次学习占用一个新额度。
                        port_dynamic_counts[ingress] += 1
                        learn_kind = "learned"
                        learn_from = None
                    elif existing_entry[0] != ingress:
                        # 跨端口迁移：旧端口释放额度，新端口占用额度。
                        port_dynamic_counts[existing_entry[0]] -= 1
                        port_dynamic_counts[ingress] += 1
                        learn_kind = "moved"
                        learn_from = existing_entry[0]
                    else:
                        # 同端口刷新仅更新刷新时间，额度不变。
                        learn_kind = "refreshed"
                        learn_from = ingress
                    # 以上情形都写入/刷新表项。
                    table[learn_key] = (ingress, time_ms)
                    if fdb_events is not None:
                        # 只记录实际提交的变化；同一键在同一事件中可因
                        # 先老化删除再学习而出现 aged 后接 learned。
                        fdb_events.append(
                            {
                                "event": index,
                                "kind": learn_kind,
                                "vid": vid,
                                "mac": src_mac,
                                "from_port": learn_from,
                                "to_port": ingress,
                            }
                        )

                if verdict["destination_type"] == "unicast":
                    static_port = static_map.get((vid, dst_mac))
                    if static_port is not None:
                        # 静态项优先：命中入端口时过滤；目标端口 down、blocking
                        # 或目标接入口 VLAN 不匹配时丢弃；均不退回未知单播泛洪。
                        if static_port == ingress:
                            decision = "filtered"
                        elif not port_by_name[static_port]["can_forward"]:
                            decision = "dropped"
                        elif not vlan_allows(static_port, vid):
                            decision = "dropped"
                        else:
                            decision = "forwarded"
                            egress = [static_port]
                    else:
                        hit_entry = table.get((vid, dst_mac))
                        if hit_entry is None:
                            # 未命中单播泛洪；接入口仅在内部 VLAN 匹配时成为出口。
                            decision = "flooded"
                            egress = [
                                name
                                for name in flood_ports
                                if name != ingress and vlan_allows(name, vid)
                            ]
                        elif hit_entry[0] == ingress:
                            # 命中入端口：过滤，出口为空。
                            decision = "filtered"
                        elif not vlan_allows(hit_entry[0], vid):
                            # 目标接入口 VLAN 不匹配：丢弃，不退回泛洪。
                            decision = "dropped"
                        else:
                            # 命中单播仅发往表项端口。
                            decision = "forwarded"
                            egress = [hit_entry[0]]
                else:
                    # 广播与组播泛洪到除入端口外所有 can_forward 且
                    # 接入 VLAN 匹配 (或未配置 access_vid) 的端口。
                    decision = "flooded"
                    egress = [
                        name
                        for name in flood_ports
                        if name != ingress and vlan_allows(name, vid)
                    ]

        # 入口镜像独立于普通转发：只要入口属于源端口集合，就尝试向镜像目的
        # 端口交付一份原始入口副本，即使该帧已因 runt/oversize/bad_fcs、入口
        # 状态、VLAN 策略或端口安全而被丢弃。交付仅取决于目的端口 can_forward，
        # 其 access_vid/trunk_vids 不限制这份副本；镜像不触发学习、刷新、迁移、
        # 老化或计数，也不改变 decision、egress_ports 与转发表。每个事件最多
        # 一份副本。未配置镜像会话时不输出 mirror_ports 键。
        if mirror_enabled:
            if (
                ingress in mirror_sources
                and port_by_name[mirror_destination]["can_forward"]
            ):
                mirror_ports = [mirror_destination]
            else:
                mirror_ports = []

        # 出口镜像在普通转发决定最终确定后判定：只要至少一个实际交付端口
        # (egress_ports) 属于源端口集合，就尝试向出口镜像目的端口交付一份
        # 原始帧副本；泛洪命中多个源端口也只产生一份。dropped、filtered 或
        # 无实际出口的事件不产生出口镜像；目的端口 can_forward 为假时也不
        # 交付，其 access_vid/trunk_vids 不限制这份副本。镜像不触发学习、
        # 刷新、迁移、老化、计数或额外的 FDB 审计，也不会再次触发镜像。
        if egress_mirror_enabled:
            source_hit = any(name in egress_mirror_sources for name in egress)
            if (
                source_hit
                and port_by_name[egress_mirror_destination]["can_forward"]
            ):
                egress_mirror_ports = [egress_mirror_destination]
            else:
                egress_mirror_ports = []

        result_record = {
            "event": index,
            "vid": vid,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "decision": decision,
            "egress_ports": egress,
        }
        if mirror_enabled:
            # mirror_ports 紧随 egress_ports 之后。
            result_record["mirror_ports"] = mirror_ports
        if egress_mirror_enabled:
            # egress_mirror_ports 位于 mirror_ports 之后；未启用入口镜像时
            # 紧随 egress_ports。
            result_record["egress_mirror_ports"] = egress_mirror_ports
        if acl_enabled:
            # matched_acl_rule 位于所有既有字段之后：首条命中规则的零基索引；
            # 未命中或事件未进入 ACL 求值时为 null。effective_pcp 紧随其后：
            # 带标签帧为最终 PCP (命中 remark_pcp 时为重标记值，未进入 ACL
            # 求值或未命中重标记规则时为原始 PCP，丢弃路径同样确定)，
            # 未标记帧为 null。
            result_record["matched_acl_rule"] = matched_acl_rule
            if tagged:
                effective_pcp = (
                    remarked_pcp
                    if remarked_pcp is not None
                    else verdict["vlan"]["pcp"]
                )
            else:
                effective_pcp = None
            result_record["effective_pcp"] = effective_pcp
        results.append(result_record)

        if include_counters:
            # 入口计数覆盖全部事件 (含随后丢弃的)；丢弃只计 decision 为
            # dropped 的事件 (filtered 不算)；出口按实际交付逐端口累计。
            port_entry = port_stats[ingress]
            port_entry[0] += 1
            vlan_entry = vlan_stats.get(vid)
            if vlan_entry is None:
                vlan_entry = vlan_stats[vid] = [0, 0, 0]
            vlan_entry[0] += 1
            if decision == "dropped":
                port_entry[2] += 1
                vlan_entry[2] += 1
            for name in egress:
                port_stats[name][1] += 1
            # VLAN 出口计数为该 VLAN 实际出口交付的总数。
            vlan_entry[1] += len(egress)

    # 表项按 VLAN 数值升序、再按 MAC 的 Unicode 码点升序排列。
    # 最后事件时刻仍有效的表项才会出现在快照中，字段与键序保持不变。
    entries = [
        {"vid": vid, "mac": mac, "port": port}
        for (vid, mac), (port, _) in sorted(table.items(), key=lambda kv: kv[0])
    ]

    output = {
        "schema": FORWARD_SCHEMA,
        "results": results,
        "dynamic_table": entries,
    }

    if static_map:
        # 静态表快照位于 dynamic_table 之后，仅含 vid、mac、port，
        # 按 vid 数值升序、再按 mac 的 Unicode 码点升序排列。
        # 空数组等价于省略，不输出该键。
        output["static_table"] = [
            {"vid": vid, "mac": mac, "port": port}
            for (vid, mac), port in sorted(static_map.items(), key=lambda kv: kv[0])
        ]

    if include_counters:
        # 端口项按 name 的 Unicode 码点升序 (port_stats 已按此序构建)，
        # 每个已配置端口都出现；VLAN 项按 vid 数值升序，只含事件归属过的 VLAN。
        output["counters"] = {
            "ports": [
                {
                    "name": name,
                    "ingress_frames": stats[0],
                    "egress_frames": stats[1],
                    "dropped_frames": stats[2],
                }
                for name, stats in port_stats.items()
            ],
            "vlans": [
                {
                    "vid": vid,
                    "ingress_frames": stats[0],
                    "egress_frames": stats[1],
                    "dropped_frames": stats[2],
                }
                for vid, stats in sorted(vlan_stats.items())
            ],
        }

    if include_fdb_events:
        # fdb_events 位于所有既有区段 (含 counters) 之后，按输入事件顺序记录
        # 实际提交的动态表变化；缺省或为 false 时输出不含该键。
        output["fdb_events"] = fdb_events

    return output


def cmd_forward(args):
    try:
        scenario = read_scenario(args.scenario)
    except ValueError as exc:
        emit_error("InputError", str(exc))
        return 2

    try:
        result = run_scenario(scenario)
    except ConfigError as exc:
        emit_error("ConfigError", exc.message, exc.path)
        return 3
    except FrameError as exc:
        emit_error("FrameError", exc.message, exc.path)
        return 4
    except StateError as exc:
        emit_error("StateError", exc.message, exc.path)
        return 5

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
            "以及场景内的动态 MAC 学习、查表与转发。"
        ),
        epilog=(
            "限制: 端口数量上限为 %d；单个端口 name 长度上限为 %d 个字符；"
            "帧描述文件大小上限为 %d 字节；场景事件数量上限为 %d。"
            "仅使用 Python 标准库，不联网。"
            % (MAX_PORTS, MAX_PORT_NAME_LEN, MAX_FRAME_FILE_BYTES, MAX_EVENTS)
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
        help="按场景顺序处理事件，执行动态学习、查表与转发",
        description=(
            "读取 UTF-8 JSON 场景 (ports 配置与按顺序排列的 events)，"
            "先完整校验，再按事件顺序执行场景内动态 MAC 表的学习、查表与转发，"
            "并向标准输出写入单行 JSON 结果。"
            "未标记帧归入 VLAN 1，带标签帧按 vid 隔离，vid 0 也作为独立域。"
            "端口可选 access_vid (1..4094) 声明接入 VLAN：该端口上的未标记帧"
            "归入接入 VLAN，任何带标签帧均作为接入策略违例丢弃；"
            "只有内部 VLAN 与 access_vid 相同的接入口才能成为出口。"
            "端口可选 trunk_vids (1..4094 的非空不重复整数数组，与 access_vid"
            " 互斥) 声明中继允许承载的 VLAN：该端口只接收 VID 在允许数组中的"
            "带标签帧，未标记帧与 VID 0 或不允许的标签帧作为中继策略违例丢弃；"
            "只有内部 VLAN 被允许的中继端口才能成为出口。"
            "端口可选 dynamic_mac_limit (1..10000 的整数) 限制绑定到该端口的"
            "动态 MAC 学习数量 (不区分 VLAN，静态项不占额度)：合法帧首次学习或"
            "跨端口迁入而额度已满时该事件 dropped、无出口且不改变动态表，"
            "同端口刷新不占额度，老化到期立即释放额度，省略时无限制。"
            "场景可选 aging_time_ms 启用由事件 time_ms 驱动的动态表项老化；"
            "可选 static_table 声明始终有效、不参与老化且不被学习覆盖的静态表项，"
            "单播目的查找优先匹配静态项；"
            "可选 include_counters 为 true 时在 dynamic_table 后追加本次场景的"
            "端口与 VLAN 帧计数；"
            "可选 include_fdb_events 为 true 时在所有既有区段之后追加 fdb_events，"
            "按事件顺序记录实际提交的动态表变化 (aged/learned/refreshed/moved)；"
            "可选 ingress_mirror 声明唯一一个入口镜像会话 (source_ports 与 "
            "destination_port)：入口属于源端口的事件都独立尝试向目的端口交付"
            "一份入口帧副本，结果在 egress_ports 后追加 mirror_ports；"
            "可选 egress_mirror 声明唯一一个出口镜像会话 (同样仅含 "
            "source_ports 与 destination_port)：至少一个实际交付端口属于"
            "源端口的事件独立尝试向目的端口再交付一份原始帧副本，泛洪命中"
            "多个源端口也只产生一份，结果在 mirror_ports 之后 (未启用入口"
            "镜像时紧随 egress_ports) 追加 egress_mirror_ports；"
            "可选 ingress_acl 声明最多 %d 条有序无状态入口过滤规则 "
            "(action 为 allow、drop 或 remark_pcp，至少含 src_mac、"
            "dst_mac、vid、ether_type、pcp 中一个匹配字段，省略字段视为"
            "通配；remark_pcp 规则必须含 pcp 匹配字段与 0..7 的 set_pcp，"
            "set_pcp 不允许出现在 allow、drop 规则中)：仅对已通过"
            "帧合法性、入端口转发状态与 VLAN 入站策略的事件在学习与查表前"
            "求值，首条命中决定动作，均未命中时允许；remark_pcp 命中时把"
            "带标签帧的 PCP 重标记为 set_pcp，学习、查表、泛洪与计数沿"
            "既有路径执行，仅普通出口帧及其出口镜像副本使用新 PCP，"
            "入口镜像仍复制原始帧。结果在所有既有字段后"
            "追加 matched_acl_rule (首条命中规则的零基索引或 null) 与 "
            "effective_pcp (带标签帧的最终 PCP，未标记帧为 null)；"
            "无端口模式或跨进程持久化。"
            % MAX_ACL_RULES
        ),
        epilog=(
            "限制: 端口数量上限为 %d；事件数量上限为 %d；静态表项数量上限为 %d；"
            "入口 ACL 规则数量上限为 %d。"
            "aging_time_ms 与 time_ms 取值为 1..%d / 0..%d 的整数，"
            "time_ms 按事件顺序单调不减；不读墙上时钟。"
            "泛洪出口按端口 name 的 Unicode 码点升序排列；"
            "相同输入的输出逐字节一致。"
            % (
                MAX_PORTS,
                MAX_EVENTS,
                MAX_STATIC_ENTRIES,
                MAX_ACL_RULES,
                MAX_AGING_TIME_MS,
                MAX_EVENT_TIME_MS,
            )
        ),
    )
    forward_parser.add_argument(
        "--scenario",
        required=True,
        metavar="FILE",
        help=(
            "UTF-8 JSON 场景文件路径，顶层包含 ports 数组与 events 数组，"
            "可选 aging_time_ms、static_table、include_counters、"
            "include_fdb_events、ingress_mirror、egress_mirror 与 "
            "ingress_acl；每个事件包含 "
            "ingress_port 与完整 frame 描述，启用老化时每个事件还需包含 time_ms"
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
