#!/usr/bin/env python3
"""l2-switch: 二层以太网交换的行为仿真与配置框架。

提供物理端口配置校验与确定性状态快照 (ports 子命令)、
以太帧的离线合法性判定 (frame 子命令)，
场景内的动态 MAC 学习、静态表项、查表与转发 (forward 子命令)，
以及单个出口端口队列快照的严格优先级或加权轮询出队调度 (qos-schedule 子命令)，
以及离线生成树根桥与根端口选举 (stp-root 子命令)。
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
MAX_MAC_BINDINGS = 10000
MAX_ACL_RULES = 4096

# qos-schedule 输入的有限上限 (在 --help 中公开)。
MAX_SCHEDULE_QUEUES = 8
MAX_SCHEDULE_TRANSMIT = 10000
MAX_SCHEDULE_TOTAL_FRAMES = 10000
# wrr 策略下每个队列权重的取值范围。
MIN_SCHEDULE_WEIGHT = 1
MAX_SCHEDULE_WEIGHT = 100

# stp-root 输入的有限上限 (在 --help 中公开)。
MAX_STP_PORTS = 4096
MAX_STP_BPDUS = 10000
# 桥优先级为 0..61440 且必须为 4096 的倍数 (802.1t 桥标识)。
MIN_STP_BRIDGE_PRIORITY = 0
MAX_STP_BRIDGE_PRIORITY = 61440
STP_PRIORITY_STEP = 4096
# 本地端口 path_cost 为 1..2147483647 的整数；BPDU 宣告的 root_path_cost
# 与累计根路径代价均为 0..4294967295 的 32 位无符号整数。
MIN_STP_PATH_COST = 1
MAX_STP_PATH_COST = 2147483647
MAX_STP_ROOT_PATH_COST = 4294967295

SCHEMA = "l2-switch/ports-v1"
FRAME_SCHEMA = "l2-switch/frame-v1"
FORWARD_SCHEMA = "l2-switch/forward-v1"
CONFIG_DIFF_SCHEMA = "l2-switch/config-diff-v1"
QOS_SCHEDULE_SCHEMA = "l2-switch/qos-schedule-v1"
STP_ROOT_SCHEMA = "l2-switch/stp-root-v1"
# 未标记帧归入 VLAN 1；带标签帧按 vid 隔离，vid 0 也是独立域。
UNTAGGED_VID = 1

# 每个端口允许的字段及其规范顺序；额外字段一律拒绝。
# access_vid 为可选的接入 VLAN 归属，trunk_vids 为可选的中继 VLAN 允许数组，
# 二者互斥，缺省时都不出现在快照中。
# trunk_pvid 为可选的中继本征 VLAN，只能与 trunk_vids 同时出现且必须属于
# 该允许数组，缺省时不出现在快照中。
# hybrid_vids、hybrid_pvid、hybrid_untagged_vids 共同声明可选的混合 VLAN
# 端口：三者必须同时出现，并与 access_vid、trunk_vids、trunk_pvid 互斥；
# hybrid_pvid 必须属于 hybrid_vids，hybrid_untagged_vids 必须为 hybrid_vids
# 的子集 (可为空数组)，缺省时都不出现在快照中。
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
    "trunk_pvid",
    "hybrid_vids",
    "hybrid_pvid",
    "hybrid_untagged_vids",
    "dynamic_mac_limit",
)
FIELD_SET = frozenset(FIELD_ORDER)
OPTIONAL_FIELDS = frozenset(
    (
        "access_vid",
        "trunk_vids",
        "trunk_pvid",
        "hybrid_vids",
        "hybrid_pvid",
        "hybrid_untagged_vids",
        "dynamic_mac_limit",
    )
)
# 混合 VLAN 模式字段的规范顺序；三者必须同时出现。
HYBRID_FIELDS = ("hybrid_vids", "hybrid_pvid", "hybrid_untagged_vids")

MIN_ACCESS_VID = 1
MAX_ACCESS_VID = 4094

MIN_TRUNK_VID = 1
MAX_TRUNK_VID = 4094

MIN_TRUNK_PVID = 1
MAX_TRUNK_PVID = 4094

MIN_HYBRID_VID = 1
MAX_HYBRID_VID = 4094

MIN_HYBRID_PVID = 1
MAX_HYBRID_PVID = 4094

MIN_HYBRID_UNTAGGED_VID = 1
MAX_HYBRID_UNTAGGED_VID = 4094

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


def _check_trunk_pvid(value, path):
    # 可选的中继本征 VLAN；bool 是 int 的子类型，必须显式排除。
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError("'trunk_pvid' must be an integer", path)
    if value < MIN_TRUNK_PVID or value > MAX_TRUNK_PVID:
        raise ConfigError(
            "'trunk_pvid' must be between %d and %d"
            % (MIN_TRUNK_PVID, MAX_TRUNK_PVID),
            path,
        )
    return value


def _check_hybrid_vids(value, path):
    # 非空整数数组声明混合端口允许承载的 802.1Q VLAN；快照按数值升序规范化。
    if not isinstance(value, list):
        raise ConfigError("'hybrid_vids' must be an array", path)
    if len(value) == 0:
        raise ConfigError("'hybrid_vids' must be a non-empty array", path)
    seen = set()
    for index, item in enumerate(value):
        item_path = "%s[%d]" % (path, index)
        # bool 是 int 的子类型，必须显式排除。
        if isinstance(item, bool) or not isinstance(item, int):
            raise ConfigError(
                "'hybrid_vids' elements must be integers", item_path
            )
        if item < MIN_HYBRID_VID or item > MAX_HYBRID_VID:
            raise ConfigError(
                "'hybrid_vids' elements must be between %d and %d"
                % (MIN_HYBRID_VID, MAX_HYBRID_VID),
                item_path,
            )
        if item in seen:
            raise ConfigError(
                "'hybrid_vids' must not contain duplicate values", item_path
            )
        seen.add(item)
    return sorted(value)


def _check_hybrid_pvid(value, path):
    # 混合端口的本征 VLAN；bool 是 int 的子类型，必须显式排除。
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError("'hybrid_pvid' must be an integer", path)
    if value < MIN_HYBRID_PVID or value > MAX_HYBRID_PVID:
        raise ConfigError(
            "'hybrid_pvid' must be between %d and %d"
            % (MIN_HYBRID_PVID, MAX_HYBRID_PVID),
            path,
        )
    return value


def _check_hybrid_untagged_vids(value, path):
    # 混合端口出站剥除标签的 VLAN 数组，可为空；快照按数值升序规范化。
    if not isinstance(value, list):
        raise ConfigError("'hybrid_untagged_vids' must be an array", path)
    seen = set()
    for index, item in enumerate(value):
        item_path = "%s[%d]" % (path, index)
        # bool 是 int 的子类型，必须显式排除。
        if isinstance(item, bool) or not isinstance(item, int):
            raise ConfigError(
                "'hybrid_untagged_vids' elements must be integers", item_path
            )
        if item < MIN_HYBRID_UNTAGGED_VID or item > MAX_HYBRID_UNTAGGED_VID:
            raise ConfigError(
                "'hybrid_untagged_vids' elements must be between %d and %d"
                % (MIN_HYBRID_UNTAGGED_VID, MAX_HYBRID_UNTAGGED_VID),
                item_path,
            )
        if item in seen:
            raise ConfigError(
                "'hybrid_untagged_vids' must not contain duplicate values",
                item_path,
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
    "trunk_pvid": _check_trunk_pvid,
    "hybrid_vids": _check_hybrid_vids,
    "hybrid_pvid": _check_hybrid_pvid,
    "hybrid_untagged_vids": _check_hybrid_untagged_vids,
    "dynamic_mac_limit": _check_dynamic_mac_limit,
}


def validate_port(item, index, seen):
    """校验单个端口，按输入字段顺序返回 (有序字段, can_forward, can_learn)。

    按字段在输入中出现的顺序报告首个错误 (未知字段、非法值或重复 name 立即
    报告)；仅当所有出现字段均合法后，才检查 access_vid 与 trunk_vids 互斥，
    再检查 trunk_pvid 与 trunk_vids 的搭配关系 (trunk_pvid 只能在
    trunk_vids 配置时出现且必须属于该允许数组)，
    再检查混合 VLAN 字段：hybrid_vids、hybrid_pvid、hybrid_untagged_vids
    必须同时出现，与 access_vid、trunk_vids、trunk_pvid 互斥，
    hybrid_pvid 必须属于 hybrid_vids，hybrid_untagged_vids 必须为
    hybrid_vids 的子集，
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

    if "trunk_pvid" in values:
        # trunk_pvid 声明中继本征 VLAN，只能与 trunk_vids 同时出现；
        # 由于 trunk_vids 与 access_vid 互斥，trunk_pvid 也无法与
        # access_vid 共存。
        if "trunk_vids" not in values:
            raise ConfigError(
                "'trunk_pvid' requires 'trunk_vids'",
                base + ".trunk_pvid",
            )
        if values["trunk_pvid"] not in values["trunk_vids"]:
            raise ConfigError(
                "'trunk_pvid' must be one of 'trunk_vids'",
                base + ".trunk_pvid",
            )

    hybrid_present = [field for field in HYBRID_FIELDS if field in values]
    if hybrid_present:
        first = hybrid_present[0]
        # 三个混合字段必须同时出现；按规范顺序报告首个缺失的搭配字段，
        # 路径指向首个出现的混合字段 (与 trunk_pvid 的搭配检查风格一致)。
        for field in HYBRID_FIELDS:
            if field not in values:
                raise ConfigError(
                    "'%s' requires '%s'" % (first, field),
                    base + "." + first,
                )
        # 混合 VLAN 模式与接入/中继 VLAN 模式互斥。
        for other in ("access_vid", "trunk_vids", "trunk_pvid"):
            if other in values:
                raise ConfigError(
                    "'%s' and '%s' are mutually exclusive" % (first, other),
                    base + "." + first,
                )
        # hybrid_pvid 为混合端口的本征 VLAN，必须属于允许数组。
        if values["hybrid_pvid"] not in values["hybrid_vids"]:
            raise ConfigError(
                "'hybrid_pvid' must be one of 'hybrid_vids'",
                base + ".hybrid_pvid",
            )
        # hybrid_untagged_vids 必须为允许数组的子集 (可为空数组)。
        hybrid_vid_set = set(values["hybrid_vids"])
        for index, item in enumerate(values["hybrid_untagged_vids"]):
            if item not in hybrid_vid_set:
                raise ConfigError(
                    "'hybrid_untagged_vids' must be a subset of 'hybrid_vids'",
                    "%s.hybrid_untagged_vids[%d]" % (base, index),
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


# 公开快照字段的比较顺序：先 ports 规范字段顺序 (FIELD_ORDER)，
# 再追加 can_forward、can_learn 两个派生字段。
DIFF_DERIVED_FIELDS = ("can_forward", "can_learn")


def with_side_prefix(path, side):
    """把 ports 校验错误路径加上 $.before 或 $.after 侧前缀。"""
    root = "$." + side
    if path == "$":
        return root
    return root + path[1:]


def diff_configs(before_snapshot, after_snapshot):
    """比较两份 validate() 产出的规范化快照，返回固定键序的比较结果。

    比较对象为规范化后的快照，与原始 JSON 字段顺序无关：VLAN 数组已按
    数值升序规范化，两侧都省略的可选字段不产生差异。按 name 匹配端口
    (不推断改名)：after 独有为 added、before 独有为 removed；同名端口
    任一公开快照字段 (含派生字段) 不同即进入 changed，changed_fields
    先按 FIELD_ORDER 再按 can_forward、can_learn 列实际变化字段。
    """
    before_by_name = {
        entry["name"]: entry for entry in before_snapshot["ports"]
    }
    after_by_name = {
        entry["name"]: entry for entry in after_snapshot["ports"]
    }
    before_names = set(before_by_name)
    after_names = set(after_by_name)

    # 集合差/交的迭代顺序不确定，统一按 name 的 Unicode 码点升序排序。
    added_names = sorted(after_names - before_names)
    removed_names = sorted(before_names - after_names)
    common_names = sorted(before_names & after_names)

    changed_ports = []
    unchanged_count = 0
    for name in common_names:
        before_entry = before_by_name[name]
        after_entry = after_by_name[name]
        if before_entry == after_entry:
            # 同名且完整快照逐字段相同才计入 unchanged。
            unchanged_count += 1
            continue

        changed_fields = []
        for field in FIELD_ORDER:
            # name 由匹配方式保证相同；只比较其余公开规范字段。
            if field == "name":
                continue
            in_before = field in before_entry
            in_after = field in after_entry
            if not in_before and not in_after:
                # 可选字段在两侧都省略时不产生差异。
                continue
            if in_before != in_after or before_entry[field] != after_entry[field]:
                # 仅一侧出现 (新增/移除可选字段) 或两侧规范化值不同。
                changed_fields.append(field)
        for field in DIFF_DERIVED_FIELDS:
            if before_entry[field] != after_entry[field]:
                changed_fields.append(field)

        changed_ports.append(
            {
                "name": name,
                "before": before_entry,
                "after": after_entry,
                "changed_fields": changed_fields,
            }
        )

    return {
        "schema": CONFIG_DIFF_SCHEMA,
        "added_ports": [after_by_name[name] for name in added_names],
        "removed_ports": [before_by_name[name] for name in removed_names],
        "changed_ports": changed_ports,
        "unchanged_count": unchanged_count,
    }


def cmd_config_diff(args):
    # 先完整读取两份文件，再分别校验，全部成功后才比较；
    # 任一侧失败时标准输出不写入任何内容。
    try:
        before_config = read_config(args.before)
    except ValueError as exc:
        emit_error("InputError", str(exc), "$.before")
        return 2
    try:
        after_config = read_config(args.after)
    except ValueError as exc:
        emit_error("InputError", str(exc), "$.after")
        return 2

    try:
        before_snapshot = validate(before_config)
    except ConfigError as exc:
        emit_error(
            "ConfigError", exc.message, with_side_prefix(exc.path, "before")
        )
        return 3
    try:
        after_snapshot = validate(after_config)
    except ConfigError as exc:
        emit_error(
            "ConfigError", exc.message, with_side_prefix(exc.path, "after")
        )
        return 3

    result = diff_configs(before_snapshot, after_snapshot)
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


def _check_include_qos_counters(value, path):
    # include_qos_counters 是场景级开关，类型错误归 ConfigError。
    if not isinstance(value, bool):
        raise ConfigError("'include_qos_counters' must be a boolean", path)
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


# VLAN 感知源 MAC 静态绑定的字段及其规范顺序；额外字段一律拒绝。
# 绑定只校验帧的源地址，不参与目的地址查表，并可与 static_table 同键共存。
BINDING_FIELD_ORDER = ("vid", "mac", "port")
BINDING_FIELD_SET = frozenset(BINDING_FIELD_ORDER)
BINDING_FIELD_CHECKS = {
    "vid": _check_static_vid,
    "mac": _check_static_mac,
    "port": _check_static_port,
}


def validate_mac_bindings(mac_bindings, port_by_name):
    """校验源 MAC 静态绑定表，返回键为 (vid, 小写 mac)、值为端口 name 的映射。

    与静态表相同的逐项校验顺序：先按输入字段顺序检查未知字段与非法值
    (vid/mac 复用静态表的 ConfigError 校验)，再按规范顺序报告缺失字段，
    然后检查 (vid, mac) 组合重复，最后检查 port 引用 (未知端口归 StateError)。
    """
    if not isinstance(mac_bindings, list):
        raise ConfigError("'mac_bindings' must be an array", "$.mac_bindings")
    if len(mac_bindings) > MAX_MAC_BINDINGS:
        raise ConfigError(
            "number of mac bindings exceeds maximum of %d" % MAX_MAC_BINDINGS,
            "$.mac_bindings",
        )

    binding_map = {}
    for index, item in enumerate(mac_bindings):
        base = "$.mac_bindings[%d]" % index
        if not isinstance(item, dict):
            raise ConfigError("mac binding entry must be an object", base)

        values = {}
        for field, value in item.items():
            path = base + "." + field
            if field not in BINDING_FIELD_SET:
                raise ConfigError("unexpected field '%s'" % field, path)
            values[field] = BINDING_FIELD_CHECKS[field](value, path)

        for field in BINDING_FIELD_ORDER:
            if field not in values:
                raise ConfigError("missing field '%s'" % field, base + "." + field)

        key = (values["vid"], values["mac"])
        if key in binding_map:
            raise ConfigError(
                "duplicate mac binding for vid %d and mac '%s'" % key, base
            )
        port = values["port"]
        if port not in port_by_name:
            raise StateError("unknown port '%s'" % port, base + ".port")
        binding_map[key] = port

    return binding_map


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
# set_pcp 仅为 remark_pcp 动作的重标记参数，不是匹配字段。
ACL_FIELD_ORDER = (
    "action", "src_mac", "dst_mac", "vid", "ether_type", "pcp", "set_pcp"
)
ACL_FIELD_SET = frozenset(ACL_FIELD_ORDER)
ACL_MATCH_FIELD_ORDER = ("src_mac", "dst_mac", "vid", "ether_type", "pcp")
ACL_ACTIONS = frozenset(("allow", "drop", "remark_pcp"))
ACL_REMARK_ACTION = "remark_pcp"

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
    # set_pcp 是 remark_pcp 动作的重标记目标值；bool 是 int 子类型，须显式排除。
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError("'set_pcp' must be an integer", path)
    if value < MIN_ACL_PCP or value > MAX_ACL_PCP:
        raise ConfigError(
            "'set_pcp' must be between %d and %d"
            % (MIN_ACL_PCP, MAX_ACL_PCP),
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


# 广播/组播/未知单播风暴抑制的字段及其规范顺序；额外字段一律拒绝。
# window_ms 为固定窗口长度，port_limits 把已配置物理端口名映射到该入口端口
# 在一个窗口内允许的广播/组播/未知单播帧数；未列出的端口不受限制。
STORM_FIELD_ORDER = ("window_ms", "port_limits")
STORM_FIELD_SET = frozenset(STORM_FIELD_ORDER)
STORM_BASE = "$.broadcast_storm_control"
MULTICAST_STORM_BASE = "$.multicast_storm_control"
UNKNOWN_UNICAST_STORM_BASE = "$.unknown_unicast_storm_control"

MIN_STORM_WINDOW_MS = 1
MAX_STORM_WINDOW_MS = 9223372036854775807
MIN_STORM_PORT_LIMIT = 0
MAX_STORM_PORT_LIMIT = 10000


def validate_storm_control(storm, port_by_name, field_name, base):
    """校验风暴抑制配置，返回 (window_ms, {端口 name: 窗口内帧限额})。

    field_name 为顶层字段名 (broadcast_storm_control、
    multicast_storm_control 或 unknown_unicast_storm_control)，base 为该字段的
    JSON 路径。
    按字段在输入中出现的顺序报告首个错误 (未知字段立即报告)，再按规范顺序
    报告缺失字段；结构、字段、整数类型 (布尔值不算整数)、范围与空
    port_limits 均为 ConfigError；port_limits 的键未引用已配置物理端口时
    为 StateError。
    """
    if not isinstance(storm, dict):
        raise ConfigError("'%s' must be an object" % field_name, base)

    values = {}
    for field, value in storm.items():
        path = base + "." + field
        if field not in STORM_FIELD_SET:
            raise ConfigError("unexpected field '%s'" % field, path)
        values[field] = value

    for field in STORM_FIELD_ORDER:
        if field not in values:
            raise ConfigError(
                "missing field '%s'" % field, base + "." + field
            )

    window_ms = values["window_ms"]
    window_path = base + ".window_ms"
    # bool 是 int 的子类型，必须显式排除。
    if isinstance(window_ms, bool) or not isinstance(window_ms, int):
        raise ConfigError("'window_ms' must be an integer", window_path)
    if window_ms < MIN_STORM_WINDOW_MS or window_ms > MAX_STORM_WINDOW_MS:
        raise ConfigError(
            "'window_ms' must be between %d and %d"
            % (MIN_STORM_WINDOW_MS, MAX_STORM_WINDOW_MS),
            window_path,
        )

    port_limits = values["port_limits"]
    limits_path = base + ".port_limits"
    if not isinstance(port_limits, dict):
        raise ConfigError("'port_limits' must be an object", limits_path)
    if len(port_limits) == 0:
        raise ConfigError("'port_limits' must be a non-empty object", limits_path)

    limits = {}
    for name, limit in port_limits.items():
        item_path = "%s.%s" % (limits_path, name)
        # bool 是 int 的子类型，必须显式排除。
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise ConfigError("'port_limits' values must be integers", item_path)
        if limit < MIN_STORM_PORT_LIMIT or limit > MAX_STORM_PORT_LIMIT:
            raise ConfigError(
                "'port_limits' values must be between %d and %d"
                % (MIN_STORM_PORT_LIMIT, MAX_STORM_PORT_LIMIT),
                item_path,
            )
        if name not in port_by_name:
            raise StateError("unknown port '%s'" % name, item_path)
        limits[name] = limit

    return window_ms, limits


def validate_ingress_acl(acl):
    """校验入口 ACL，返回按输入顺序排列的已校验规则列表。

    每条规则先按输入字段顺序报告首个错误 (未知字段或非法值)，再检查
    缺失的 action，再检查至少出现一个匹配字段，最后按动作检查
    set_pcp/pcp 的搭配：remark_pcp 必须同时携带 pcp 与 set_pcp，
    allow/drop 不得携带 set_pcp。规则数量上限为 MAX_ACL_RULES。
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
        if not any(field in values for field in ACL_MATCH_FIELD_ORDER):
            raise ConfigError(
                "acl rule must specify at least one match field", base
            )

        action = values["action"]
        if action == ACL_REMARK_ACTION:
            # remark_pcp 只可能命中带 802.1Q 标签的帧，必须带 pcp 匹配；
            # 同时必须给出重标记目标值 set_pcp。
            if "pcp" not in values:
                raise ConfigError(
                    "'remark_pcp' rule must specify 'pcp'", base + ".pcp"
                )
            if "set_pcp" not in values:
                raise ConfigError(
                    "'remark_pcp' rule must specify 'set_pcp'", base + ".set_pcp"
                )
        elif "set_pcp" in values:
            # set_pcp 只能与 remark_pcp 动作一起出现。
            raise ConfigError(
                "'set_pcp' is only valid with 'remark_pcp' action",
                base + ".set_pcp",
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


# QoS 队列分类配置的字段及其规范顺序；额外字段一律拒绝。
# queue_count 声明出口队列数量，pcp_to_queue 把 PCP 0..7 映射到队列号，
# untagged_queue 为未标记帧的队列号；队列号取值均为 0..queue_count-1。
QOS_FIELD_ORDER = ("queue_count", "pcp_to_queue", "untagged_queue")
QOS_FIELD_SET = frozenset(QOS_FIELD_ORDER)
QOS_BASE = "$.qos_queues"

MIN_QOS_QUEUE_COUNT = 1
MAX_QOS_QUEUE_COUNT = 8
QOS_PCP_TO_QUEUE_LEN = 8


def validate_qos_queues(qos):
    """校验 QoS 队列分类配置，返回 (queue_count, pcp_to_queue, untagged_queue)。

    只做确定性分类与审计，不引入缓存深度、丢弃算法或出队调度。
    按字段在输入中出现的顺序报告未知字段，再按规范顺序报告缺失字段；
    queue_count、pcp_to_queue (类型、长度与逐元素) 与 untagged_queue 的
    类型或范围错误均为 ConfigError (布尔值不算整数)，path 精确指向对应
    字段或数组元素。
    """
    if not isinstance(qos, dict):
        raise ConfigError("'qos_queues' must be an object", QOS_BASE)

    values = {}
    for field, value in qos.items():
        path = QOS_BASE + "." + field
        if field not in QOS_FIELD_SET:
            raise ConfigError("unexpected field '%s'" % field, path)
        values[field] = value

    for field in QOS_FIELD_ORDER:
        if field not in values:
            raise ConfigError(
                "missing field '%s'" % field, QOS_BASE + "." + field
            )

    queue_count = values["queue_count"]
    count_path = QOS_BASE + ".queue_count"
    # bool 是 int 的子类型，必须显式排除。
    if isinstance(queue_count, bool) or not isinstance(queue_count, int):
        raise ConfigError("'queue_count' must be an integer", count_path)
    if queue_count < MIN_QOS_QUEUE_COUNT or queue_count > MAX_QOS_QUEUE_COUNT:
        raise ConfigError(
            "'queue_count' must be between %d and %d"
            % (MIN_QOS_QUEUE_COUNT, MAX_QOS_QUEUE_COUNT),
            count_path,
        )

    pcp_to_queue = values["pcp_to_queue"]
    map_path = QOS_BASE + ".pcp_to_queue"
    if not isinstance(pcp_to_queue, list):
        raise ConfigError("'pcp_to_queue' must be an array", map_path)
    if len(pcp_to_queue) != QOS_PCP_TO_QUEUE_LEN:
        raise ConfigError(
            "'pcp_to_queue' must contain exactly %d elements"
            % QOS_PCP_TO_QUEUE_LEN,
            map_path,
        )
    checked_map = []
    for index, item in enumerate(pcp_to_queue):
        item_path = "%s[%d]" % (map_path, index)
        # bool 是 int 的子类型，必须显式排除。
        if isinstance(item, bool) or not isinstance(item, int):
            raise ConfigError(
                "'pcp_to_queue' elements must be integers", item_path
            )
        if item < 0 or item > queue_count - 1:
            raise ConfigError(
                "'pcp_to_queue' elements must be between 0 and %d"
                % (queue_count - 1),
                item_path,
            )
        checked_map.append(item)

    untagged_queue = values["untagged_queue"]
    untagged_path = QOS_BASE + ".untagged_queue"
    # bool 是 int 的子类型，必须显式排除。
    if isinstance(untagged_queue, bool) or not isinstance(untagged_queue, int):
        raise ConfigError("'untagged_queue' must be an integer", untagged_path)
    if untagged_queue < 0 or untagged_queue > queue_count - 1:
        raise ConfigError(
            "'untagged_queue' must be between 0 and %d" % (queue_count - 1),
            untagged_path,
        )

    return queue_count, checked_map, untagged_queue


def validate_scenario(scenario):
    """先完整校验场景再处理；任何结构、字段、引用错误都在处理首个事件前抛出。

    返回 (port_by_name, validated_events, aging_time_ms, include_counters,
    static_map, include_fdb_events, mirror_sources, mirror_destination,
    egress_mirror_sources, egress_mirror_destination, acl_rules, binding_map,
    storm_control, multicast_storm_control, unknown_unicast_storm_control,
    qos_queues, include_qos_counters)：
    port_by_name 将端口 name 映射为
    {"can_forward", "can_learn", "access_vid", "trunk_vids",
    "trunk_pvid", "hybrid_vids", "hybrid_pvid", "hybrid_untagged_vids",
    "dynamic_mac_limit"} (未配置对应 VLAN 模式、本征 VLAN
    或学习上限时为 None)；
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
    未提供 ingress_acl 时为 None；
    binding_map 键为 (vid, 小写 mac)、值为绑定端口 name，仅校验源地址，
    未提供 mac_bindings 或其为空数组时为空映射；
    storm_control 为 (window_ms, {端口 name: 窗口内广播帧限额})，
    未提供 broadcast_storm_control 时为 None；
    multicast_storm_control 为 (window_ms, {端口 name: 窗口内组播帧限额})，
    未提供 multicast_storm_control 时为 None；
    unknown_unicast_storm_control 为 (window_ms, {端口 name: 窗口内未知单播
    帧限额})，未提供 unknown_unicast_storm_control 时为 None；启用任一风暴
    抑制或老化时每个事件都必须携带 time_ms，都未启用时不得出现 time_ms。
    qos_queues 为 (queue_count, pcp_to_queue, untagged_queue)，
    未提供 qos_queues 时为 None。
    include_qos_counters 缺省或为 false 时为 False，输出不含 qos_counters；
    为 true 时必须同时提供 qos_queues，否则在处理任何事件前以
    ConfigError (路径 $.include_qos_counters) 失败。
    """
    if not isinstance(scenario, dict):
        raise ConfigError("top-level scenario must be an object", "$")

    # 按顶层键在输入中出现的顺序报告首个错误；遍历后再按规范顺序报告缺失字段。
    seen_fields = set()
    aging_time_ms = None
    include_counters = False
    include_fdb_events = False
    include_qos_counters = False
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
        elif field == "include_qos_counters":
            include_qos_counters = _check_include_qos_counters(value, path)
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
        elif field == "mac_bindings":
            # 记录字段出现；结构与引用校验在 ports 校验完成后进行。
            seen_fields.add(field)
        elif field == "broadcast_storm_control":
            # 记录字段出现；结构与引用校验在 ports 校验完成后进行。
            seen_fields.add(field)
        elif field == "multicast_storm_control":
            # 记录字段出现；结构与引用校验在 ports 校验完成后进行。
            seen_fields.add(field)
        elif field == "unknown_unicast_storm_control":
            # 记录字段出现；结构与引用校验在 ports 校验完成后进行。
            seen_fields.add(field)
        elif field == "qos_queues":
            # 记录字段出现；结构校验在 ports 校验完成后进行。
            seen_fields.add(field)
        else:
            raise ConfigError("unexpected field '%s'" % field, path)

    if "ports" not in seen_fields:
        raise ConfigError("missing field 'ports'", "$.ports")
    if "events" not in seen_fields:
        raise FrameError("missing field 'events'", "$.events")
    if include_qos_counters and "qos_queues" not in seen_fields:
        # 队列计数依赖 qos_queues 的分类配置；为 true 而缺失时在处理任何
        # 事件前失败，路径指向开关本身。
        raise ConfigError(
            "'include_qos_counters' requires 'qos_queues'",
            "$.include_qos_counters",
        )

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
            # 未配置 trunk_pvid 时为 None，表示中继端口不接收未标记帧；
            # 配置时为未标记入站帧归属的本征 VLAN (保证属于 trunk_vids)。
            "trunk_pvid": fields.get("trunk_pvid"),
            # 未配置混合 VLAN 模式时三者均为 None；配置时 hybrid_vids 与
            # hybrid_untagged_vids 为按数值升序规范化后的数组 (后者可空)，
            # hybrid_pvid 为未标记入站帧归属的本征 VLAN
            # (保证属于 hybrid_vids)，hybrid_untagged_vids 保证为
            # hybrid_vids 的子集。
            "hybrid_vids": fields.get("hybrid_vids"),
            "hybrid_pvid": fields.get("hybrid_pvid"),
            "hybrid_untagged_vids": fields.get("hybrid_untagged_vids"),
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

    # 源 MAC 静态绑定引用端口，同样在 ports 之后、events 之前校验。
    binding_map = {}
    if "mac_bindings" in seen_fields:
        binding_map = validate_mac_bindings(scenario["mac_bindings"], port_by_name)

    # 广播风暴抑制引用端口，同样在 ports 之后、events 之前校验。
    # 启用后与 aging_time_ms 共用显式事件时钟：每个事件都必须携带 time_ms。
    storm_control = None
    if "broadcast_storm_control" in seen_fields:
        storm_control = validate_storm_control(
            scenario["broadcast_storm_control"], port_by_name,
            "broadcast_storm_control", STORM_BASE,
        )

    # 组播风暴抑制与广播抑制结构相同、独立计数，同样在 ports 之后、
    # events 之前校验；启用后同样要求每个事件携带 time_ms。
    multicast_storm_control = None
    if "multicast_storm_control" in seen_fields:
        multicast_storm_control = validate_storm_control(
            scenario["multicast_storm_control"], port_by_name,
            "multicast_storm_control", MULTICAST_STORM_BASE,
        )

    # 未知单播风暴抑制与广播/组播抑制结构相同、独立计数，同样在 ports 之后、
    # events 之前校验；启用后同样要求每个事件携带 time_ms。
    unknown_unicast_storm_control = None
    if "unknown_unicast_storm_control" in seen_fields:
        unknown_unicast_storm_control = validate_storm_control(
            scenario["unknown_unicast_storm_control"], port_by_name,
            "unknown_unicast_storm_control", UNKNOWN_UNICAST_STORM_BASE,
        )

    # QoS 队列分类不引用端口，同样在 ports 之后、events 之前校验。
    qos_queues = None
    if "qos_queues" in seen_fields:
        qos_queues = validate_qos_queues(scenario["qos_queues"])
    clock_enabled = (
        aging_time_ms is not None
        or storm_control is not None
        or multicast_storm_control is not None
        or unknown_unicast_storm_control is not None
    )

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
                if not clock_enabled:
                    # 未启用老化与风暴抑制时不接受孤立的 time_ms，
                    # 按既有未知字段约定拒绝。
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
        if clock_enabled and "time_ms" not in values:
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
        event_time = values["time_ms"] if clock_enabled else None
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
        binding_map,
        storm_control,
        multicast_storm_control,
        unknown_unicast_storm_control,
        qos_queues,
        include_qos_counters,
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
        binding_map,
        storm_control,
        multicast_storm_control,
        unknown_unicast_storm_control,
        qos_queues,
        include_qos_counters,
    ) = validate_scenario(scenario)
    mirror_enabled = mirror_sources is not None
    egress_mirror_enabled = egress_mirror_sources is not None
    acl_enabled = acl_rules is not None
    # 场景含任一混合 VLAN 端口时，每条 results 记录在 egress_ports 后追加
    # hybrid_egress_actions；未配置混合字段时输出与此前逐字节一致。
    hybrid_enabled = any(
        attrs["hybrid_vids"] is not None for attrs in port_by_name.values()
    )
    # 绑定只校验源地址；省略或空数组时 binding_map 为空，功能完全关闭
    # (包括结果记录中的 binding_violation 键)。
    bindings_enabled = bool(binding_map)
    # 省略 broadcast_storm_control 时功能完全关闭 (包括结果记录中的
    # storm_controlled 键)，time_ms 的既有约束不变。
    storm_enabled = storm_control is not None
    if storm_enabled:
        storm_window_ms, storm_port_limits = storm_control
        # 每个受限端口只保留当前窗口状态 [窗口序号, 已计数广播帧数]，
        # 不保留历史窗口；附加状态不超过 port_limits 的端口数。
        storm_state = {name: [-1, 0] for name in storm_port_limits}
    # 省略 multicast_storm_control 时功能完全关闭 (包括结果记录中的
    # multicast_storm_controlled 键)，time_ms 的既有约束不变。
    # 与广播抑制同时启用时二者独立计数。
    multicast_storm_enabled = multicast_storm_control is not None
    if multicast_storm_enabled:
        multicast_storm_window_ms, multicast_storm_port_limits = (
            multicast_storm_control
        )
        # 每个受限端口只保留当前窗口状态 [窗口序号, 已计数组播帧数]，
        # 不保留历史窗口；附加状态不超过 port_limits 的端口数。
        multicast_storm_state = {
            name: [-1, 0] for name in multicast_storm_port_limits
        }
    # 省略 unknown_unicast_storm_control 时功能完全关闭 (包括结果记录中的
    # unknown_unicast_storm_controlled 键)，time_ms 的既有约束不变。
    # 与广播/组播抑制同时启用时各自独立计数。
    unknown_unicast_storm_enabled = unknown_unicast_storm_control is not None
    if unknown_unicast_storm_enabled:
        unknown_unicast_storm_window_ms, unknown_unicast_storm_port_limits = (
            unknown_unicast_storm_control
        )
        # 每个受限端口只保留当前窗口状态 [窗口序号, 已计数未知单播帧数]，
        # 不保留历史窗口；附加状态不超过 port_limits 的端口数。
        unknown_unicast_storm_state = {
            name: [-1, 0] for name in unknown_unicast_storm_port_limits
        }
    # 省略 qos_queues 时功能完全关闭 (包括结果记录中的 egress_queues 键)；
    # 只做确定性的队列分类与审计，不引入缓存深度、丢弃算法或出队调度，
    # 除结果数组外不保留跨事件队列状态。
    qos_enabled = qos_queues is not None
    if qos_enabled:
        qos_queue_count, qos_pcp_to_queue, qos_untagged_queue = qos_queues

    # 队列计数状态仅在 include_qos_counters 为真时维护 (此时 qos_queues
    # 必然存在)；只读取每事件已确定的 egress_ports 与队列分类，不参与
    # 学习、查表或转发决定。状态上界为端口数乘队列数。
    if include_qos_counters:
        qos_port_stats = {
            name: [0] * qos_queue_count for name in sorted(port_by_name)
        }
    else:
        qos_port_stats = None

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
        # trunk_vids 允许的内部 VLAN；混合端口只承载 hybrid_vids 允许的
        # 内部 VLAN；三种 VLAN 模式都未配置的端口不受接入/中继/混合 VLAN
        # 限制，按既有语义参与转发。
        attrs = port_by_name[port_name]
        access_vid = attrs["access_vid"]
        if access_vid is not None:
            return access_vid == vid
        trunk_vids = attrs["trunk_vids"]
        if trunk_vids is not None:
            return vid in trunk_vids
        hybrid_vids = attrs["hybrid_vids"]
        return hybrid_vids is None or vid in hybrid_vids

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
        trunk_pvid = ingress_attrs["trunk_pvid"]
        hybrid_vids = ingress_attrs["hybrid_vids"]
        hybrid_pvid = ingress_attrs["hybrid_pvid"]
        tagged = verdict["vlan"] is not None
        if tagged:
            # 带标签帧的内部 VLAN 取其标签 VID；在接入口上这也是违例事件的
            # 结果 vid 与 VLAN 计数归属。
            vid = verdict["vlan"]["vid"]
        elif access_vid is not None:
            # 接入口上的未标记帧 (含坏帧) 归入其接入 VLAN。
            vid = access_vid
        elif trunk_pvid is not None:
            # 配置了本征 VLAN 的中继端口上的未标记帧 (含坏帧) 归入该 PVID。
            vid = trunk_pvid
        elif hybrid_pvid is not None:
            # 混合端口上的未标记帧 (含坏帧) 归入其 hybrid_pvid。
            vid = hybrid_pvid
        else:
            # 其他端口上的未标记帧 (含坏帧) 归入缺省 VLAN 1。
            vid = UNTAGGED_VID
        src_mac = verdict["src_mac"]
        dst_mac = verdict["dst_mac"]

        egress = []
        # runt、oversize 或 bad_fcs：一律 dropped，不学习、不查表、无出口。
        # 入端口不能转发：该事件确定为 dropped。
        # 接入口收到任何带 802.1Q 标签的帧 (含 VID 0 或与 access_vid 相同)：
        # 接入策略违例，dropped，不学习、不查表、无出口。
        # 中继端口收到未标记帧但未配置 trunk_pvid，或标签 VID 为 0 或不在
        # trunk_vids 允许数组中：中继策略违例，dropped，不学习、不查表、
        # 无出口。配置了 trunk_pvid 时未标记帧归入该 PVID (保证属于
        # trunk_vids)，按合法候选继续既有流程。
        # 混合端口收到标签 VID 为 0 或不在 hybrid_vids 允许数组中的带标签帧：
        # 混合策略违例，dropped，不学习、不查表、无出口；未标记帧归入
        # hybrid_pvid (保证属于 hybrid_vids)，按合法候选继续既有流程。
        # 未通过上述检查的事件不进入 ACL 求值，matched_acl_rule 为 null。
        pre_acl_ok = not (
            not verdict["valid"]
            or not ingress_attrs["can_forward"]
            or (tagged and access_vid is not None)
            or (
                trunk_vids is not None
                and ((not tagged and trunk_pvid is None) or vid not in trunk_vids)
            )
            or (hybrid_vids is not None and tagged and vid not in hybrid_vids)
        )

        # 源 MAC 静态绑定在入口 ACL、端口安全、MAC 学习与目的查表前查询一次：
        # 仅对已通过帧合法性、入端口状态与 VLAN 入站策略的事件，按内部 VLAN
        # 与规范化源 MAC 查询；未绑定或源地址来自绑定端口时继续既有流程。
        # 绑定不创建转发表项，也不占动态学习额度。
        binding_violation = False
        if bindings_enabled and pre_acl_ok:
            bound_port = binding_map.get((vid, src_mac))
            if bound_port is not None and bound_port != ingress:
                # 冒用：固定 dropped、空出口；不求值 ACL，不学习、刷新或迁移
                # 源 MAC，也不查询目的地址。事件时钟触发的老化已在上方先执行。
                binding_violation = True

        # 入口 ACL 仅对已通过帧合法性、入端口转发状态与 VLAN 入站策略检查的
        # 事件求值，并在 MAC 学习、端口安全检查与目的查表之前执行；首条命中
        # 规则决定动作，均未命中时允许。vid 匹配内部 VLAN (接入口未标记帧用
        # access_vid，配置 trunk_pvid 的中继端口未标记帧用该 PVID，其他
        # 未标记帧用 VLAN 1)；pcp 只匹配带标签帧。
        # 绑定冒用事件不求值 ACL，matched_acl_rule 保持 null。
        matched_acl_rule = None
        acl_drop = False
        original_pcp = verdict["vlan"]["pcp"] if tagged else None
        # 带标签帧的可观察 PCP：未进入 ACL 求值、未命中或命中 allow/drop 时
        # 为原始 PCP；首条命中 remark_pcp 时在学习与目的查表前重标记为
        # set_pcp (内部 VLAN 不变，也不重新执行 ACL)。未标记帧始终为 None。
        effective_pcp = original_pcp
        if acl_enabled and pre_acl_ok and not binding_violation:
            for rule_index, rule in enumerate(acl_rules):
                if acl_rule_matches(
                    rule, src_mac, dst_mac, vid,
                    verdict["ether_type"], original_pcp,
                ):
                    matched_acl_rule = rule_index
                    break
            if matched_acl_rule is not None:
                matched_rule = acl_rules[matched_acl_rule]
                if matched_rule["action"] == "drop":
                    # ACL 丢弃：固定 dropped 且出口为空；不学习或刷新源 MAC，
                    # 不查目的表，不产生 learned/refreshed/moved 记录；
                    # 仍计入端口与 VLAN 的入站及丢弃计数。
                    acl_drop = True
                elif matched_rule["action"] == ACL_REMARK_ACTION:
                    # remark_pcp 与 allow 一样继续既有学习、端口安全、查表、泛洪与
                    # 计数路径，仅把 PCP 改成确定值；普通出口帧及由它触发的出口
                    # 镜像副本使用新 PCP，入口镜像仍复制重标记前的原始帧。
                    effective_pcp = matched_rule["set_pcp"]

        # 广播风暴抑制在源 MAC 绑定与入口 ACL 之后、MAC 学习/端口安全/目的
        # 查表之前做常数时间判定：只有目的 MAC 为 ff:ff:ff:ff:ff:ff 且已通过
        # 帧合法性、入口端口状态、VLAN 入站策略、源 MAC 绑定与入口 ACL 的事件
        # 才消耗该入口端口额度；组播、未知单播与前置策略丢弃的帧不计数。
        # 窗口从时刻 0 开始，以 time_ms 整除 window_ms 的商区分，边界事件
        # 进入新窗口；未列出的端口不受限制。
        storm_controlled = False
        if (
            storm_enabled
            and pre_acl_ok
            and not binding_violation
            and not acl_drop
            and dst_mac == BROADCAST_MAC
        ):
            storm_limit = storm_port_limits.get(ingress)
            if storm_limit is not None:
                window = time_ms // storm_window_ms
                state = storm_state[ingress]
                if state[0] != window:
                    state[0] = window
                    state[1] = 0
                if state[1] >= storm_limit:
                    # 超额：固定 dropped 且出口为空；不学习、刷新或迁移 MAC，
                    # 不查询目的表，也不产生 learned/refreshed/moved 记录。
                    # 事件时钟触发的老化已在上方先执行。
                    storm_controlled = True
                else:
                    state[1] += 1

        # 组播风暴抑制与广播抑制在同一位置、按相同规则做常数时间判定，但
        # 独立计数：只有目的 MAC 首字节最低位为 1 且不等于
        # ff:ff:ff:ff:ff:ff (即 destination_type 为 multicast)，且已通过
        # 帧合法性、入口端口状态、VLAN 入站策略、源 MAC 绑定与入口 ACL 的
        # 事件才消耗该入口端口额度；广播、未知单播与前置策略丢弃的帧不计数。
        # 窗口从时刻 0 开始，以 time_ms 整除 window_ms 的商区分，边界事件
        # 进入新窗口；未列出的端口不受限制。
        multicast_storm_controlled = False
        if (
            multicast_storm_enabled
            and pre_acl_ok
            and not binding_violation
            and not acl_drop
            and verdict["destination_type"] == "multicast"
        ):
            multicast_storm_limit = multicast_storm_port_limits.get(ingress)
            if multicast_storm_limit is not None:
                window = time_ms // multicast_storm_window_ms
                state = multicast_storm_state[ingress]
                if state[0] != window:
                    state[0] = window
                    state[1] = 0
                if state[1] >= multicast_storm_limit:
                    # 超额：固定 dropped 且出口为空；不学习、刷新或迁移 MAC，
                    # 不查询目的表，也不产生 learned/refreshed/moved 记录。
                    # 事件时钟触发的老化已在上方先执行。
                    multicast_storm_controlled = True
                else:
                    state[1] += 1

        # 未知单播风暴抑制与广播/组播抑制在同一位置、按相同规则做常数时间
        # 判定，但独立计数：只有目的地址为单播，且在当前帧学习前静态表与动态表
        # 对内部 VLAN 与规范化目的 MAC 均无表项 (动态表为本次老化清理之后、
        # 本帧学习之前的状态)，且已通过帧合法性、入口端口状态、VLAN 入站策略、
        # 源 MAC 绑定与入口 ACL 的事件才消耗该入口端口额度；广播、组播、已有
        # 表项命中的单播与前置策略丢弃的帧不计数。窗口从时刻 0 开始，以
        # time_ms 整除 window_ms 的商区分，边界事件进入新窗口；未列出的端口
        # 不受限制。
        unknown_unicast_storm_controlled = False
        if (
            unknown_unicast_storm_enabled
            and pre_acl_ok
            and not binding_violation
            and not acl_drop
            and verdict["destination_type"] == "unicast"
            and (vid, dst_mac) not in static_map
            and (vid, dst_mac) not in table
        ):
            unknown_unicast_storm_limit = unknown_unicast_storm_port_limits.get(
                ingress
            )
            if unknown_unicast_storm_limit is not None:
                window = time_ms // unknown_unicast_storm_window_ms
                state = unknown_unicast_storm_state[ingress]
                if state[0] != window:
                    state[0] = window
                    state[1] = 0
                if state[1] >= unknown_unicast_storm_limit:
                    # 超额：固定 dropped 且出口为空；不学习、刷新或迁移 MAC，
                    # 不查询目的表，也不产生 learned/refreshed/moved 记录。
                    # 事件时钟触发的老化已在上方先执行。
                    unknown_unicast_storm_controlled = True
                else:
                    state[1] += 1

        if (
            not pre_acl_ok
            or acl_drop
            or binding_violation
            or storm_controlled
            or multicast_storm_controlled
            or unknown_unicast_storm_controlled
        ):
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

        # 混合端口的出站标签动作：按 egress_ports 顺序仅记录实际混合出口。
        # 混合出口的内部 VLAN 已被 vlan_allows 保证属于其 hybrid_vids；
        # 属于 hybrid_untagged_vids 时剥除标签 (vlan 为 null)，否则携带该
        # VID 标签：原帧带标签时保留 ACL 处理后的 PCP (effective_pcp) 与原
        # DEI，未标记帧需要加标签时 PCP 与 DEI 均为 0。
        if hybrid_enabled:
            hybrid_egress_actions = []
            for name in egress:
                untagged_vids = port_by_name[name]["hybrid_untagged_vids"]
                if untagged_vids is None:
                    continue
                if vid in untagged_vids:
                    hybrid_egress_actions.append(
                        {"port": name, "tagged": False, "vlan": None}
                    )
                else:
                    if tagged:
                        action_vlan = {
                            "vid": vid,
                            "pcp": effective_pcp,
                            "dei": verdict["vlan"]["dei"],
                        }
                    else:
                        action_vlan = {"vid": vid, "pcp": 0, "dei": 0}
                    hybrid_egress_actions.append(
                        {"port": name, "tagged": True, "vlan": action_vlan}
                    )

        # QoS 队列分类：对最终 egress_ports 中的每个普通出口，带 802.1Q 标签
        # 的帧用 ACL 重标记后的 effective_pcp 查询 pcp_to_queue，未标记帧使用
        # untagged_queue；与 egress_ports 同序且一一对应。dropped、filtered
        # 或无出口事件为空数组。入口/出口镜像副本不参与分类；混合端口出站
        # 剥除标签也不改变按内部帧优先级得到的分类。分类只读取本事件的
        # 转发结果，时间与实际出口数线性相关，不改变任何既有状态。
        if qos_enabled:
            if tagged:
                qos_queue = qos_pcp_to_queue[effective_pcp]
            else:
                qos_queue = qos_untagged_queue
            egress_queues = [
                {"port": name, "queue": qos_queue} for name in egress
            ]

        result_record = {
            "event": index,
            "vid": vid,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "decision": decision,
            "egress_ports": egress,
        }
        if hybrid_enabled:
            # hybrid_egress_actions 紧随 egress_ports；没有混合出口时为空数组。
            result_record["hybrid_egress_actions"] = hybrid_egress_actions
        if mirror_enabled:
            # mirror_ports 紧随 egress_ports 之后。
            result_record["mirror_ports"] = mirror_ports
        if egress_mirror_enabled:
            # egress_mirror_ports 位于 mirror_ports 之后；未启用入口镜像时
            # 紧随 egress_ports。
            result_record["egress_mirror_ports"] = egress_mirror_ports
        if acl_enabled:
            # matched_acl_rule 位于所有既有字段之后：首条命中规则的零基索引；
            # 未命中或事件未进入 ACL 求值时为 null。
            result_record["matched_acl_rule"] = matched_acl_rule
            # effective_pcp 紧随 matched_acl_rule：带标签帧返回最终 PCP
            # (命中 remark_pcp 时为重标记值，否则为原始 PCP，丢弃路径也有
            # 确定值)；未标记帧为 null。
            result_record["effective_pcp"] = effective_pcp
        if bindings_enabled:
            # binding_violation 位于所有既有可选字段之后，仅源 MAC 冒用为 true；
            # 绑定表为空或省略时不增加该键。
            result_record["binding_violation"] = binding_violation
        if storm_enabled:
            # storm_controlled 位于所有既有可选字段之后，仅因超额被丢弃的
            # 广播事件为 true；省略 broadcast_storm_control 时不增加该键。
            result_record["storm_controlled"] = storm_controlled
        if multicast_storm_enabled:
            # multicast_storm_controlled 位于所有既有可选字段之后，仅因超额
            # 被丢弃的组播事件为 true；省略 multicast_storm_control 时不增加
            # 该键。
            result_record["multicast_storm_controlled"] = (
                multicast_storm_controlled
            )
        if unknown_unicast_storm_enabled:
            # unknown_unicast_storm_controlled 位于所有既有可选字段之后，仅因
            # 本功能超额被丢弃的未知单播事件为 true；省略
            # unknown_unicast_storm_control 时不增加该键。
            result_record["unknown_unicast_storm_controlled"] = (
                unknown_unicast_storm_controlled
            )
        if qos_enabled:
            # egress_queues 位于所有既有可选字段之后：每项固定键序 port、queue，
            # 与 egress_ports 同序且一一对应；省略 qos_queues 时不增加该键。
            result_record["egress_queues"] = egress_queues
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

        if include_qos_counters:
            # 队列计数只统计普通出口交付 (egress_ports)：泛洪的每个实际出口
            # 分别计数，单播只计命中的实际出口；dropped、filtered、无出口
            # 事件与入口/出口镜像副本都不计入。队列归属沿用本事件
            # egress_queues 的分类 (同一事件全部出口同属一个队列)，混合端口
            # 出站剥除或携带标签不改变该归属。
            for name in egress:
                qos_port_stats[name][qos_queue] += 1

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

    if include_qos_counters:
        # qos_counters 位于所有既有区段 (含 fdb_events) 之后：ports 按端口
        # name 的 Unicode 码点升序包含全部已配置物理端口 (qos_port_stats
        # 已按此序构建)，queues 按队列号升序包含 0..queue_count-1 的全部
        # 队列，计数为零也保留；缺省或为 false 时输出不含该键。
        output["qos_counters"] = {
            "ports": [
                {
                    "name": name,
                    "queues": [
                        {"queue": queue, "egress_frames": counts[queue]}
                        for queue in range(qos_queue_count)
                    ],
                }
                for name, counts in qos_port_stats.items()
            ]
        }

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


# qos-schedule 输入的字段及其规范顺序；额外字段一律拒绝。
# queue_count 声明单个出口端口的队列数量，queues 为按下标对齐队列号的有限
# 队列快照，transmit_count 声明本次最多出队发送的帧数，可选的 discipline
# 选择调度策略 (strict 或缺省为严格优先级，wrr 为加权轮询)，可选的 weights
# 仅在 discipline 为 wrr 时提供，按下标对齐队列号声明每队列的连续发送配额。
QOS_SCHEDULE_FIELD_ORDER = (
    "queue_count",
    "queues",
    "transmit_count",
    "discipline",
    "weights",
)
QOS_SCHEDULE_FIELD_SET = frozenset(QOS_SCHEDULE_FIELD_ORDER)

SCHEDULE_DISCIPLINE_STRICT = "strict"
SCHEDULE_DISCIPLINE_WRR = "wrr"
SCHEDULE_DISCIPLINES = frozenset(
    (SCHEDULE_DISCIPLINE_STRICT, SCHEDULE_DISCIPLINE_WRR)
)

MIN_SCHEDULE_QUEUE_COUNT = 1
MAX_SCHEDULE_QUEUE_COUNT_LOCAL = MAX_SCHEDULE_QUEUES


def read_schedule_input(path):
    """读取并解析 UTF-8 JSON 队列快照；读取/解码/解析失败抛 ValueError。"""
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError:
        # 使用固定消息，避免平台/locale 文本差异影响确定性。
        raise ValueError("cannot read input file")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("input file is not valid UTF-8")
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        # JSONDecodeError 是 ValueError 的子类；超长整数等解析限制同样归为输入错误。
        raise ValueError("input file is not valid JSON")


def validate_schedule_input(snapshot):
    """校验单个出口端口的队列快照，返回 (queue_count, queues, transmit_count,
    discipline, weights)。

    按字段在输入中出现的顺序报告未知字段，再按规范顺序报告缺失字段；
    queue_count 为 1..8 的整数，transmit_count 为 0..10000 的整数
    (布尔值不算整数)，queues 必须是长度等于 queue_count 的数组，每项为
    非空字符串帧标识组成的数组，同一标识不得重复，全部队列合计最多
    10000 项。可选 discipline 只接受字符串 strict 或 wrr，省略等同
    strict；wrr 必须提供 weights，strict (含省略) 不得携带 weights。
    weights 为长度恰好等于 queue_count 的整数数组，按下标对齐队列号，
    每项取值 1..100 (布尔值不算整数)。结构、字段、范围、长度或帧标识
    错误均为 ConfigError，path 精确指向对应字段或数组元素。
    """
    if not isinstance(snapshot, dict):
        raise ConfigError("top-level input must be an object", "$")

    values = {}
    for field, value in snapshot.items():
        path = "$." + field
        if field not in QOS_SCHEDULE_FIELD_SET:
            raise ConfigError("unexpected field '%s'" % field, path)
        values[field] = value

    for field in ("queue_count", "queues", "transmit_count"):
        if field not in values:
            raise ConfigError(
                "missing field '%s'" % field, "$." + field
            )

    queue_count = values["queue_count"]
    count_path = "$.queue_count"
    # bool 是 int 的子类型，必须显式排除。
    if isinstance(queue_count, bool) or not isinstance(queue_count, int):
        raise ConfigError("'queue_count' must be an integer", count_path)
    if (
        queue_count < MIN_SCHEDULE_QUEUE_COUNT
        or queue_count > MAX_SCHEDULE_QUEUE_COUNT_LOCAL
    ):
        raise ConfigError(
            "'queue_count' must be between %d and %d"
            % (MIN_SCHEDULE_QUEUE_COUNT, MAX_SCHEDULE_QUEUE_COUNT_LOCAL),
            count_path,
        )

    queues = values["queues"]
    queues_path = "$.queues"
    if not isinstance(queues, list):
        raise ConfigError("'queues' must be an array", queues_path)
    if len(queues) != queue_count:
        raise ConfigError(
            "'queues' must contain exactly %d elements" % queue_count,
            queues_path,
        )

    checked_queues = []
    total_frames = 0
    # 同一帧标识不得跨全部队列重复。
    seen_frames = set()
    for queue_index, queue in enumerate(queues):
        queue_path = "%s[%d]" % (queues_path, queue_index)
        if not isinstance(queue, list):
            raise ConfigError(
                "'queues' elements must be arrays", queue_path
            )
        checked_queue = []
        for frame_index, frame_id in enumerate(queue):
            frame_path = "%s[%d]" % (queue_path, frame_index)
            if not isinstance(frame_id, str):
                raise ConfigError(
                    "frame identifiers must be strings", frame_path
                )
            if len(frame_id) == 0:
                raise ConfigError(
                    "frame identifiers must be non-empty", frame_path
                )
            if frame_id in seen_frames:
                raise ConfigError(
                    "duplicate frame identifier '%s'" % frame_id, frame_path
                )
            seen_frames.add(frame_id)
            checked_queue.append(frame_id)
            total_frames += 1
            if total_frames > MAX_SCHEDULE_TOTAL_FRAMES:
                raise ConfigError(
                    "total number of queued frames exceeds maximum of %d"
                    % MAX_SCHEDULE_TOTAL_FRAMES,
                    frame_path,
                )
        checked_queues.append(checked_queue)

    transmit_count = values["transmit_count"]
    transmit_path = "$.transmit_count"
    # bool 是 int 的子类型，必须显式排除。
    if isinstance(transmit_count, bool) or not isinstance(transmit_count, int):
        raise ConfigError("'transmit_count' must be an integer", transmit_path)
    if transmit_count < 0 or transmit_count > MAX_SCHEDULE_TRANSMIT:
        raise ConfigError(
            "'transmit_count' must be between 0 and %d"
            % MAX_SCHEDULE_TRANSMIT,
            transmit_path,
        )

    discipline_path = "$.discipline"
    if "discipline" in values:
        discipline = values["discipline"]
        if not isinstance(discipline, str):
            raise ConfigError("'discipline' must be a string", discipline_path)
        if discipline not in SCHEDULE_DISCIPLINES:
            raise ConfigError(
                "'discipline' must be 'strict' or 'wrr'", discipline_path
            )
    else:
        # 省略 discipline 等同 strict。
        discipline = SCHEDULE_DISCIPLINE_STRICT

    weights_path = "$.weights"
    weights_present = "weights" in values
    if discipline == SCHEDULE_DISCIPLINE_WRR and not weights_present:
        raise ConfigError("missing field 'weights'", weights_path)
    if discipline == SCHEDULE_DISCIPLINE_STRICT and weights_present:
        raise ConfigError(
            "'weights' is only valid with 'wrr' discipline", weights_path
        )

    checked_weights = None
    if weights_present:
        weights = values["weights"]
        if not isinstance(weights, list):
            raise ConfigError("'weights' must be an array", weights_path)
        if len(weights) != queue_count:
            raise ConfigError(
                "'weights' must contain exactly %d elements" % queue_count,
                weights_path,
            )
        checked_weights = []
        for weight_index, weight in enumerate(weights):
            weight_path = "%s[%d]" % (weights_path, weight_index)
            # bool 是 int 的子类型，必须显式排除。
            if isinstance(weight, bool) or not isinstance(weight, int):
                raise ConfigError(
                    "'weights' elements must be integers", weight_path
                )
            if weight < MIN_SCHEDULE_WEIGHT or weight > MAX_SCHEDULE_WEIGHT:
                raise ConfigError(
                    "'weights' elements must be between %d and %d"
                    % (MIN_SCHEDULE_WEIGHT, MAX_SCHEDULE_WEIGHT),
                    weight_path,
                )
            checked_weights.append(weight)

    return (
        queue_count,
        checked_queues,
        transmit_count,
        discipline,
        checked_weights,
    )


def schedule_strict(queue_count, queues, transmit_count):
    """对队列快照执行严格优先级调度，返回 transmitted 记录列表。

    较大的队列号代表更高优先级；每次从当前最高的非空队列队首取出一项，
    同一队列保持先入先出，直到达到 transmit_count 或所有队列为空。
    使用每队列队首下标避免搬运帧标识。
    """
    # 每队列的队首下标；调度只推进下标，不从队列中搬运帧标识。
    heads = [0] * queue_count
    # 初始为最高队列号，逐档下降，跳过空队列。
    highest = queue_count - 1
    transmitted = []
    while len(transmitted) < transmit_count:
        while highest >= 0 and heads[highest] == len(queues[highest]):
            highest -= 1
        if highest < 0:
            # 所有队列为空，停止；transmit_count 大于待发送总数时只发送现有项。
            break
        frame_id = queues[highest][heads[highest]]
        heads[highest] += 1
        transmitted.append(
            {
                "sequence": len(transmitted),
                "queue": highest,
                "frame_id": frame_id,
            }
        )
    return heads, transmitted


def schedule_wrr(queue_count, queues, weights, transmit_count):
    """对队列快照执行确定性加权轮询调度，返回 (heads, transmitted)。

    每轮从最高队列号开始，按队列号递减访问队列，访问到 0 后再从最高队列
    开始下一轮；每次访问非空队列时最多连续发送其权重指定数量的队首帧，
    队内保持先入先出；队列不足本次配额时只发送现有帧，剩余配额不转借也
    不累计，空队列直接跳过。调度在已发送数量达到 transmit_count 或所有
    队列为空时停止。每次调用都从最高队列开始，不读取时间，也不保留跨
    调用游标。使用每队列队首下标，单次时间为 O(n+queue_count) 量级，
    附加内存为 O(n)。
    """
    heads = [0] * queue_count
    lengths = [len(queue) for queue in queues]
    remaining_total = sum(lengths)
    transmitted = []
    # 每一轮都从最高队列号开始；一轮结束 (访问完 0 号队列) 后重新开始。
    while len(transmitted) < transmit_count and remaining_total > 0:
        for queue_index in range(queue_count - 1, -1, -1):
            if heads[queue_index] == lengths[queue_index]:
                # 空队列直接跳过，配额不转借也不累计。
                continue
            # 本次访问最多发送权重指定数量，同时不超过 transmit_count
            # 与队列现有帧数；剩余配额不转借到其他队列，也不累计到下一轮。
            quota = min(
                weights[queue_index],
                lengths[queue_index] - heads[queue_index],
                transmit_count - len(transmitted),
            )
            for _ in range(quota):
                frame_id = queues[queue_index][heads[queue_index]]
                heads[queue_index] += 1
                transmitted.append(
                    {
                        "sequence": len(transmitted),
                        "queue": queue_index,
                        "frame_id": frame_id,
                    }
                )
            remaining_total -= quota
            if len(transmitted) == transmit_count:
                break
    return heads, transmitted


def schedule_queues(queue_count, queues, transmit_count, discipline, weights):
    """对单个出口端口的有限队列快照执行出队调度，返回固定键序结果。

    discipline 为 strict (或缺省) 时执行严格优先级调度；为 wrr 时执行
    确定性加权轮询调度。transmitted 按发送次序记录 (sequence 从 0 连续
    递增)；remaining 按队列号升序保留全部队列 (空队列也不省略)。
    """
    if discipline == SCHEDULE_DISCIPLINE_WRR:
        heads, transmitted = schedule_wrr(
            queue_count, queues, weights, transmit_count
        )
    else:
        heads, transmitted = schedule_strict(
            queue_count, queues, transmit_count
        )

    remaining = [
        {"queue": queue_index, "frame_ids": queues[queue_index][heads[queue_index]:]}
        for queue_index in range(queue_count)
    ]

    return {
        "schema": QOS_SCHEDULE_SCHEMA,
        "transmitted": transmitted,
        "remaining": remaining,
    }


def cmd_qos_schedule(args):
    try:
        snapshot = read_schedule_input(args.input)
    except ValueError as exc:
        emit_error("InputError", str(exc))
        return 2

    try:
        (
            queue_count,
            queues,
            transmit_count,
            discipline,
            weights,
        ) = validate_schedule_input(snapshot)
    except ConfigError as exc:
        emit_error("ConfigError", exc.message, exc.path)
        return 3

    result = schedule_queues(
        queue_count, queues, transmit_count, discipline, weights
    )
    sys.stdout.buffer.write(
        (json.dumps(result, ensure_ascii=False) + "\n").encode("utf-8")
    )
    return 0


# stp-root 快照的字段及其规范顺序；额外字段一律拒绝。
# bridge 声明本桥标识 (priority 加六字节单播 MAC)，ports 声明参与选举的
# 本地物理端口 (唯一 name 与 path_cost)，received_bpdus 为各端口收到的
# BPDU 快照 (引用一个本地端口并宣告根桥/发送桥标识)。
STP_ROOT_FIELD_ORDER = ("bridge", "ports", "received_bpdus")
STP_ROOT_FIELD_SET = frozenset(STP_ROOT_FIELD_ORDER)

STP_BRIDGE_FIELD_ORDER = ("priority", "mac")
STP_BRIDGE_FIELD_SET = frozenset(STP_BRIDGE_FIELD_ORDER)

STP_PORT_FIELD_ORDER = ("name", "path_cost")
STP_PORT_FIELD_SET = frozenset(STP_PORT_FIELD_ORDER)

STP_BPDU_FIELD_ORDER = (
    "port",
    "root_priority",
    "root_mac",
    "root_path_cost",
    "sender_priority",
    "sender_mac",
    "sender_port_id",
)
STP_BPDU_FIELD_SET = frozenset(STP_BPDU_FIELD_ORDER)

# sender_port_id 为 16 位桥端口标识，取值 0..65535。
MIN_STP_PORT_ID = 0
MAX_STP_PORT_ID = 65535


def read_stp_input(path):
    """读取并解析 UTF-8 JSON STP 快照；读取/解码/解析失败抛 ValueError。"""
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError:
        # 使用固定消息，避免平台/locale 文本差异影响确定性。
        raise ValueError("cannot read input file")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("input file is not valid UTF-8")
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        # JSONDecodeError 是 ValueError 的子类；超长整数等解析限制同样归为输入错误。
        raise ValueError("input file is not valid JSON")


def _check_stp_priority(value, path, field):
    """桥优先级：0..61440 的整数且为 4096 的倍数 (布尔值不算整数)。"""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError("'%s' must be an integer" % field, path)
    if value < MIN_STP_BRIDGE_PRIORITY or value > MAX_STP_BRIDGE_PRIORITY:
        raise ConfigError(
            "'%s' must be between %d and %d"
            % (field, MIN_STP_BRIDGE_PRIORITY, MAX_STP_BRIDGE_PRIORITY),
            path,
        )
    if value % STP_PRIORITY_STEP != 0:
        raise ConfigError(
            "'%s' must be a multiple of %d" % (field, STP_PRIORITY_STEP),
            path,
        )
    return value


def _check_stp_mac(value, path, field):
    """六字节单播 MAC 地址：六个冒号分隔的两位十六进制字节，首字节最低位为 0。"""
    if not isinstance(value, str):
        raise ConfigError("'%s' must be a string" % field, path)
    if not MAC_PATTERN.fullmatch(value):
        raise ConfigError(
            "'%s' must be six colon-separated two-digit hex octets" % field,
            path,
        )
    mac = value.lower()
    if int(mac.split(":")[0], 16) & 1:
        raise ConfigError("'%s' must be a unicast address" % field, path)
    return mac


def _check_stp_path_cost(value, path):
    """本地端口 path_cost：1..2147483647 的整数 (布尔值不算整数)。"""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError("'path_cost' must be an integer", path)
    if value < MIN_STP_PATH_COST or value > MAX_STP_PATH_COST:
        raise ConfigError(
            "'path_cost' must be between %d and %d"
            % (MIN_STP_PATH_COST, MAX_STP_PATH_COST),
            path,
        )
    return value


def _check_stp_root_path_cost(value, path):
    """BPDU 宣告的 root_path_cost：0..4294967295 的整数 (布尔值不算整数)。"""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError("'root_path_cost' must be an integer", path)
    if value < 0 or value > MAX_STP_ROOT_PATH_COST:
        raise ConfigError(
            "'root_path_cost' must be between 0 and %d"
            % MAX_STP_ROOT_PATH_COST,
            path,
        )
    return value


def _check_stp_port_id(value, path):
    """sender_port_id：0..65535 的整数 (布尔值不算整数)。"""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError("'sender_port_id' must be an integer", path)
    if value < MIN_STP_PORT_ID or value > MAX_STP_PORT_ID:
        raise ConfigError(
            "'sender_port_id' must be between %d and %d"
            % (MIN_STP_PORT_ID, MAX_STP_PORT_ID),
            path,
        )
    return value


def _check_stp_bpdu_port(value, path):
    # 引用校验在整条 BPDU 结构校验完成后进行，未知端口归 StateError。
    if not isinstance(value, str):
        raise ConfigError("'port' must be a string", path)
    return value


STP_BPDU_FIELD_CHECKS = {
    "port": _check_stp_bpdu_port,
    "root_priority": lambda value, path: _check_stp_priority(
        value, path, "root_priority"
    ),
    "root_mac": lambda value, path: _check_stp_mac(value, path, "root_mac"),
    "root_path_cost": _check_stp_root_path_cost,
    "sender_priority": lambda value, path: _check_stp_priority(
        value, path, "sender_priority"
    ),
    "sender_mac": lambda value, path: _check_stp_mac(value, path, "sender_mac"),
    "sender_port_id": _check_stp_port_id,
}


def validate_stp_root_input(snapshot):
    """离线校验 STP 根桥/根端口选举快照。

    顶层必须且仅含 bridge、ports、received_bpdus：bridge 为仅含
    priority (0..61440 且为 4096 倍数的整数) 与 mac (六字节单播地址)
    的对象；ports 为最多 4096 项的数组，每项仅含唯一 name (非空字符串)
    与 path_cost (1..2147483647 的整数，布尔值不算整数)；
    received_bpdus 为最多 10000 项的数组，每项仅含 port、root_priority、
    root_mac、root_path_cost、sender_priority、sender_mac、
    sender_port_id 七个字段 (整数均拒绝布尔值，MAC 均为六字节单播地址)。
    按字段在输入中出现的顺序报告首个错误，再按规范顺序报告缺失字段；
    BPDU 的 port 引用未知端口为 StateError。结构、字段、类型、范围、
    重复端口名与非法 MAC 均为 ConfigError，path 精确指向对应字段或元素。
    选举所需的累计代价溢出检查在 elect_stp_root 中完成。
    """
    if not isinstance(snapshot, dict):
        raise ConfigError("top-level input must be an object", "$")

    values = {}
    for field, value in snapshot.items():
        path = "$." + field
        if field not in STP_ROOT_FIELD_SET:
            raise ConfigError("unexpected field '%s'" % field, path)
        values[field] = value

    for field in STP_ROOT_FIELD_ORDER:
        if field not in values:
            raise ConfigError("missing field '%s'" % field, "$." + field)

    bridge = values["bridge"]
    bridge_path = "$.bridge"
    if not isinstance(bridge, dict):
        raise ConfigError("'bridge' must be an object", bridge_path)
    bridge_values = {}
    for field, value in bridge.items():
        path = bridge_path + "." + field
        if field not in STP_BRIDGE_FIELD_SET:
            raise ConfigError("unexpected field '%s'" % field, path)
        if field == "priority":
            bridge_values[field] = _check_stp_priority(value, path, "priority")
        else:
            bridge_values[field] = _check_stp_mac(value, path, "mac")
    for field in STP_BRIDGE_FIELD_ORDER:
        if field not in bridge_values:
            raise ConfigError(
                "missing field '%s'" % field, bridge_path + "." + field
            )

    ports = values["ports"]
    ports_path = "$.ports"
    if not isinstance(ports, list):
        raise ConfigError("'ports' must be an array", ports_path)
    if len(ports) > MAX_STP_PORTS:
        raise ConfigError(
            "number of ports exceeds maximum of %d" % MAX_STP_PORTS,
            ports_path,
        )

    port_names = set()
    for index, item in enumerate(ports):
        base = "%s[%d]" % (ports_path, index)
        if not isinstance(item, dict):
            raise ConfigError("port must be an object", base)
        port_values = {}
        for field, value in item.items():
            path = base + "." + field
            if field not in STP_PORT_FIELD_SET:
                raise ConfigError("unexpected field '%s'" % field, path)
            if field == "name":
                name = _check_name(value, path)
                if name in port_names:
                    raise ConfigError(
                        "duplicate port name '%s'" % name, path
                    )
                port_names.add(name)
                port_values[field] = name
            else:
                port_values[field] = _check_stp_path_cost(value, path)
        for field in STP_PORT_FIELD_ORDER:
            if field not in port_values:
                raise ConfigError(
                    "missing field '%s'" % field, base + "." + field
                )

    bpdus = values["received_bpdus"]
    bpdus_path = "$.received_bpdus"
    if not isinstance(bpdus, list):
        raise ConfigError("'received_bpdus' must be an array", bpdus_path)
    if len(bpdus) > MAX_STP_BPDUS:
        raise ConfigError(
            "number of received bpdus exceeds maximum of %d" % MAX_STP_BPDUS,
            bpdus_path,
        )

    for index, item in enumerate(bpdus):
        base = "%s[%d]" % (bpdus_path, index)
        if not isinstance(item, dict):
            raise ConfigError("bpdu must be an object", base)
        bpdu_values = {}
        for field, value in item.items():
            path = base + "." + field
            if field not in STP_BPDU_FIELD_SET:
                raise ConfigError("unexpected field '%s'" % field, path)
            bpdu_values[field] = STP_BPDU_FIELD_CHECKS[field](value, path)
        for field in STP_BPDU_FIELD_ORDER:
            if field not in bpdu_values:
                raise ConfigError(
                    "missing field '%s'" % field, base + "." + field
                )
        if bpdu_values["port"] not in port_names:
            raise StateError(
                "unknown port '%s'" % bpdu_values["port"], base + ".port"
            )


def _stp_mac_to_int(mac):
    """把规范化 MAC 字符串解释为 48 位无符号整数，用于按数值比较桥标识。"""
    return int(mac.replace(":", ""), 16)


def elect_stp_root(snapshot):
    """对已校验快照离线选举根桥与根端口，返回固定键序结果。

    先在本桥标识与各 BPDU 宣告的根桥标识间按 (priority, MAC 数值)
    升序确定根桥：本桥标识不大于任何宣告时本桥胜出 (is_root 为 true、
    root_path_cost 为 0、root_port 为 null)。否则仅比较宣告胜出根桥的
    BPDU，候选依次按 (root_path_cost 加本地端口 path_cost、发送桥
    priority、发送桥 MAC 数值、sender_port_id、本地端口 name) 取最小；
    同端口多条 BPDU 均参与，比较不依赖输入顺序，完全相同的候选取输入中
    最早的一条仅用于错误路径定位。胜出候选的累计代价超过
    4294967295 时以 ConfigError 失败。两次线性扫描完成选举，除本地
    端口代价映射 O(p) 外不保留额外状态，总时间为 O(p+b)。
    """
    bridge = snapshot["bridge"]
    local_priority = bridge["priority"]
    local_mac = bridge["mac"].lower()
    local_bridge_id = (local_priority, _stp_mac_to_int(local_mac))

    # 仅保留本地端口 name -> path_cost 的 O(p) 附加映射。
    port_cost = {
        port["name"]: port["path_cost"] for port in snapshot["ports"]
    }
    bpdus = snapshot["received_bpdus"]

    # 第一轮：在本桥与各 BPDU 宣告的根桥标识间选最小标识。
    winning_root = local_bridge_id
    for bpdu in bpdus:
        announced = (
            bpdu["root_priority"],
            _stp_mac_to_int(bpdu["root_mac"].lower()),
        )
        if announced < winning_root:
            winning_root = announced

    bridge_result = {"priority": local_priority, "mac": local_mac}

    if winning_root == local_bridge_id:
        return {
            "schema": STP_ROOT_SCHEMA,
            "bridge": bridge_result,
            "root": {"priority": local_priority, "mac": local_mac},
            "is_root": True,
            "root_path_cost": 0,
            "root_port": None,
        }

    # 第二轮：仅比较宣告胜出根桥的 BPDU，按完整候选键取最小。
    best_key = None
    best_index = None
    for index, bpdu in enumerate(bpdus):
        announced = (
            bpdu["root_priority"],
            _stp_mac_to_int(bpdu["root_mac"].lower()),
        )
        if announced != winning_root:
            continue
        total_cost = bpdu["root_path_cost"] + port_cost[bpdu["port"]]
        key = (
            total_cost,
            bpdu["sender_priority"],
            _stp_mac_to_int(bpdu["sender_mac"].lower()),
            bpdu["sender_port_id"],
            bpdu["port"],
        )
        # 完全相同的候选保留最早下标，仅用于确定的错误路径定位。
        if best_key is None or key < best_key:
            best_key = key
            best_index = index

    if best_key[0] > MAX_STP_ROOT_PATH_COST:
        raise ConfigError(
            "sum of 'root_path_cost' and port 'path_cost' must not exceed %d"
            % MAX_STP_ROOT_PATH_COST,
            "$.received_bpdus[%d].root_path_cost" % best_index,
        )

    winning_bpdu = bpdus[best_index]
    return {
        "schema": STP_ROOT_SCHEMA,
        "bridge": bridge_result,
        "root": {
            "priority": winning_root[0],
            "mac": winning_bpdu["root_mac"].lower(),
        },
        "is_root": False,
        "root_path_cost": best_key[0],
        "root_port": best_key[4],
    }


def cmd_stp_root(args):
    try:
        snapshot = read_stp_input(args.input)
    except ValueError as exc:
        emit_error("InputError", str(exc))
        return 2

    try:
        validate_stp_root_input(snapshot)
        result = elect_stp_root(snapshot)
    except ConfigError as exc:
        emit_error("ConfigError", exc.message, exc.path)
        return 3
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

    config_diff_parser = subparsers.add_parser(
        "config-diff",
        help="按 before/after 顺序比较两份物理端口配置的规范化快照",
        description=(
            "按命令行参数顺序读取 before 与 after 两个 UTF-8 JSON 端口配置"
            "文件，沿用 ports 的全部字段、校验规则、数量上限、排序与派生状态"
            "语义，比较两侧校验后的规范化快照 (不受原始 JSON 字段顺序影响)："
            "after 独有端口为 added_ports，before 独有端口为 removed_ports，"
            "同名端口任一公开快照字段不同则进入 changed_ports (改名视为删除加"
            "新增，不推断重命名)。"
        ),
        epilog=(
            "限制: 每侧端口数量上限为 %d；单个端口 name 长度上限为 %d 个字符。"
            "三个结果数组均按 name 的 Unicode 码点升序排列；"
            "相同输入重复执行的输出逐字节一致。"
            % (MAX_PORTS, MAX_PORT_NAME_LEN)
        ),
    )
    config_diff_parser.add_argument(
        "before",
        metavar="BEFORE",
        help="before 侧 UTF-8 JSON 端口配置文件路径 (错误路径置于 $.before 下)",
    )
    config_diff_parser.add_argument(
        "after",
        metavar="AFTER",
        help="after 侧 UTF-8 JSON 端口配置文件路径 (错误路径置于 $.after 下)",
    )
    config_diff_parser.set_defaults(func=cmd_config_diff)

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
            "带标签帧，VID 0 或不允许的标签帧作为中继策略违例丢弃；"
            "只有内部 VLAN 被允许的中继端口才能成为出口。"
            "中继端口可选 trunk_pvid (1..4094 的整数，只能与 trunk_vids 同时"
            "出现且必须属于该允许数组) 声明本征 VLAN：该端口上的未标记帧归入"
            "此 PVID 并继续既有的学习、查表、泛洪、ACL、绑定、端口安全、审计"
            "与计数流程；未配置 trunk_pvid 的中继端口仍将未标记帧作为中继"
            "策略违例丢弃。"
            "端口可选 hybrid_vids、hybrid_pvid 与 hybrid_untagged_vids "
            "(三者必须同时出现，与 access_vid、trunk_vids、trunk_pvid 互斥；"
            "hybrid_vids 为 1..4094 的非空不重复整数数组，hybrid_pvid 必须"
            "属于该数组，hybrid_untagged_vids 为其不重复子集且可为空) 声明"
            "混合 VLAN 端口：未标记入站帧归入 hybrid_pvid，带标签帧仅当 VID "
            "属于 hybrid_vids 时接受，VID 0 或未允许 VID 作为混合策略违例"
            "丢弃；混合端口仅在内部 VLAN 被允许时成为单播或泛洪出口，出站 "
            "VLAN 属于 hybrid_untagged_vids 时剥除标签，否则携带该 VID 标签 "
            "(原帧带标签时保留 ACL 处理后的 PCP 与原 DEI，未标记帧加标签时"
            "二者均为 0)；场景含混合端口时，每条结果在 egress_ports 后追加 "
            "hybrid_egress_actions (按 egress_ports 顺序仅记录实际混合出口，"
            "每项含 port、tagged、vlan)。"
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
            "(action 为 allow、drop 或 remark_pcp，至少含 src_mac、dst_mac、vid、"
            "ether_type、pcp 中一个匹配字段，省略字段视为通配)：仅对已通过"
            "帧合法性、入端口转发状态与 VLAN 入站策略的事件在学习与查表前"
            "求值，首条命中决定动作，均未命中时允许。remark_pcp 规则必须含 "
            "pcp 匹配与 0..7 的整数 set_pcp (仅该动作接受 set_pcp)，"
            "命中后在学习与查表前把带标签帧的 PCP 重标记为确定值，其余路径"
            "与 allow 一致，结果在所有既有字段后追加 matched_acl_rule 与 "
            "effective_pcp (首条命中规则的零基索引或 null；带标签帧的最终 PCP，"
            "未标记帧为 null)；"
            "可选 mac_bindings 声明最多 %d 条 VLAN 感知的源 MAC 静态绑定 "
            "(每项仅含 vid、mac、port，同一 (vid, 规范化 mac) 不得重复，可与 "
            "static_table 同键共存)：绑定只校验源地址，对已通过帧合法性、入端口"
            "状态与 VLAN 入站策略的事件，在入口 ACL、端口安全、MAC 学习与目的"
            "查表前按内部 VLAN 与规范化源 MAC 查询；源地址从绑定端口以外的端口"
            "出现时该事件固定 dropped、空出口，不求值 ACL、不学习刷新迁移、不查"
            "目的表，结果在所有既有可选字段后追加 binding_violation (仅冒用为 "
            "true)；绑定不创建转发表项也不占动态学习额度，省略或为空数组时行为"
            "与输出逐字节不变；"
            "可选 broadcast_storm_control 声明广播风暴抑制 (仅含 window_ms 与 "
            "port_limits)：window_ms 为 1..%d 的整数窗口长度，port_limits 把"
            "已配置物理端口名映射到 0..%d 的整数，表示该入口端口在一个固定窗口"
            "内允许的广播帧数，未列出的端口不受限制；启用后每个事件必须携带 "
            "time_ms (与 aging_time_ms 共用显式事件时钟)，窗口以 time_ms 整除 "
            "window_ms 的商区分，只有目的 MAC 为 ff:ff:ff:ff:ff:ff 且已通过"
            "帧合法性、入口端口状态、VLAN 入站策略、源 MAC 绑定与入口 ACL 的"
            "事件才消耗额度，超额候选帧固定 dropped、空出口，不学习刷新迁移、"
            "不查目的表，结果在所有既有可选字段后追加 storm_controlled (仅超额"
            "丢弃为 true)；省略时行为与输出逐字节不变；"
            "可选 multicast_storm_control 声明组播风暴抑制，结构与取值范围和 "
            "broadcast_storm_control 相同 (仅含 window_ms 与 port_limits)，"
            "二者同时启用时独立计数：只有目的 MAC 首字节最低位为 1 且不等于 "
            "ff:ff:ff:ff:ff:ff 且已通过帧合法性、入口端口状态、VLAN 入站策略、"
            "源 MAC 绑定与入口 ACL 的事件才消耗额度，广播与未知单播不占组播"
            "额度，超额候选帧固定 dropped、空出口，不学习刷新迁移、不查目的表，"
            "结果在所有既有可选字段后追加 multicast_storm_controlled (仅超额"
            "丢弃为 true)；省略时行为与输出逐字节不变；"
            "可选 unknown_unicast_storm_control 声明未知单播风暴抑制，结构与"
            "取值范围和 broadcast_storm_control 相同 (仅含 window_ms 与 "
            "port_limits)，三类抑制同时启用时独立计数：只有目的地址为单播，且"
            "在当前帧学习前静态表与动态表对内部 VLAN 与规范化目的 MAC 均无"
            "表项，且已通过帧合法性、入口端口状态、VLAN 入站策略、源 MAC 绑定"
            "与入口 ACL 的事件才消耗额度，广播、组播与已有表项命中的单播不占"
            "未知单播额度，超额候选帧固定 dropped、空出口，不学习刷新迁移、"
            "不查目的表，结果在所有既有可选字段后追加 "
            "unknown_unicast_storm_controlled (仅超额丢弃为 true)；省略时行为"
            "与输出逐字节不变；"
            "可选 qos_queues 声明出口队列分类 (仅含 queue_count、pcp_to_queue "
            "与 untagged_queue)：queue_count 为 1..8 的整数，pcp_to_queue 为"
            "恰好 8 个整数的数组 (下标为 PCP 0..7)，数组值与 untagged_queue "
            "均为 0..queue_count-1 的整数 (布尔值不算整数)；启用后每个普通"
            "出口按帧分类，带标签帧用 ACL 重标记后的 effective_pcp 查 "
            "pcp_to_queue，未标记帧用 untagged_queue，结果在所有既有可选字段"
            "后追加 egress_queues (每项含 port、queue，与 egress_ports 同序"
            "且一一对应，无出口时为空数组)；只做分类与审计，不改变转发决定，"
            "省略时行为与输出逐字节不变；"
            "可选 include_qos_counters 为 true 时 (必须同时提供合法的 "
            "qos_queues，否则在处理任何事件前以 ConfigError 失败，路径 "
            "$.include_qos_counters) 在所有既有区段之后追加 qos_counters："
            "ports 按端口 name 的 Unicode 码点升序包含全部已配置物理端口，"
            "每项的 queues 按队列号升序包含 0..queue_count-1 的全部队列 "
            "(每项含 queue 与 egress_frames，计数为零也保留)，按事件的实际"
            "普通出口逐端口逐队列累计 (泛洪分别计数，镜像副本不计入)；"
            "缺省或为 false 时行为与输出逐字节不变；"
            "无端口模式或跨进程持久化。"
            % (
                MAX_ACL_RULES,
                MAX_MAC_BINDINGS,
                MAX_STORM_WINDOW_MS,
                MAX_STORM_PORT_LIMIT,
            )
        ),
        epilog=(
            "限制: 端口数量上限为 %d；事件数量上限为 %d；静态表项数量上限为 %d；"
            "源 MAC 绑定数量上限为 %d；入口 ACL 规则数量上限为 %d。"
            "aging_time_ms 与 time_ms 取值为 1..%d / 0..%d 的整数，"
            "time_ms 按事件顺序单调不减；不读墙上时钟。"
            "broadcast_storm_control、multicast_storm_control 与 "
            "unknown_unicast_storm_control 的 window_ms "
            "与 port_limits 限额取值均为 1..%d / 0..%d 的整数。"
            "泛洪出口按端口 name 的 Unicode 码点升序排列；"
            "相同输入的输出逐字节一致。"
            % (
                MAX_PORTS,
                MAX_EVENTS,
                MAX_STATIC_ENTRIES,
                MAX_MAC_BINDINGS,
                MAX_ACL_RULES,
                MAX_AGING_TIME_MS,
                MAX_EVENT_TIME_MS,
                MAX_STORM_WINDOW_MS,
                MAX_STORM_PORT_LIMIT,
            )
        ),
    )
    forward_parser.add_argument(
        "--scenario",
        required=True,
        metavar="FILE",
        help=(
            "UTF-8 JSON 场景文件路径，顶层包含 ports 数组与 events 数组，"
            "可选 aging_time_ms、static_table、mac_bindings、include_counters、"
            "include_fdb_events、include_qos_counters、ingress_mirror、"
            "egress_mirror、"
            "ingress_acl、broadcast_storm_control、multicast_storm_control、"
            "unknown_unicast_storm_control 与 qos_queues；每个事件包含 "
            "ingress_port 与完整 frame 描述，启用老化或风暴抑制时每个事件"
            "还需包含 time_ms"
        ),
    )
    forward_parser.set_defaults(func=cmd_forward)

    qos_schedule_parser = subparsers.add_parser(
        "qos-schedule",
        help="对单个出口端口的有限队列快照执行严格优先级或加权轮询调度",
        description=(
            "通过 --input 读取 UTF-8 JSON 队列快照 (顶层含 queue_count、"
            "queues 与 transmit_count，可选 discipline 与 weights)，对单个"
            "出口端口执行出队调度，并向标准输出写入单行固定键序 JSON。"
            "discipline 省略或为 strict 时执行严格优先级调度：较大的队列号"
            "代表更高优先级，每次从当前最高的非空队列队首取出一项，同一队列"
            "保持先入先出，直到达到 transmit_count 或所有队列为空。"
            "discipline 为 wrr 时执行加权轮询：必须提供长度等于 "
            "queue_count、每项 1..100 整数的 weights，按下标对齐队列号；"
            "每轮从最高队列号开始按队列号递减访问，访问到 0 后再从最高队列"
            "开始下一轮，每次访问非空队列时最多连续发送其权重指定数量的队首"
            "帧，队列不足配额时只发送现有帧，剩余配额不转借也不累计，空队列"
            "直接跳过。"
        ),
        epilog=(
            "限制: queue_count 为 1..%d；transmit_count 为 0..%d；"
            "全部队列合计最多 %d 项；wrr 的 weights 每项为 %d..%d 的整数。"
            "transmit_count 大于待发送总数时只发送现有项目；"
            "相同输入的输出逐字节一致，单次时间为 O(n+queue_count)。"
            % (
                MAX_SCHEDULE_QUEUES,
                MAX_SCHEDULE_TRANSMIT,
                MAX_SCHEDULE_TOTAL_FRAMES,
                MIN_SCHEDULE_WEIGHT,
                MAX_SCHEDULE_WEIGHT,
            )
        ),
    )
    qos_schedule_parser.add_argument(
        "--input",
        required=True,
        metavar="FILE",
        help=(
            "UTF-8 JSON 队列快照文件路径，顶层包含 queue_count (1..8 的"
            "整数)、queues (长度等于 queue_count 的数组，每项为非空字符串帧"
            "标识组成的数组，同一标识不得重复) 与 transmit_count "
            "(0..10000 的整数)；可选 discipline (仅 strict 或 wrr，省略"
            "等同 strict)，选择 wrr 时必须提供 weights (长度恰好等于 "
            "queue_count 的整数数组，每项对应同下标队列，取值 1..100，"
            "布尔值不算整数)，strict 或省略 discipline 时不得提供 weights"
        ),
    )
    qos_schedule_parser.set_defaults(func=cmd_qos_schedule)

    stp_root_parser = subparsers.add_parser(
        "stp-root",
        help="离线选举生成树根桥与根端口",
        description=(
            "通过 --input 读取 UTF-8 JSON 快照 (顶层包含 bridge、ports 与 "
            "received_bpdus)，离线选举根桥和根端口，并向标准输出写入单行"
            "固定键序 JSON。先在本桥与各 BPDU 宣告的根桥标识间按 "
            "priority、MAC 数值升序确定根桥：本桥胜出时 is_root 为 true、"
            "root_path_cost 为 0、root_port 为 null；否则仅比较宣告胜出"
            "根桥的 BPDU，依次按 root_path_cost 加本地 path_cost、发送桥 "
            "priority、发送桥 MAC、sender_port_id、本地端口 name 取最小"
            "候选，代价之和不得超过 4294967295。同端口多条 BPDU 均参与，"
            "结果不依赖输入顺序。"
        ),
        epilog=(
            "限制: 端口数量上限为 %d；BPDU 数量上限为 %d；"
            "bridge priority 为 %d..%d 且为 %d 的倍数；"
            "端口 path_cost 为 1..%d；root_path_cost 为 0..%d；"
            "sender_port_id 为 0..65535。"
            "相同输入的输出逐字节一致，单次时间为 O(p+b)，不读墙上时钟。"
            % (
                MAX_STP_PORTS,
                MAX_STP_BPDUS,
                MIN_STP_BRIDGE_PRIORITY,
                MAX_STP_BRIDGE_PRIORITY,
                STP_PRIORITY_STEP,
                MAX_STP_PATH_COST,
                MAX_STP_ROOT_PATH_COST,
            )
        ),
    )
    stp_root_parser.add_argument(
        "--input",
        required=True,
        metavar="FILE",
        help=(
            "UTF-8 JSON STP 快照文件路径，顶层包含 bridge (priority 为 "
            "0..61440 且为 4096 倍数的整数，mac 为六字节单播地址)、ports "
            "(每项含唯一 name 与 1..2147483647 的 path_cost，最多 4096 项) "
            "与 received_bpdus (每项引用一个端口并含 root_priority、"
            "root_mac、root_path_cost、sender_priority、sender_mac、"
            "sender_port_id，最多 10000 条)；布尔值不算整数"
        ),
    )
    stp_root_parser.set_defaults(func=cmd_stp_root)

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
