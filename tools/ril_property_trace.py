import re
import struct


SINK_PATH = "/dev/lineage_ril_property_audit"
MAGIC = b"RILSET1\0"
HEADER_BYTES = 64
RECORD_BYTES = 640
CAPACITY = 512
FILE_BYTES = HEADER_BYTES + RECORD_BYTES * CAPACITY
SOURCE_CONTEXT = "u:r:rild:s0"
HEADER = struct.Struct("<8s14I")
RECORD = struct.Struct("<iIQ256s256s112s")
NAME = re.compile(r"(?:vendor\.|persist\.vendor\.|ro\.vendor\.)[A-Za-z0-9_.:@-]+\Z")
CONTEXT = re.compile(r"u:object_r:[A-Za-z0-9_]+:s0\Z")


class TraceError(ValueError):
    pass


class UnstableSnapshot(TraceError):
    pass


def header(data):
    if len(data) != FILE_BYTES:
        raise TraceError("Unexpected RIL trace size: " + str(len(data)))
    fields = HEADER.unpack_from(data)
    magic, version, header_bytes, record_bytes, capacity = fields[:5]
    if (magic, version, header_bytes, record_bytes, capacity) != (MAGIC, 1, HEADER_BYTES, RECORD_BYTES, CAPACITY):
        raise TraceError("Unsupported RIL trace schema")
    sequence, records, attempts, duplicates, dropped, flags = fields[5:11]
    if any(fields[11:]) or flags & ~15 or records > CAPACITY:
        raise TraceError("Invalid RIL trace header")
    if sequence % 2:
        raise UnstableSnapshot("RIL trace writer is active")
    return sequence, records, attempts, duplicates, dropped, flags


def c_string(data):
    end = data.find(b"\0")
    if end < 0 or any(data[end:]):
        raise TraceError("Invalid RIL trace string padding")
    try:
        return data[:end].decode("ascii")
    except UnicodeDecodeError as error:
        raise TraceError("Non-ASCII RIL trace field") from error


def parse_pair(first, second):
    first_header = header(first)
    second_header = header(second)
    if first_header != second_header or first[:HEADER_BYTES] != second[:HEADER_BYTES]:
        raise UnstableSnapshot("RIL trace changed between snapshots")
    sequence, count, attempts, duplicates, dropped, flags = first_header
    if not flags & (2 | 8) and attempts != count + duplicates + dropped:
        raise TraceError("Inconsistent RIL trace counters")
    records = []
    keys = set()
    for index in range(count):
        pid, uid, boottime_ns, name_bytes, context_bytes, reserved = RECORD.unpack_from(
            first, HEADER_BYTES + index * RECORD_BYTES)
        name = c_string(name_bytes)
        context = c_string(context_bytes)
        if pid <= 0 or not NAME.fullmatch(name) or not CONTEXT.fullmatch(context) or any(reserved):
            raise TraceError("Invalid RIL trace record " + str(index))
        key = (pid, uid, name, context)
        if key in keys:
            raise TraceError("Duplicate RIL trace record")
        keys.add(key)
        records.append({"pid": pid, "uid": uid, "boottime_ns": boottime_ns,
                        "name": name, "source_context": SOURCE_CONTEXT, "target_context": context})
    if any(first[HEADER_BYTES + count * RECORD_BYTES:]):
        raise TraceError("Unexpected data outside committed RIL trace records")
    return {"schema_version": 1, "status": "captured", "snapshot_consistent": True,
            "phase": "before_mac", "source_context": SOURCE_CONTEXT,
            "record_semantics": "first_seen_per_pid_uid_name_context",
            "exhaustive": False, "sequence": sequence, "capacity": CAPACITY,
            "attempts": attempts, "duplicates": duplicates, "dropped": dropped,
            "flags": flags, "counters_stopped": bool(flags & 8), "truncated": bool(flags),
            "records": records,
            "caveat": "Attempt names only; neither policy decisions nor successful writes. Workload coverage is not established."}
