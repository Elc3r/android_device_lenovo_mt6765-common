#!/usr/bin/env python3
import argparse
import collections
from datetime import datetime, timedelta
import json
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import time

import ril_property_trace


EXPECTED_DEVICE = "achilles6_row_data"
PROPERTY_NAMES = [
    "ro.product.device", "ro.build.fingerprint", "ro.build.version.incremental",
    "ro.build.version.security_patch", "ro.vendor.build.security_patch",
    "ro.crypto.state", "ro.crypto.type", "sys.boot_completed", "init.svc.console",
]
REQUIRED_HAL = [
    "android.hardware.keymaster@4.0::IKeymasterDevice/default",
    "android.hardware.camera.provider@2.4::ICameraProvider/internal/0",
    "android.hardware.bluetooth@1.0::IBluetoothHci/default",
    "android.hardware.wifi@1.0::IWifi/default",
    "vendor.mediatek.hardware.mtkpower@1.0::IMtkPower/default",
    "vendor.mediatek.hardware.pq@2.3::IPictureQuality/default",
]
SERVICE_NAMES = ["SurfaceFlinger", "media.camera", "media.audio_flinger", "sensorservice", "power"]
MEDIA_PROPERTY_LIBRARIES = {
    "/vendor/lib64/libcam.iopipe.so": {
        "original": "e05e576c4dac9bdff507e1904814a9df104f723c7e6b582392d3ff3b13ad300c",
        "migrated": "319bb8c1cc09ad590741973bb249f51e44a415c169577a82d49802732f9f238d",
    },
    "/vendor/lib/libMtkOmxCore.so": {
        "original": "48f37a722850e21386b8c4eec02f3266c2306106350eb7b537b96f986dabdee0",
        "migrated": "68d92cb015eefa82bef541eeae4a26c54d93da4337654a1ada920f746bc0689d",
    },
    "/vendor/lib64/libMtkOmxCore.so": {
        "original": "36f0baab53a4d3b658acecf9b93023c3d07d7a04c3e566722133b909961a35c5",
        "migrated": "709e932cd450213e1a8a42e1f31bd4919b6ef0e473c3e31489f0b617f0db5608",
    },
}
INTERFACE_DOMAINS = {
    "mediacodec", "hal_camera_default", "mtk_vtservice", "rild", "vendor_bip",
    "vendor_ccci_mdinit", "vendor_nvram_daemon", "vendor_bp_kmsetkey_ca", "surfaceflinger",
    "hal_graphics_composer_default",
}
BOOT_MIGRATION_FILES = {
    "/vendor/lib64/libmtk-ril.so": {
        "original": "3bde0c384b74835fc4e1ceafab74fe1afeb98dc6be6b2bf91e14467ffd4a8c47",
        "migrated": "5c6a0d928859a2f6684999461568cfb2f6d784b5c10010628f6c5bb0e9b7e8c6",
    },
    "/vendor/lib64/libmtkcam.logicalmodule.so": {
        "original": "a7efe5e255a08bcd0b530ba3f4a13089800e3758ccceab51a68548f93030ef6a",
        "migrated": "c6e41ab7f6a38ce8f9c37c3620b4cffa6438cc6f20a065c95f2c0b58d1149ce0",
    },
    "/vendor/lib64/libfeature.stereo.provider.so": {
        "original": "5cc82117be98e1849e267f19d093d121445d425f40b8af63c0546621ef3bfefd",
        "migrated": "47f6041f4e482eb67c86c711c6b8dc68b2e53fbdaefb41a2a1df426f4332733e",
    },
    "/vendor/lib64/libstereoinfoaccessor_vsdof.so": {
        "original": "678641db4def23261cb99f99d3fe758cb8c5500ac88e6734bbad4cb555a4b8c1",
        "migrated": "5e26254af9fb53b7b6f43d14b261a147bdcdc9a3b38ddcd71d586cecac0ed75d",
    },
    "/vendor/lib64/egl/libGLES_meow.so": {
        "original": "32fa3f4d9044a72251c2e310c000b038867f1dabd091ac7da67e9f206b7803e8",
        "migrated": "57c4c58b1cf1b85a4f0c1ae88929343ec5bbda2facc9bd4519070e5abcc00ece",
    },
    "/vendor/bin/ccci_mdinit": {
        "original": "98d7ab98c4abf5139d01b84ac9eb4dc9bcec275789857e77087f5b486589cf19",
        "migrated": "1a81767ca29c669884df518a2a2702c14bc251046ceeff2edc48d768e41b7ae8",
    },
    "/vendor/bin/nvram_daemon": {
        "original": "9d61663f1310a11e1eaf4da28a592c0d1be6c5b6a6776940a506ad984c3d1fa3",
        "migrated": "41d32484e1a8ec35cfc1d88814d6736a15b6290e3dfd385b4bfcfbf48b0075a8",
    },
}
CODEC_LIBRARIES = {
    "/vendor/lib/libvcodec_utility.so": {
        "original": "7bea798d69d332b5f4286777fc3ecb3dcbdf38867f50013fc2676f71e4bc6d02",
        "migrated": "e4b004250d36be63347ef10ba3781a1e3e5f70e8c828d84828a42ce589fd3fda",
    },
    "/vendor/lib64/libvcodec_utility.so": {
        "original": "6565dc7b017121fa9883379bd974625cf7d662401f5fb3aeee48bc482b8b63b0",
        "migrated": "9bb25dd00017f05d717d6e3566df325f6d85dc5a0c8c6a274bd89f8564f1fe25",
    },
}
TRACE = re.compile(r"^\S+\s+\S+\s+(?:[+-]\d{4}\s+)?(\d+)\s+\d+\s+\S\s+property_audit\s*:\s*lookup name=(\S+) context=(\S+) sequence=(\d+)")
PROPERTY_ROUTE = re.compile(r"^\S+\s+\S+\s+(?:[+-]\d{4}\s+)?(\d+)\s+(\d+)\s+\S\s+property_route\s*:\s*route operation=(serialized_init|named_lookup|foreach|reset_access|named_vendor_open|foreach_vendor|reset_vendor|vendor_check|vendor_open) context=(none|u:object_r:vendor_default_prop:s0) env=(absent|enabled|disabled) scope=process_selector limit=9(?:\s|$)")
LOSS = re.compile(r"audit.*(?:lost[= :]+[1-9]\d*|backlog limit|rate limit exceeded)|logd.*dropped", re.I)
CRASH = re.compile(r"FATAL EXCEPTION|Fatal signal|WATCHDOG KILLING")


DISPLAY_LIBRARIES = {
    "/vendor/lib64/libdpframework.so": {
        "pinned": "9f06c4638faa3b1c7903d6256180a6343e57fe52674aa248f29eb63d1c450817",
    },
    "/vendor/lib64/hw/hwcomposer.mt6765.so": {
        "pinned": "9a18055801d3100da86a8083f6a204d45b1a9170ff9694672c993266cdf6fff9",
    },
}


class AuditError(Exception):
    pass


def process_map(text):
    processes = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) > 3 and fields[0].startswith("u:r:") and fields[2].isdigit():
            processes[fields[2]] = {"context": fields[0], "name": fields[-1]}
    return processes


def case_category(key):
    source, target, kind, ioctl, permissions, target_object = key
    domain = source.split(":")[2] if source.startswith("u:r:") else ""
    target_type = target.split(":")[2] if target.startswith("u:object_r:") else ""
    if domain.startswith(("untrusted_app", "isolated_app", "ephemeral_app")):
        return "app_policy_review"
    if target_type in {"net_dns_prop", "radio_cdma_ecm_prop", "init_service_status_private_prop"}:
        return "platform_private_interface"
    if kind == "blk_file":
        return "raw_partition_interface"
    if target_type == "tee_device":
        return "tee_interface"
    if kind == "property_service":
        return "property_write_interface"
    if target_type in {"default_prop", "vendor_default_prop"}:
        return "untyped_property_read"
    if target_type.endswith("_prop"):
        return "typed_property_access"
    if domain == "surfaceflinger" and target_type == "mnt_user_file":
        return "compositor_user_storage"
    if domain == "vendor_init" and target_object == "name:generate-oops":
        return "legacy_boot_diagnostic"
    return "vendor_runtime_review"


def summarize_categories(cases):
    categories = {}
    for item in cases:
        category = case_category(item["key"])
        bucket = categories.setdefault(category, {"raw_records": 0, "signatures": set(), "object_cases": 0})
        bucket["raw_records"] += item["records"]
        bucket["signatures"].add(tuple(item["key"][:5]))
        bucket["object_cases"] += 1
    return {category: {**bucket, "signatures": len(bucket["signatures"])}
            for category, bucket in sorted(categories.items())}


def analyze(text, processes_text="", hal_text=""):
    processes = process_map(processes_text)
    signatures = collections.Counter()
    cases = collections.Counter()
    examples = {}
    events = set()
    traces = collections.Counter()
    budgets = {}
    trace_modes = collections.Counter()
    trace_incomplete = []
    property_routes = collections.Counter()
    losses = []
    crashes = []
    for line_number, line in enumerate(text.splitlines()):
        if LOSS.search(line):
            losses.append(line)
        if CRASH.search(line):
            crashes.append(line)
        route = PROPERTY_ROUTE.search(line)
        if route:
            property_routes[route.groups()] += 1
        if re.search(r"\bproperty_audit\s*:\s*incomplete\s+reason=", line):
            trace_incomplete.append(line)
        match = TRACE.search(line)
        if match:
            pid, name, context, sequence = match.groups()
            traces[(pid, name, context)] += 1
            budgets[pid] = max(budgets.get(pid, 0), int(sequence))
            trace_modes["distinct" if re.search(r"\bmode=distinct\b", line) else "legacy"] += 1
        if not re.search(r"avc:\s*denied", line):
            continue
        fields = {}
        for field in ["scontext", "tcontext", "tclass", "ioctlcmd"]:
            match = re.search(r"\b" + field + r"=([^\s]+)", line)
            fields[field] = match.group(1) if match else ""
        permissions = re.search(r"denied\s*\{([^}]+)\}", line)
        signature = tuple(fields[field] for field in ["scontext", "tcontext", "tclass", "ioctlcmd"])
        signature += (" ".join(sorted(permissions.group(1).split())) if permissions else "",)
        signatures[signature] += 1
        match = re.search(r"\bproperty=([^\s]+)", line)
        if match:
            target = "property:" + match.group(1).rstrip("'\"")
        else:
            match = re.search(r'\bpath="([^"]+)"', line)
            if match:
                target = "path:" + re.sub(r"^/proc/\d+/", "/proc/<pid>/", match.group(1))
            else:
                match = re.search(r'\bname="([^"]+)"', line)
                target = "name:" + match.group(1) if match else "unknown"
        case = signature + (target,)
        cases[case] += 1
        examples.setdefault(case, line)
        match = re.search(r"audit\(([^)]+)\)", line)
        events.add((match.group(1) if match else "line:" + str(line_number), signature))
    published = {field for line in hal_text.splitlines() if line.startswith("DM")
                 for field in line.split() if "::" in field}
    object_cases = [{"key": list(key), "records": count, "example": examples[key]}
                    for key, count in cases.most_common()]
    return {
        "schema_version": 1,
        "raw_avc_records": sum(signatures.values()),
        "unique_audit_events": len(events),
        "distinct_signatures": len(signatures),
        "signatures": [{"key": list(key), "records": count} for key, count in sorted(signatures.items())],
        "object_cases": object_cases,
        "categories": summarize_categories(object_cases),
        "loss_markers": losses,
        "crash_markers": crashes,
        "property_lookup_records": sum(traces.values()),
        "property_lookup_names": len({key[1] for key in traces}),
        "property_trace_modes": dict(trace_modes),
        "property_trace_incomplete": trace_incomplete,
        "property_routes": [{"pid": pid, "tid": tid, "operation": operation,
                             "context": context, "environment": environment,
                             "records": count, "process_at_snapshot": processes.get(pid)}
                            for (pid, tid, operation, context, environment), count
                            in sorted(property_routes.items())],
        "property_lookups": [{"pid": pid, "name": name, "context": context, "records": count,
                              "process_at_snapshot": processes.get(pid)}
                             for (pid, name, context), count in sorted(traces.items())],
        "saturated_property_pids": sorted(pid for pid, sequence in budgets.items() if sequence >= 128),
        "init_domain_processes": [{"pid": pid, **process} for pid, process in processes.items()
                                  if process["context"] == "u:r:init:s0"],
        "required_hal": {name: name in published for name in REQUIRED_HAL} if hal_text.strip() else {},
        "warnings": [],
        "scope": "Log and registration checks only; not hardware validation or enforcing readiness.",
    }


def compare(report, baseline):
    old = {tuple(item["key"]) for item in baseline["signatures"]}
    new = {tuple(item["key"]) for item in report["signatures"]}
    old_objects = {tuple(item["key"]) for item in baseline["object_cases"]}
    new_objects = {tuple(item["key"]) for item in report["object_cases"]}
    return {
        "previous_raw_avc_records": baseline["raw_avc_records"],
        "previous_distinct_signatures": baseline["distinct_signatures"],
        "disappeared_signatures": len(old - new), "new_signatures": len(new - old),
        "new_object_cases": [list(key) for key in sorted(new_objects - old_objects)],
        "disappeared_object_cases": [list(key) for key in sorted(old_objects - new_objects)],
        "caveat": "Different capture coverage and generic-label suppression prevent counting fixed bugs.",
    }


def load_baseline(path):
    if path is None:
        return None
    if path.suffix == ".json":
        baseline = json.loads(path.read_text())
        if not isinstance(baseline, dict) or baseline.get("schema_version") != 1 or not all(
            isinstance(baseline.get(field), list) for field in ["signatures", "object_cases"]
        ):
            raise AuditError("Baseline JSON nemá podporovaný formát; použij původní log.")
        for field in ["signatures", "object_cases"]:
            expected_length = 5 if field == "signatures" else 6
            if any(not isinstance(item, dict) or not isinstance(item.get("key"), list)
                   or len(item["key"]) != expected_length
                   or not all(isinstance(value, str) for value in item["key"])
                   for item in baseline[field]):
                raise AuditError("Baseline má neplatné klíče auditních kombinací.")
        if not all(isinstance(baseline.get(field), int) for field in ["raw_avc_records", "distinct_signatures"]):
            raise AuditError("Baseline neobsahuje platné počty auditů.")
        return baseline
    return analyze(path.read_text(errors="replace"))


def marker_timing(markers, window):
    groups = {"historical": [], "during_collection": [], "unknown": []}
    try:
        if (not isinstance(window, dict) or window.get("time_basis") != "utc-year"
                or window.get("same_boot_verified") is not True):
            raise ValueError("Missing verified capture window")
        start = datetime.strptime(window["start"], "%Y-%m-%dT%H:%M:%SZ")
        end = datetime.strptime(window["end"], "%Y-%m-%dT%H:%M:%SZ")
        elapsed = window["monotonic_seconds"]
        if (isinstance(elapsed, bool) or not isinstance(elapsed, (int, float)) or not 0 <= elapsed < float("inf")
                or end < start or abs((end - start).total_seconds() - elapsed) > 5):
            raise ValueError("Unreliable device clock")
        definite_start = start + timedelta(seconds=1)
    except (KeyError, TypeError, ValueError, OverflowError):
        groups["unknown"] = list(markers)
        return groups
    for line in markers:
        match = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3,6})\s", line)
        try:
            timestamp = datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S.%f") if match else None
        except ValueError:
            timestamp = None
        if timestamp is not None and timestamp < start:
            groups["historical"].append(line)
        elif timestamp is not None and definite_start <= timestamp <= end:
            groups["during_collection"].append(line)
        else:
            groups["unknown"].append(line)
    return groups


def save_report(directory, report, baseline):
    if baseline is not None:
        report["comparison"] = compare(report, baseline)
    warnings = report["warnings"]
    timing = {name: marker_timing(report[field], report.get("capture_window"))
              for name, field in [("loss", "loss_markers"), ("crash", "crash_markers")]}
    report["marker_timing"] = timing
    if timing["loss"]["during_collection"]:
        warnings.append("V intervalu sběru byly zaznamenány ztrátové hlášky auditu; nejde o počet ztracených záznamů.")
    if timing["loss"]["unknown"]:
        warnings.append("Čas části ztrátových hlášek nelze určit; nejsou potvrzené jako nové během sběru.")
    if timing["crash"]["during_collection"]:
        warnings.append("V intervalu sběru byly zaznamenány značky pádů; ověř jejich příčinu.")
    if timing["crash"]["unknown"]:
        warnings.append("Čas části značek pádů nelze určit; nejsou potvrzené jako nové během sběru.")
    if report["saturated_property_pids"]:
        warnings.append("Některé procesy vyčerpaly limit diagnostiky properties; seznam je neúplný.")
    if report.get("property_trace_incomplete"):
        warnings.append("Diagnostika properties hlásí vynechané názvy; podrobnosti jsou v property_trace_incomplete.")
    for process in report["init_domain_processes"]:
        if process["pid"] != "1":
            warnings.append("Proces mimo PID 1 běží v init doméně: " + process["name"])
    if not report["required_hal"]:
        warnings.append("Registrace HAL nebyly ověřeny: chybí použitelný výstup lshal.")
    else:
        for name, registered in report["required_hal"].items():
            if not registered:
                warnings.append("V seznamu registrovaných HAL chybí: " + name)
    lines = ["Audit zařízení", f"AVC záznamy: {report['raw_avc_records']}",
             f"Jedinečné auditní události: {report['unique_audit_events']}",
             f"Odlišné kombinace: {report['distinct_signatures']}",
             f"Názvy properties: {report['property_lookup_names']} ({report['property_lookup_records']} diagnostických záznamů)"]
    if "selinux" in report:
        lines.append("SELinux: " + report["selinux"])
    if "properties" in report:
        properties = report["properties"]
        lines.append("Šifrování hlášené systémem: " + properties.get("ro.crypto.state", "unknown") + "/" + properties.get("ro.crypto.type", "unknown"))
    if report["required_hal"]:
        lines.append(f"Registrované požadované HAL: {sum(report['required_hal'].values())}/{len(REQUIRED_HAL)}")
    if baseline is not None:
        delta = report["comparison"]
        lines += [f"Předchozí audit: {delta['previous_raw_avc_records']} záznamů / {delta['previous_distinct_signatures']} kombinací",
                  f"Kombinace: zmizelo {delta['disappeared_signatures']}, přibylo {delta['new_signatures']}",
                  f"Nové objektové případy: {len(delta['new_object_cases'])}; detaily v report.json"]
    for name, label in [("loss", "Ztrátová hlášení"), ("crash", "Značky pádů")]:
        groups = timing[name]
        lines.append(f"{label}: během sběru {len(groups['during_collection'])}, "
                     f"historická {len(groups['historical'])}, čas neurčen {len(groups['unknown'])}")
    if isinstance(report.get("capture_window"), dict) and report["capture_window"].get("time_basis") == "utc-year":
        lines.append("Čas logu: UTC s rokem; hranice sběru jsou v capture_window.")
    if report.get("categories"):
        lines += ["", "Oblasti k posouzení (počty kombinací, nikoliv návrhy allow pravidel):"]
        lines += [f"- {category}: {bucket['signatures']}" for category, bucket in report["categories"].items()]
    if "interface_snapshots" in report:
        snapshots = report["interface_snapshots"]
        lines.append(f"Mapování knihoven služeb: {sum('error' not in item for item in snapshots)}/{len(snapshots)} snapshotů")
    if "codec_library_files" in report:
        migrated = sum(item.get("state") == "migrated" for item in report["codec_library_files"])
        lines.append(f"Knihovny kodeku na disku: {migrated}/2 migrovaných; neprokazuje načtenou verzi.")
    if "display_library_files" in report:
        pinned = sum(item.get("state") == "pinned" for item in report["display_library_files"])
        lines.append(f"Knihovny DP/HWC na disku: {pinned}/2 referenčních; neprokazuje načtené bajty.")
    if "media_property_library_files" in report:
        migrated = sum(item.get("state") == "migrated" for item in report["media_property_library_files"])
        lines.append(f"Knihovny camera/OMX na disku: {migrated}/3 migrovaných; neprokazuje načtené bajty.")
    if "boot_migration_files" in report:
        migrated = sum(item.get("state") == "migrated" for item in report["boot_migration_files"])
        lines.append(f"Boot migrace na disku: {migrated}/{len(BOOT_MIGRATION_FILES)}; neprokazuje načtené bajty ani provedení cesty.")
    if "ecm_publisher_snapshot" in report:
        state = report["ecm_publisher_snapshot"]["ril_service_state"]
        lines.append(f"RIL služba ve snapshotu: {state}; nejde o důkaz živého ECM stavu nebo úspěchu nouzového volání.")
    if report.get("property_routes"):
        operations = sorted({item["operation"] for item in report["property_routes"]})
        lines.append("VT diagnostické cesty: " + ", ".join(operations) +
                     "; vstupy do cest, nikoli úspěch přístupu nebo příčina AVC.")
    if "ril_setter_trace" in report:
        trace = report["ril_setter_trace"]
        lines.append("RIL setter trace: " + trace["status"] +
                     "; jmenných záznamů " + str(len(trace.get("records", []))) +
                     "; nejde o MAC rozhodnutí ani potvrzení úspěšného zápisu.")
    lines += ["", "Upozornění:"]
    lines += ["- " + warning for warning in warnings] or ["- Žádné z kontrolovaných varování."]
    lines += ["", "Nejde o test kvality kamer, zvuku, dotyku ani důkaz připravenosti pro Enforcing.",
              "Historické hlášky nejsou novými událostmi sběru; jejich původní ztráty tím nejsou odstraněny.",
              "Absence nových ztrátových hlášek nezaručuje úplnost logu.",
              "Lookup není automaticky chyba. Názvy souborů a celé cesty mohou tvořit různé případy.",
              "PID je přiřazen podle snapshotu; u ukončených/restartovaných procesů není identita jistá."]
    rendered = "\n".join(lines) + "\n"
    (directory / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    (directory / "report.txt").write_text(rendered)
    print(rendered, end="")
    print("Výstup:", directory.resolve())


def device_utc_time(adb, warnings):
    try:
        value = adb.run("shell", "date -u +%Y-%m-%dT%H:%M:%S", timeout=5).strip()
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S").strftime("%Y-%m-%dT%H:%M:%SZ")
    except (AuditError, ValueError) as error:
        warnings.append("Čas zařízení neověřen; časové zařazení hlášek může zůstat neurčené: " + str(error))
        return None


class Adb:
    def __init__(self, executable, serial):
        self.executable = executable
        self.serial = serial

    def command(self, *arguments):
        return [self.executable] + (["-s", self.serial] if self.serial else []) + list(arguments)

    def run(self, *arguments, timeout=30):
        try:
            result = subprocess.run(self.command(*arguments), capture_output=True, text=True,
                                    errors="replace", timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise AuditError(str(error)) from error
        if result.returncode:
            raise AuditError(" ".join(arguments) + ": " + (result.stderr or result.stdout).strip())
        return result.stdout

    def run_binary(self, *arguments, timeout=30):
        try:
            result = subprocess.run(self.command(*arguments), capture_output=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise AuditError(str(error)) from error
        if result.returncode:
            raise AuditError(" ".join(arguments) + ": " + result.stderr.decode(errors="replace").strip())
        return result.stdout


def snapshot_ril_setters(adb, directory, warnings):
    path = ril_property_trace.SINK_PATH
    try:
        probe = adb.run("shell", "if [ -L " + path + " ]; then echo invalid; elif [ -f " + path +
                        " ]; then echo present; else echo absent; fi", timeout=5).strip()
        if probe == "absent":
            return {"status": "absent", "exhaustive": False,
                    "caveat": "Disabled/older build or unavailable sink; absence does not mean no setter attempts."}
        if probe != "present":
            raise AuditError("Unexpected RIL trace sink probe: " + repr(probe))
        command = "dd if=" + path + " bs=" + str(ril_property_trace.FILE_BYTES + 1) + " count=1 2>/dev/null"
        for attempt in range(3):
            first = adb.run_binary("exec-out", command, timeout=15)
            second = adb.run_binary("exec-out", command, timeout=15)
            (directory / ("ril-setter-trace-" + str(attempt) + "-first.bin")).write_bytes(first)
            (directory / ("ril-setter-trace-" + str(attempt) + "-second.bin")).write_bytes(second)
            try:
                trace = ril_property_trace.parse_pair(first, second)
            except ril_property_trace.UnstableSnapshot:
                continue
            if trace["truncated"]:
                warnings.append("RIL setter trace obsahuje ztráty nebo vyčerpaný rozpočet; viz flags/dropped.")
            (directory / "ril-setter-trace.json").write_text(json.dumps(trace, indent=2) + "\n")
            return trace
        raise AuditError("RIL trace zůstal během všech tří snapshotů nestabilní.")
    except (AuditError, ril_property_trace.TraceError, OSError) as error:
        warnings.append("RIL setter trace neověřen: " + str(error))
        return {"status": "unverified", "exhaustive": False, "error": str(error)}


def snapshot(adb, directory, warnings):
    requests = {
        "processes.txt": "ps -AZ", "hal.txt": "lshal", "selinux.txt": "getenforce",
        "battery.txt": "dumpsys battery", "data-space.txt": "df -k /data",
        "uptime.txt": "cat /proc/uptime", "consoles.txt": "cat /proc/consoles",
        "services.txt": "; ".join("service check " + name for name in SERVICE_NAMES),
        "boot-operation-labels.txt": "ls -lZ /dev/block/mmcblk0p3 /dev/block/mmcblk0p4 /dev/block/mmcblk0p12 /proc/aed/generate-oops",
        "camera-debug-markers.txt": "ls -ldZ /data/vendor/jp /data/vendor/gdepth 2>&1 || true",
        "camera-private-config.txt": "ls -ldZ /data/vendor/camcfg /data/vendor/camcfg/s.json /data/vendor/camcfg/t.json /data/vendor/camcfg/s.h /data/vendor/camcfg/t.h 2>&1 || true",
        "ecm-publisher-status.txt": "getprop init.svc.vendor.ril-daemon-mtk; ls -lZ /dev/__properties__/u:object_r:mt6765_ecm_snapshot_prop:s0 2>&1 || true",
        "modem-boot-status.txt": "; ".join("printf '" + name + "='; getprop " + name for name in (
            "init.svc.vendor.gsm0710muxd", "init.svc.vendor.ril-daemon-mtk",
            "ro.vendor.mtk_md1_support", "ro.vendor.mtk_md2_support", "ro.vendor.mtk_md5_support",
            "vendor.ril.mtk", "vendor.ril.mux.start", "vendor.mtk.md1.status")),
        "properties.txt": "; ".join("printf '" + name + "='; getprop " + name for name in PROPERTY_NAMES),
    }
    for filename, command in requests.items():
        try:
            content = adb.run("shell", command)
        except AuditError as error:
            warnings.append(filename + ": " + str(error))
            content = ""
        (directory / filename).write_text(content)
        if not content:
            try:
                if adb.run("get-state", timeout=5).strip() != "device":
                    warnings.append("Zařízení již není v Androidu; zbývající snapshoty vynechávám.")
                    break
            except AuditError:
                warnings.append("Zařízení je nedostupné; zbývající snapshoty vynechávám.")
                break


def snapshot_library_files(adb, directory, warnings, libraries, filename, expected_state):
    files = []
    try:
        content = adb.run("shell", "sha256sum " + " ".join(libraries), timeout=10)
        (directory / filename).write_text(content)
        hashes = {}
        for line in content.splitlines():
            fields = line.split()
            if (len(fields) != 2 or not re.fullmatch(r"[0-9a-fA-F]{64}", fields[0])
                    or fields[1] not in libraries or fields[1] in hashes):
                raise AuditError("Neplatná nebo duplicitní odpověď sha256sum.")
            hashes[fields[1]] = fields[0].lower()
        if set(hashes) != set(libraries):
            raise AuditError("Chybí hash jedné nebo více knihoven.")
        for path, digest in hashes.items():
            state = next((name for name, expected in libraries[path].items() if digest == expected), "unknown")
            files.append({"path": path, "sha256": digest, "state": state})
            if state != expected_state:
                warnings.append("Knihovna nemá očekávaný stav " + expected_state + ": " + path + " (" + state + ").")
    except AuditError as error:
        warnings.append("Hash knihoven neověřen (" + filename + "): " + str(error))
    return files


def snapshot_codec_libraries(adb, directory, warnings):
    return snapshot_library_files(adb, directory, warnings, CODEC_LIBRARIES,
                                  "codec-library-sha256.txt", "migrated")


def snapshot_media_property_libraries(adb, directory, warnings, snapshots):
    files = snapshot_library_files(adb, directory, warnings, MEDIA_PROPERTY_LIBRARIES,
                                   "media-property-library-sha256.txt", "migrated")
    for item in files:
        item["expected_domain"] = "hal_camera_default" if item["path"].endswith("/libcam.iopipe.so") else "mediacodec"
        item["byte_identity"] = "on_disk_only"
        item["mapped_in_snapshots"] = [
            {"pid": snapshot["pid"], "context": snapshot["context"], "file": snapshot["file"]}
            for snapshot in snapshots
            if not snapshot.get("error") and item["path"] in snapshot.get("mapped_libraries", [])
        ]
    return files


def snapshot_interfaces(adb, directory, warnings):
    process_file = directory / "processes.txt"
    if not process_file.exists():
        warnings.append("Mapování knihoven neověřeno: chybí snapshot procesů.")
        return []
    snapshots = []
    for pid, process in process_map(process_file.read_text()).items():
        if process["context"].split(":")[2] not in INTERFACE_DOMAINS:
            continue
        filename = "interface-maps-" + pid + ".txt"
        context = shlex.quote(process["context"])
        command = (f"context=$(cat /proc/{pid}/attr/current) || exit 1; "
                   f'[ "$context" = {context} ] || exit 2; '
                   'printf "%s\\n" "$context"; '
                   f"readlink /proc/{pid}/exe || exit 3; cat /proc/{pid}/maps")
        item = {"pid": pid, "context": process["context"], "name_at_snapshot": process["name"], "file": filename}
        try:
            content = adb.run("shell", command, timeout=10)
            lines = content.splitlines()
            if len(lines) < 2 or lines[0].strip() != process["context"] or not lines[1].startswith("/"):
                raise AuditError("Neplatná odpověď identity procesu nebo executable path.")
            modules = set()
            for line in lines[2:]:
                fields = line.split(maxsplit=5)
                if len(fields) == 6 and fields[5].startswith("/") and ".so" in fields[5]:
                    modules.add(fields[5])
            if not modules:
                raise AuditError("Snapshot neobsahuje mapované knihovny; neoznačuji jej jako ověřený.")
            (directory / filename).write_text(content)
            item.update({"executable": lines[1], "mapped_libraries": sorted(modules),
                         "property_provider_candidates": sorted(path for path in modules if
                         Path(path[:-10] if path.endswith(" (deleted)") else path).name in {"libc.so", "libcutils.so", "libbase.so"}
                         or Path(path).name.startswith("libshim_"))})
        except AuditError as error:
            item["error"] = str(error)
            warnings.append("Mapování PID " + pid + " neověřeno: " + str(error))
        snapshots.append(item)
    if not snapshots:
        warnings.append("Ve snapshotu nebyla nalezena žádná z cílových native služeb pro mapování knihoven.")
    return snapshots


def collect(args, directory, baseline):
    adb = Adb(args.adb, args.serial)
    devices = Adb(args.adb, None).run("devices")
    ready = [fields[0] for line in devices.splitlines() if len(fields := line.split()) == 2 and fields[1] == "device"]
    if adb.serial:
        if adb.serial not in ready:
            raise AuditError("Vybrané zařízení není dostupné jako autorizované ADB device.")
    elif len(ready) == 1:
        adb.serial = ready[0]
    else:
        raise AuditError("Je potřeba právě jedno autorizované zařízení, nebo --serial.")
    baseline_source = str(args.baseline) if args.baseline else None
    if baseline is None:
        for candidate in sorted(Path("out/device-audits").glob("*/report.json"), reverse=True):
            try:
                previous = load_baseline(candidate)
            except (AuditError, OSError, ValueError, KeyError):
                continue
            collection = previous.get("collection", {})
            if collection.get("serial") == adb.serial and not collection.get("failure") and not collection.get("interrupted"):
                baseline = previous
                baseline_source = str(candidate)
                break
    device = adb.run("shell", "getprop ro.product.device").strip()
    if device != EXPECTED_DEVICE:
        raise AuditError("Neočekávané zařízení: " + repr(device) + "; sběr nebyl spuštěn.")
    if not args.no_root and adb.run("shell", "id -u").strip() != "0":
        adb.run("root")
        adb.run("wait-for-device", timeout=60)
    deadline = time.monotonic() + args.boot_timeout
    while adb.run("shell", "getprop sys.boot_completed").strip() != "1":
        if time.monotonic() >= deadline:
            raise AuditError("Android nedokončil boot; nic nerestartuji. Zkus sběr později.")
        time.sleep(1)
    if adb.run("shell", "getprop ro.product.device").strip() != EXPECTED_DEVICE:
        raise AuditError("Po připojení se změnila identita zařízení.")
    warnings = []
    original_rate = None
    rate_changed = False
    interrupted = False
    failure = None
    logger = None
    interface_snapshots = None
    codec_library_files = None
    display_library_files = None
    media_property_library_files = None
    boot_migration_files = None
    ril_setter_trace = {"status": "not_requested", "exhaustive": False}
    boot_id = adb.run("shell", "cat /proc/sys/kernel/random/boot_id").strip()
    started = time.monotonic()
    capture_window = {"time_basis": "utc-year", "start": None, "end": None,
                      "monotonic_seconds": None, "same_boot_verified": False}
    with (directory / "logcat.txt").open("w") as output, (directory / "logcat-stderr.txt").open("w") as errors:
        try:
            capture_window["start"] = device_utc_time(adb, warnings)
            logger = subprocess.Popen(adb.command("logcat", "-b", "all", "-v", "threadtime", "-v", "year", "-v", "UTC"),
                                      stdout=output, stderr=errors)
            try:
                status = adb.run("shell", "auditctl -s")
                (directory / "audit-status-before.txt").write_text(status)
                match = re.search(r"^rate_limit\s+(\d+)\s*$", status, re.M)
                if match:
                    original_rate = int(match.group(1))
                    if original_rate != 0:
                        rate_changed = True
                        adb.run("shell", "auditctl -r 0")
                else:
                    warnings.append("Neznám původní audit rate limit; ponechávám jej beze změny.")
            except AuditError as error:
                warnings.append("Audit rate limit nelze ověřit/upravit: " + str(error))
            print(f"Sbírám {args.seconds} s; tablet může zůstat v klidu. Ctrl+C bezpečně ukončí sběr.", flush=True)
            snapshot(adb, directory, warnings)
            if args.interfaces:
                interface_snapshots = snapshot_interfaces(adb, directory, warnings)
                codec_library_files = snapshot_codec_libraries(adb, directory, warnings)
                media_property_library_files = snapshot_media_property_libraries(
                    adb, directory, warnings, interface_snapshots)
                boot_migration_files = snapshot_library_files(adb, directory, warnings,
                    BOOT_MIGRATION_FILES, "boot-migration-sha256.txt", "migrated")
                for item in boot_migration_files:
                    item["byte_identity"] = "on_disk_only"
                display_library_files = snapshot_library_files(adb, directory, warnings,
                                                               DISPLAY_LIBRARIES,
                                                               "display-library-sha256.txt", "pinned")
            deadline = time.monotonic() + args.seconds
            while time.monotonic() < deadline:
                if logger.poll() is not None:
                    raise AuditError("Logcat skončil předčasně; viz logcat-stderr.txt.")
                time.sleep(min(0.2, max(0, deadline - time.monotonic())))
            if logger.poll() is not None:
                raise AuditError("Logcat skončil předčasně; viz logcat-stderr.txt.")
            if args.interfaces:
                ril_setter_trace = snapshot_ril_setters(adb, directory, warnings)
        except KeyboardInterrupt:
            interrupted = True
            warnings.append("Sběr byl ukončen uživatelem; report pokrývá jen zachycený interval.")
        except (AuditError, OSError) as error:
            failure = str(error)
            warnings.append("Neúplný sběr: " + failure)
        finally:
            previous_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
            try:
                try:
                    current_boot = adb.run("shell", "cat /proc/sys/kernel/random/boot_id").strip()
                    capture_window["same_boot_verified"] = current_boot == boot_id
                    if current_boot != boot_id:
                        warnings.append("Zařízení mezitím rebootovalo; audit není z jednoho bootu a nepřepisuji limit nového bootu.")
                        failure = failure or "Zařízení během sběru rebootovalo."
                    elif rate_changed:
                        try:
                            adb.run("shell", "auditctl -r " + str(original_rate))
                        except AuditError as error:
                            raise AuditError("Obnova limitu: " + str(error)) from error
                except AuditError as error:
                    if rate_changed:
                        recovery = shlex.join(adb.command("shell", "auditctl -r " + str(original_rate)))
                        warnings.append("OBNOVA AUDIT LIMITU SELHALA: " + str(error) + "; po připojení spusť: " + recovery)
                        failure = failure or "Nepodařilo se obnovit původní audit rate limit."
                    else:
                        warnings.append("Nelze potvrdit stejný boot na konci sběru: " + str(error))
                        failure = failure or "Neověřený konec sběru."
                if logger is not None:
                    if logger.poll() is None:
                        logger.terminate()
                    try:
                        logger.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        logger.kill()
                        logger.wait(timeout=5)
                capture_window["end"] = device_utc_time(adb, warnings)
                capture_window["monotonic_seconds"] = round(time.monotonic() - started, 3)
            finally:
                signal.signal(signal.SIGINT, previous_handler)
    report = analyze((directory / "logcat.txt").read_text(errors="replace"),
                     (directory / "processes.txt").read_text() if (directory / "processes.txt").exists() else "",
                     (directory / "hal.txt").read_text() if (directory / "hal.txt").exists() else "")
    report["capture_window"] = capture_window
    report["ril_setter_trace"] = ril_setter_trace
    (directory / "capture-window.json").write_text(json.dumps(capture_window, indent=2) + "\n")
    report.update({"warnings": warnings, "collection": {"serial": adb.serial, "boot_id": boot_id,
                   "baseline_source": baseline_source,
                   "requested_seconds": args.seconds, "original_audit_rate": original_rate,
                   "elapsed_seconds": round(time.monotonic() - started, 2),
                   "interrupted": interrupted, "failure": failure}})
    if interface_snapshots is not None:
        report["interface_snapshots"] = interface_snapshots
        report["codec_library_files"] = codec_library_files or []
        report["media_property_library_files"] = media_property_library_files or []
        report["boot_migration_files"] = boot_migration_files or []
        report["display_library_files"] = display_library_files or []
    if (directory / "services.txt").exists():
        services = (directory / "services.txt").read_text()
        for name in SERVICE_NAMES:
            if not re.search(r"Service\s+" + re.escape(name) + r":\s+found", services):
                warnings.append("Registrace systémové služby nepotvrzena: " + name)
    if (directory / "ecm-publisher-status.txt").exists():
        status_lines = (directory / "ecm-publisher-status.txt").read_text(errors="replace").splitlines()
        state = status_lines[0].strip() if status_lines and status_lines[0].strip() else "unknown"
        report["ecm_publisher_snapshot"] = {"ril_service_state": state, "live_ecm_state_proven": False}
        selected = any(item.get("path") == "/vendor/lib64/libmtk-ril.so" and item.get("state") == "migrated"
                       for item in report.get("boot_migration_files", []))
        if selected and state != "running":
            warnings.append("Migrovaný RIL není ve snapshotu running (" + state
                            + "); zkontroluj ECM inicializaci a log služby. Nic automaticky nerestartuji.")
    if (directory / "properties.txt").exists():
        properties = dict(line.split("=", 1) for line in (directory / "properties.txt").read_text().splitlines() if "=" in line)
        report["properties"] = properties
        if properties.get("ro.crypto.state") != "encrypted" or properties.get("ro.crypto.type") != "file":
            warnings.append("Očekávané FBE encrypted/file nebylo potvrzeno; nic neformátuj.")
        if properties.get("init.svc.console") != "stopped":
            warnings.append("Služba sériové konzole není hlášena jako stopped.")
    report["selinux"] = (directory / "selinux.txt").read_text().strip() if (directory / "selinux.txt").exists() else "unknown"
    if report["selinux"] not in ["Permissive", "Enforcing"]:
        warnings.append("SELinux stav není ověřený jako Permissive/Enforcing: " + report["selinux"])
    save_report(directory, report, baseline)
    return 2 if failure else (130 if interrupted else 0)


def main():
    parser = argparse.ArgumentParser(description="Bezpečný sběr a offline porovnání auditů TB-X606X.")
    subparsers = parser.add_subparsers(dest="mode", required=True)
    collector = subparsers.add_parser("collect")
    collector.add_argument("--adb", default="adb")
    collector.add_argument("--serial")
    collector.add_argument("--seconds", type=int, default=45)
    collector.add_argument("--boot-timeout", type=int, default=120)
    collector.add_argument("--no-root", action="store_true")
    collector.add_argument("--interfaces", action="store_true", help="Přečíst mapování knihoven cílových native služeb bez čtení jejich paměti.")
    offline = subparsers.add_parser("analyze")
    offline.add_argument("log", type=Path)
    offline.add_argument("--processes", type=Path)
    offline.add_argument("--hal", type=Path)
    offline.add_argument("--capture-window", type=Path, help="Časové hranice z capture-window.json; bez nich jsou staré hlášky časově neurčené.")
    for command in [collector, offline]:
        command.add_argument("--baseline", type=Path)
        command.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.mode == "collect" and (args.seconds < 1 or args.boot_timeout < 1):
        parser.error("Časy musí být alespoň 1 sekunda.")
    try:
        baseline = load_baseline(args.baseline)
        directory = args.output or Path("out/device-audits") / datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        directory.mkdir(parents=True, exist_ok=False)
        if args.mode == "collect":
            return collect(args, directory, baseline)
        report = analyze(args.log.read_text(errors="replace"),
                         args.processes.read_text(errors="replace") if args.processes else "",
                         args.hal.read_text(errors="replace") if args.hal else "")
        report["source_log"] = str(args.log.resolve())
        if args.capture_window:
            report["capture_window"] = json.loads(args.capture_window.read_text())
        save_report(directory, report, baseline)
        return 0
    except (AuditError, OSError, ValueError, KeyError) as error:
        print("Chyba:", error, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
