#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
import device_audit


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_optional(path):
    return path.read_text(errors="replace") if path.exists() else ""


def add_entry(inventory, source, name, context, capture):
    entry = inventory.setdefault((source, name), {"source": source, "name": name,
                                                 "contexts": set(), "captures": set()})
    entry["contexts"].add(context)
    entry["captures"].add(capture)


def publish(inventory):
    return [{**entry, "contexts": sorted(entry["contexts"]), "captures": sorted(entry["captures"])}
            for key, entry in sorted(inventory.items())]


def inventory_captures(captures):
    summaries = []
    reports = {}
    setters = {}
    lookups = {}
    for directory in sorted(captures.iterdir()):
        log = directory / "logcat.txt"
        original_path = directory / "report.json"
        if not directory.is_dir() or not log.is_file() or not original_path.is_file():
            continue
        original = json.loads(original_path.read_text())
        processes = directory / "processes.txt"
        hal = directory / "hal.txt"
        window = directory / "capture-window.json"
        inputs = [path for path in [log, original_path, processes, hal, window] if path.is_file()]
        before = {str(path.resolve()): digest(path) for path in inputs}
        report = device_audit.analyze(log.read_text(errors="replace"),
                                      read_optional(processes), read_optional(hal))
        if window.exists():
            report["capture_window"] = json.loads(window.read_text())
        report["marker_timing"] = {
            "loss": device_audit.marker_timing(report["loss_markers"], report.get("capture_window")),
            "crash": device_audit.marker_timing(report["crash_markers"], report.get("capture_window")),
        }
        report["original_snapshot_metadata"] = {
            key: original[key] for key in ["collection", "selinux", "properties", "warnings",
                                           "interface_snapshots", "codec_library_files", "display_library_files"]
            if key in original
        }
        report["input_sha256"] = before
        after = {str(path.resolve()): digest(path) for path in inputs}
        if before != after:
            raise ValueError("Capture changed during analysis: " + str(directory))
        reports[directory.name] = report
        summaries.append({
            "capture": directory.name,
            "source": str(directory.resolve()),
            "previous_lookup_records": original.get("property_lookup_records"),
            "lookup_records": report["property_lookup_records"],
            "lookup_names": report["property_lookup_names"],
            "raw_avc_records": report["raw_avc_records"],
            "distinct_signatures": report["distinct_signatures"],
            "input_sha256": before,
        })
        for case in report["object_cases"]:
            source, target, kind, command, permissions, object_name = case["key"]
            if kind == "property_service" and "set" in permissions.split() and object_name.startswith("property:"):
                add_entry(setters, source, object_name[len("property:"):], target, directory.name)
        for lookup in report["property_lookups"]:
            process = lookup["process_at_snapshot"]
            source = process["context"] if process else "unattributed"
            add_entry(lookups, source, lookup["name"], lookup["context"], directory.name)
    if not summaries:
        raise ValueError("No completed captures found in " + str(captures))
    return summaries, reports, publish(setters), publish(lookups)


def main():
    parser = argparse.ArgumentParser(description="Offline SELinux inventory; never connects to a device.")
    parser.add_argument("--captures", type=Path, default=Path("out/device-audits"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        summaries, reports, setters, lookups = inventory_captures(args.captures)
        latest = summaries[-1]
        limitations = [
            "Lookups are not setter evidence, denied accesses or proof a property exists.",
            "Lookup source domains come from process snapshots; PID reuse and exited processes remain ambiguous.",
            "Setter names come from explicit AVCs; AVC caching/rate limits mean this is not a complete attempt trace.",
            "Repeated captures of one boot and duplicate log lines are not independent fixes or failures.",
            "Original snapshot warnings/health are preserved as historical metadata, not newly measured.",
            "Missing markers or accesses do not prove a workload ran or that Enforcing is ready.",
        ]
        result = {"schema_version": 1, "offline_only": True, "captures": summaries,
                  "latest_capture": latest["capture"], "setter_avc_inventory": setters,
                  "lookup_inventory_snapshot_attribution": lookups, "limitations": limitations,
                  "analyzer_sha256": digest(Path(device_audit.__file__)),
                  "inventory_tool_sha256": digest(Path(__file__))}
        lines = ["# Offline SELinux inventory", "", "No device commands or ROM builds were run.", "",
                 "Captures: " + str(len(summaries)), "Latest: " + latest["capture"],
                 "Latest property records: {} -> {}".format(latest["previous_lookup_records"], latest["lookup_records"]),
                 "Latest distinct lookup names: " + str(latest["lookup_names"]), "",
                 "## Explicit RIL setter AVC names across captures", ""]
        lines += ["- `" + entry["name"] + "`" for entry in setters if entry["source"] == "u:r:rild:s0"]
        lines += ["", "## Limits", ""] + ["- " + limit for limit in limitations]
        args.output.mkdir(parents=True, exist_ok=False)
        reanalysis = args.output / "reanalysis"
        reanalysis.mkdir()
        for name, report in reports.items():
            (reanalysis / (name + ".json")).write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        (args.output / "inventory.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
        (args.output / "inventory.md").write_text("\n".join(lines) + "\n")
        print("Analyzed {} captures; latest: {} records / {} lookup names".format(
            len(summaries), latest["lookup_records"], latest["lookup_names"]))
        print("Output: " + str(args.output))
        return 0
    except (OSError, ValueError, KeyError) as error:
        print("Error: " + str(error))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
