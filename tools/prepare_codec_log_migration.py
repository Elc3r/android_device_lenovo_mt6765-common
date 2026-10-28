#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile


OLD_NAME = b"mtk.vdec.log\0"
NEW_NAME = b"vendor.vdlog\0"
INPUTS = {
    "7bea798d69d332b5f4286777fc3ecb3dcbdf38867f50013fc2676f71e4bc6d02": {
        "architecture": "arm", "elf_class": 1, "machine": 40, "offset": 0x5D1F,
    },
    "6565dc7b017121fa9883379bd974625cf7d662401f5fb3aeee48bc482b8b63b0": {
        "architecture": "arm64", "elf_class": 2, "machine": 183, "offset": 0x68CF,
    },
}


def prepare(data):
    digest = hashlib.sha256(data).hexdigest()
    identity = INPUTS.get(digest)
    if identity is None:
        raise ValueError("Unsupported input SHA256; refusing to guess a blob revision.")
    if (data[:4] != b"\x7fELF" or data[4] != identity["elf_class"] or data[5] != 1
            or int.from_bytes(data[18:20], "little") != identity["machine"]):
        raise ValueError("ELF architecture does not match the pinned input.")
    offset = identity["offset"]
    if len(OLD_NAME) != len(NEW_NAME):
        raise ValueError("The migration must preserve the literal's byte length.")
    if data.count(OLD_NAME) != 1 or data[offset:offset + len(OLD_NAME)] != OLD_NAME:
        raise ValueError("The reviewed property literal is not unique or moved.")
    migrated = data[:offset] + NEW_NAME + data[offset + len(OLD_NAME):]
    evidence = {
        "architecture": identity["architecture"],
        "input_sha256": digest,
        "output_sha256": hashlib.sha256(migrated).hexdigest(),
        "literal_offset": offset,
        "literal_size": len(OLD_NAME),
        "old_property": OLD_NAME[:-1].decode(),
        "new_property": NEW_NAME[:-1].decode(),
        "installed": False,
        "scope": "Prepared bytes only; this tool never installs or flashes them.",
    }
    return migrated, evidence


def write_candidate(input_path, output_path, data, generated_root=None, architecture=None):
    if input_path.resolve() == output_path.resolve():
        raise ValueError("Refusing to overwrite the input blob.")
    if output_path.exists() and input_path.samefile(output_path):
        raise ValueError("Refusing to overwrite a hard link to the input blob.")
    if generated_root is None:
        with output_path.open("xb") as destination:
            destination.write(data)
        return
    root = generated_root.resolve()
    resolved_output = output_path.resolve()
    try:
        resolved_output.relative_to(root)
    except ValueError as error:
        raise ValueError("Generated output escapes its declared build directory.") from error
    if resolved_output != root / architecture / "libvcodec_utility.so":
        raise ValueError("Generated output does not match the architecture-specific build path.")
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(dir=output_path.parent, prefix=output_path.name + ".", delete=False) as destination:
            temporary_path = Path(destination.name)
            destination.write(data)
            destination.flush()
            os.fchmod(destination.fileno(), 0o644)
        os.replace(temporary_path, output_path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def main():
    parser = argparse.ArgumentParser(description="Prepare a hash-pinned codec log-property migration; never installs it.")
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, help="New candidate file; omitted means validate/report only.")
    parser.add_argument("--architecture", choices=["arm", "arm64"], help="Require the expected input architecture.")
    parser.add_argument("--replace-generated", action="store_true", help="Atomically replace a build-owned output, never the input.")
    parser.add_argument("--generated-root", type=Path, help="Build-owned migration root; required with --replace-generated.")
    args = parser.parse_args()
    if args.replace_generated and (args.output is None or args.generated_root is None):
        parser.error("--replace-generated requires --output and --generated-root")
    if args.generated_root is not None and not args.replace_generated:
        parser.error("--generated-root requires --replace-generated")
    try:
        migrated, evidence = prepare(args.input.read_bytes())
        if args.architecture is not None and evidence["architecture"] != args.architecture:
            raise ValueError("Input architecture does not match the requested build output.")
        if args.output is not None:
            write_candidate(args.input, args.output, migrated,
                            args.generated_root if args.replace_generated else None,
                            evidence["architecture"])
            evidence["candidate_file"] = str(args.output)
    except (OSError, ValueError) as error:
        print("Error:", error, file=sys.stderr)
        return 2
    print(json.dumps(evidence, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
