#!/usr/bin/env python3
"""Generate the reviewed ARM64 MEOW config-path migration; never edit a blob."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import os
import stat

SOURCE_SHA256 = "32fa3f4d9044a72251c2e310c000b038867f1dabd091ac7da67e9f206b7803e8"
OFFSET = 0xb7ce
OLD = b"/sdcard/gles_multi.cfg\0"
NEW = b"/vendor/etc/gles.cfg\0"
OUTPUT_SHA256 = "57c4c58b1cf1b85a4f0c1ae88929343ec5bbda2facc9bd4519070e5abcc00ece"


def migrate(data):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError("unreviewed source SHA256")
    if data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", data, 18)[0] != 183:
        raise ValueError("expected little-endian ARM64 ELF")
    if data.count(OLD) != 1 or data[OFFSET:OFFSET + len(OLD)] != OLD:
        raise ValueError("literal contract mismatch")
    if struct.unpack_from("<4Q", data, 0x1dac70) != (OFFSET, 0x5e2f, 0xead0, 0):
        raise ValueError("config fallback table mismatch")
    replacement = NEW.ljust(len(OLD), b"\0")
    result = data[:OFFSET] + replacement + data[OFFSET + len(OLD):]
    if hashlib.sha256(result).hexdigest() != OUTPUT_SHA256:
        raise ValueError("generated SHA256 mismatch")
    return result


def checked_output(source, output, root):
    # Use caller paths, never __file__: Soong embeds this script in a host zip.
    source, output, root = (Path(os.path.abspath(p)) for p in (source, output, root))
    for path in (source, output, root):
        if any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError("symlink paths are forbidden")
    if root.parent.name != "lenovo-graphics-storage-migration":
        raise ValueError("expected dedicated lenovo-graphics-storage-migration root")
    if output != root / "arm64" / "libGLES_meow.so":
        raise ValueError("output must be the exact root/arm64/libGLES_meow.so path")
    if any(os.path.lexists(p / ".git") for p in (output.parent, *output.parent.parents)):
        raise ValueError("output inside a source Git repository is forbidden")
    if not source.is_file() or source == output:
        raise ValueError("input must be a separate regular file")
    if os.path.lexists(output):
        info = output.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or source.samefile(output)):
            raise ValueError("output must be a regular file without hardlink aliases")
    return source, output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--generated-root", type=Path, required=True)
    args = parser.parse_args()
    try:
        source, output = checked_output(args.input, args.output, args.generated_root)
        original = source.read_bytes()
        result = migrate(original)
        if output.exists():
            if output.read_bytes() != result:
                raise ValueError("refusing to overwrite a different generated file")
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=output.parent, delete=False) as temp:
                temporary = Path(temp.name)
                temp.write(result)
                temp.flush()
                os.fchmod(temp.fileno(), 0o644)
            os.replace(temporary, output)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps({"input_sha256": SOURCE_SHA256,
                      "output_sha256": hashlib.sha256(result).hexdigest(),
                      "offset": hex(OFFSET), "old": OLD[:-1].decode(),
                      "new": NEW[:-1].decode(), "length": len(result)}, sort_keys=True))


if __name__ == "__main__":
    main()
