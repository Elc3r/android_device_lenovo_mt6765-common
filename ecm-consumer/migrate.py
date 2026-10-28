#!/usr/bin/env python3
"""Prepare an inactive fixed ECM consumer migration; requires platform publisher."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import tempfile

INPUT_SHA256 = '3bde0c384b74835fc4e1ceafab74fe1afeb98dc6be6b2bf91e14467ffd4a8c47'
OUTPUT_SHA256 = '5c6a0d928859a2f6684999461568cfb2f6d784b5c10010628f6c5bb0e9b7e8c6'
PATCHES = ((0x13ddb3, b'ril.cdma.inecmmode\0', b'sys.radio.ecm_v1\0'),)


def migrate(data):
    if hashlib.sha256(data).hexdigest() != INPUT_SHA256:
        raise ValueError('Unsupported input SHA256')
    if data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', data, 18)[0] != 183:
        raise ValueError('Expected ARM64 little-endian ELF')
    result = bytearray(data)
    for offset, old, new in PATCHES:
        if (len(new) > len(old) or data.count(old) != 1
                or data[offset:offset + len(old)] != old or new in data):
            raise ValueError('Reviewed literal allocation changed')
        result[offset:offset + len(old)] = new.ljust(len(old), b'\0')
    result = bytes(result)
    if hashlib.sha256(result).hexdigest() != OUTPUT_SHA256:
        raise ValueError('Unexpected generated SHA256')
    return result


def checked_paths(source, output, root):
    source, output, root = (Path(os.path.abspath(path)) for path in (source, output, root))
    for path in (source, output, root):
        if any(parent.is_symlink() for parent in (path, *path.parents)):
            raise ValueError('Symlink path components are forbidden')
    if root.parent.name != 'lenovo-ecm-consumer-migration':
        raise ValueError('Expected dedicated generated root')
    if output != root / 'arm64/libmtk-ril.so':
        raise ValueError('Expected exact generated library path')
    if any(os.path.lexists(parent / '.git') for parent in (output.parent, *output.parent.parents)):
        raise ValueError('Output inside source Git repository is forbidden')
    if not source.is_file() or source == output:
        raise ValueError('Input must be a separate regular file')
    if os.path.lexists(output):
        info = output.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or source.samefile(output):
            raise ValueError('Output aliases and special files are forbidden')
    return source, output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--generated-root', type=Path, required=True)
    args = parser.parse_args()
    try:
        source, output = checked_paths(args.input, args.output, args.generated_root)
        result = migrate(source.read_bytes())
        if output.exists() and output.read_bytes() != result:
            raise ValueError('Refusing a different existing output')
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=output.parent, delete=False) as target:
                temporary = Path(target.name)
                target.write(result)
                target.flush()
                os.fchmod(target.fileno(), 0o644)
            os.replace(temporary, output)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps({'input_sha256': INPUT_SHA256,
                      'output_sha256': hashlib.sha256(result).hexdigest(),
                      'size': len(result)}, sort_keys=True))


if __name__ == '__main__':
    main()
