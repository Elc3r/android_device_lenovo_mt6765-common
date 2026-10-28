#!/usr/bin/env python3
"""Move coordinated optional stereo config readers and exports to private data."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import tempfile

LIBRARIES = {
    'libmtkcam.logicalmodule.so': (
        'a7efe5e255a08bcd0b530ba3f4a13089800e3758ccceab51a68548f93030ef6a',
        'c6e41ab7f6a38ce8f9c37c3620b4cffa6438cc6f20a065c95f2c0b58d1149ce0',
        ((0x16a4f, b'/sdcard/stereo_setting.json\0', b'/data/vendor/camcfg/s.json\0'),)),
    'libfeature.stereo.provider.so': (
        '5cc82117be98e1849e267f19d093d121445d425f40b8af63c0546621ef3bfefd',
        '47f6041f4e482eb67c86c711c6b8dc68b2e53fbdaefb41a2a1df426f4332733e',
        ((0x26b68, b'/sdcard/stereo_setting.json\0', b'/data/vendor/camcfg/s.json\0'),
         (0x27089, b'/sdcard/stereo_tuning.json\0', b'/data/vendor/camcfg/t.json\0'),
         (0x2aa74, b'/sdcard/camera_custom_stereo_setting.h\0', b'/data/vendor/camcfg/s.h\0'),
         (0x2c4fc, b'/sdcard/camera_custom_stereo_tuning.h\0', b'/data/vendor/camcfg/t.h\0'))),
}


def migrate(data, name):
    input_sha256, output_sha256, patches = LIBRARIES[name]
    if hashlib.sha256(data).hexdigest() != input_sha256:
        raise ValueError('Unsupported input SHA256')
    if data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', data, 18)[0] != 183:
        raise ValueError('Expected ARM64 little-endian ELF')
    result = bytearray(data)
    for offset, old, new in patches:
        if (len(new) > len(old) or data.count(old) != 1
                or data[offset:offset + len(old)] != old or new in data):
            raise ValueError('Reviewed literal allocation changed')
        result[offset:offset + len(old)] = new.ljust(len(old), b'\0')
    result = bytes(result)
    if hashlib.sha256(result).hexdigest() != output_sha256:
        raise ValueError('Unexpected generated SHA256')
    return result


def checked_paths(source, output, root):
    source, output, root = (Path(os.path.abspath(path)) for path in (source, output, root))
    for path in (source, output, root):
        if any(parent.is_symlink() for parent in (path, *path.parents)):
            raise ValueError('Symlink path components are forbidden')
    if root.parent.name != 'lenovo-camera-config-migration':
        raise ValueError('Expected dedicated generated root')
    if source.name not in LIBRARIES or output != root / 'arm64' / source.name:
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
        result = migrate(source.read_bytes(), source.name)
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
    print(json.dumps({'input_sha256': LIBRARIES[source.name][0],
                      'output_sha256': hashlib.sha256(result).hexdigest(),
                      'size': len(result)}, sort_keys=True))


if __name__ == '__main__':
    main()
