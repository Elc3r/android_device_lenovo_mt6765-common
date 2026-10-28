#!/usr/bin/env python3
"""Host-only safety, shared reader/writer and generated-tool checks."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
VENDOR = ROOT / 'vendor/lenovo/mt6765-common/proprietary/vendor/lib64'
spec = importlib.util.spec_from_file_location('camera_config', HERE / 'migrate.py')
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)

# Actual readers and writers, independently decoded from the pinned originals.
REFERENCES = {
    'libmtkcam.logicalmodule.so': [(0x42fd4, 0x42fd8), (0x42fec, 0x42ff0)],
    'libfeature.stereo.provider.so': [
        (0x4b83c, 0x4b840), (0x4b854, 0x4b858), (0x4c0ac, 0x4c0b0),
        (0x4c0c4, 0x4c0c8), (0x4c8e0, 0x4c8e4), (0x4c8f4, 0x4c8fc),
        (0x98fc4, 0x98fc8), (0x98fdc, 0x98fe0), (0x997b4, 0x997b8),
        (0x997cc, 0x997d0), (0x99fe8, 0x99fec), (0x99ffc, 0x9a004),
        (0x4c944, 0x4c94c), (0x9a04c, 0x9a054)],
}


def resolve(blob, a, d):
    adrp, add = struct.unpack_from('<I', blob, a)[0], struct.unpack_from('<I', blob, d)[0]
    assert adrp & 0x9f000000 == 0x90000000 and add & 0xffc00000 == 0x91000000
    assert adrp & 31 == (add >> 5) & 31
    immediate = ((adrp >> 5) & 0x7ffff) << 2 | (adrp >> 29) & 3
    if immediate & (1 << 20):
        immediate -= 1 << 21
    return (a & ~4095) + immediate * 4096 + ((add >> 10) & 4095)


def main():
    checks = {}
    def check(name, condition):
        assert condition, name
        checks[name] = True
    with tempfile.TemporaryDirectory(prefix='camera-config-test-') as temp:
        temporary = Path(temp)
        archive = temporary / 'embedded-tool'
        archive.write_bytes(('#!' + sys.executable + '\n').encode())
        stub = (ROOT / 'build/soong/python/scripts/main.py').read_text().replace('ENTRY_POINT', 'migrate')
        with zipfile.ZipFile(archive, 'a') as package:
            package.writestr('__main__.py', stub)
            package.writestr('migrate.py', (HERE / 'migrate.py').read_bytes())
        archive.chmod(0o755)
        for name, (input_hash, output_hash, patches) in migration.LIBRARIES.items():
            original = (VENDOR / name).read_bytes()
            candidate = migration.migrate(original, name)
            check(name + ':pins', hashlib.sha256(original).hexdigest() == input_hash
                  and hashlib.sha256(candidate).hexdigest() == output_hash)
            allowed = {i for off, old, _ in patches for i in range(off, off + len(old))}
            check(name + ':literal-only', len(original) == len(candidate)
                  and all(x == y or i in allowed for i, (x, y) in enumerate(zip(original, candidate))))
            for adrp, add in REFERENCES[name]:
                offset = resolve(original, adrp, add)
                entry = next(p for p in patches if p[0] == offset)
                check(name + ':ref-' + hex(add), resolve(candidate, adrp, add) == offset
                      and candidate[offset:candidate.index(0, offset)] == entry[2].rstrip(b'\0'))
            for suffix, blob in [('modified', original + b'x'), ('short', original[:-1]), ('migrated', candidate)]:
                try:
                    migration.migrate(blob, name)
                except ValueError:
                    check(name + ':reject-' + suffix, True)
                else:
                    raise AssertionError(suffix)
            source = temporary / 'sources' / name
            source.parent.mkdir(exist_ok=True)
            source.write_bytes(original)
            for mode, launcher in [('source', [sys.executable, str(HERE / 'migrate.py')]), ('embedded', [str(archive)])]:
                prefix = name + ':' + mode + ':'
                parent = temporary / name / mode
                root = parent / 'out/lenovo-camera-config-migration/custom-product'
                output = root / 'arm64' / name
                def run(out=output, generated=root, src=source):
                    return subprocess.run(launcher + [str(src), '--output', str(out),
                        '--generated-root', str(generated)], capture_output=True, timeout=15).returncode
                check(prefix + 'generate', run() == 0 and output.read_bytes() == candidate)
                check(prefix + 'repeat', run() == 0 and output.stat().st_mode & 0o777 == 0o644)
                output.write_bytes(b'foreign')
                check(prefix + 'foreign', run() != 0 and output.read_bytes() == b'foreign')
                output.unlink()
                check(prefix + 'source', run(out=source) != 0)
                other = next(n for n in migration.LIBRARIES if n != name)
                check(prefix + 'other-architecture-output', run(out=root / 'arm64' / other) != 0)
                check(prefix + 'outside', run(out=temporary / 'outside.so') != 0)
                output.symlink_to(source)
                check(prefix + 'symlink', run() != 0)
                output.unlink()
                os.link(source, output)
                check(prefix + 'hardlink', run() != 0)
                output.unlink()
                marker = parent / '.git'
                marker.symlink_to(parent / 'missing')
                check(prefix + 'dangling-git', run() != 0)
                marker.unlink()
                check(prefix + 'input-preserved', source.read_bytes() == original)
    print(json.dumps({'passed': len(checks), 'checks': checks,
                      'scope': 'host only; no Android or device execution'}, indent=2))


if __name__ == '__main__':
    main()
