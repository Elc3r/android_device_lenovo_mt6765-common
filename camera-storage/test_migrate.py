#!/usr/bin/env python3
"""Host-only byte, path-safety and embedded-generator regression checks."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import zipfile


def target_path(blob, adrp_pc, add_pc):
    adrp = struct.unpack_from('<I', blob, adrp_pc)[0]
    add = struct.unpack_from('<I', blob, add_pc)[0]
    assert adrp & 0x9f000000 == 0x90000000
    assert add & 0xffc00000 == 0x91000000
    register = adrp & 31
    assert (add >> 5) & 31 == register and add & 31 == register
    immediate = ((adrp >> 5) & 0x7ffff) << 2 | ((adrp >> 29) & 3)
    if immediate & (1 << 20):
        immediate -= 1 << 21
    address = (adrp_pc & ~0xfff) + immediate * 4096 + ((add >> 10) & 0xfff)
    return address, blob[address:blob.index(0, address)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    root = Path.cwd()
    script = root / 'device/lenovo/mt6765-common/camera-storage/migrate.py'
    original_path = root / 'vendor/lenovo/mt6765-common/proprietary/vendor/lib64/libstereoinfoaccessor_vsdof.so'
    report = args.report.resolve()
    report.mkdir(parents=True, exist_ok=True)
    spec = importlib.util.spec_from_file_location('camera_migration', script)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    original = original_path.read_bytes()
    candidate = migration.migrate(original)
    checks = {}
    def check(name, value):
        checks[name] = bool(value)
        assert value, name
    allowed = {i for offset, old, _ in migration.PATCHES for i in range(offset, offset + len(old))}
    check('same_file_length', len(original) == len(candidate))
    check('only_two_literal_allocations_change', all(a == b or i in allowed for i, (a, b) in enumerate(zip(original, candidate))))
    check('output_pin', hashlib.sha256(candidate).hexdigest() == migration.OUTPUT_SHA256)
    for off, old, new in migration.PATCHES:
        check('new_literal_' + hex(off), candidate[off:off + len(old)] == new.ljust(len(old), b'\0') and old not in candidate)
    shoff = struct.unpack_from('<Q', original, 40)[0]
    stride, count = struct.unpack_from('<HH', original, 58)
    headers = [struct.unpack_from('<IIQQQQIIQQ', original, shoff + i * stride) for i in range(count)]
    check('all_executable_code_unchanged', all(original[h[4]:h[4] + h[5]] == candidate[h[4]:h[4] + h[5]] for h in headers if h[2] & 4))
    check('relocations_and_init_arrays_unchanged', all(original[h[4]:h[4] + h[5]] == candidate[h[4]:h[4] + h[5]] for h in headers if h[1] in [4, 9, 14]))
    for name, adrp, add, address, old, new in [
        ('dump-marker', 0x50840, 0x50844, 0x2c8f4, b'/sdcard/dumpJps', b'/data/vendor/jp'),
        ('dump-writer', 0x69ec4, 0x69ec8, 0x2c8f4, b'/sdcard/dumpJps', b'/data/vendor/jp'),
        ('dump-writer-packed', 0x69fec, 0x69ff0, 0x2c8f4, b'/sdcard/dumpJps', b'/data/vendor/jp'),
        ('google-parser', 0x52e74, 0x52e78, 0x2c8f4, b'/sdcard/dumpJps', b'/data/vendor/jp'),
        ('segment-parser', 0x55a6c, 0x55a70, 0x2c8f4, b'/sdcard/dumpJps', b'/data/vendor/jp'),
        ('buffer-parser', 0x5709c, 0x570a0, 0x2c8f4, b'/sdcard/dumpJps', b'/data/vendor/jp'),
        ('capture-parser', 0x57ddc, 0x57de0, 0x2c8f4, b'/sdcard/dumpJps', b'/data/vendor/jp'),
        ('config-parser', 0x5e87c, 0x5e880, 0x2c8f4, b'/sdcard/dumpJps', b'/data/vendor/jp'),
        ('depth-parser', 0x63a0c, 0x63a10, 0x2c8f4, b'/sdcard/dumpJps', b'/data/vendor/jp'),
        ('depth-marker', 0x50858, 0x50864, 0x2efd9, b'sdcard/ENABLE_GDEPTH', b'/data/vendor/gdepth'),
    ]:
        check(name + ':original-target', target_path(original, adrp, add) == (address, old))
        check(name + ':new-target', target_path(candidate, adrp, add) == (address, new))
    check('F_OK_cmp_store_opcodes_retained', all(struct.unpack_from('<I', candidate, p)[0] == value for p, value in [
        (0x50848, 0x2a1f03e1), (0x50868, 0x2a1f03e1),
        (0x50854, 0x7100001f), (0x50878, 0x7100001f),
        (0x50860, 0x1a9f17e9), (0x5087c, 0x1a9f17e9),
        (0x5086c, 0x39000109), (0x50884, 0x39000109)]))
    for name, bad in [('corrupt', original[:-1] + bytes([original[-1] ^ 1])), ('truncated', original[:-1]), ('extended', original + b'0'), ('already-migrated', candidate)]:
        try:
            migration.migrate(bad)
        except ValueError:
            check('reject-' + name, True)
        else:
            raise AssertionError('accepted ' + name)
    with tempfile.TemporaryDirectory(dir=report) as temporary:
        directory = Path(temporary)
        source = directory / 'input.so'
        source.write_bytes(original)
        archive = directory / 'generator'
        with archive.open('wb') as target:
            target.write(('#!' + sys.executable + '\n').encode())
        stub = (root / 'build/soong/python/scripts/main.py').read_text().replace('ENTRY_POINT', 'migrate')
        with zipfile.ZipFile(archive, 'a') as package:
            package.writestr('__main__.py', stub)
            package.writestr('migrate.py', script.read_bytes())
        archive.chmod(0o755)
        for context, launcher in [('source', [sys.executable, str(script)]), ('embedded', [str(archive)])]:
            parent = directory / context
            generated = parent / 'custom-out/lenovo-camera-storage-migration/product'
            output = generated / 'arm64/libstereoinfoaccessor_vsdof.so'
            def run(src=source, out=output, gen=generated):
                return subprocess.run(launcher + [str(src), '--output', str(out), '--generated-root', str(gen)], capture_output=True, timeout=10).returncode
            check(context + ':generate', run() == 0 and output.read_bytes() == candidate)
            check(context + ':mode', stat.S_IMODE(output.stat().st_mode) == 0o644)
            inode = output.stat().st_ino
            check(context + ':atomic-repeat', run() == 0 and output.stat().st_ino != inode)
            output.write_bytes(b'foreign')
            check(context + ':reject-foreign', run() != 0 and output.read_bytes() == b'foreign')
            output.unlink()
            check(context + ':reject-source', run(out=source) != 0 and source.read_bytes() == original)
            check(context + ':reject-outside-root', run(out=directory / 'outside.so') != 0)
            check(context + ':reject-other-basename', run(out=generated / 'arm64/other.so') != 0)
            output.symlink_to(source)
            check(context + ':reject-symlink', run() != 0)
            output.unlink()
            os.link(source, output)
            check(context + ':reject-hardlink', run() != 0)
            output.unlink()
            for kind in ['directory', 'file', 'dangling']:
                marker = parent / '.git'
                if kind == 'directory':
                    marker.mkdir()
                elif kind == 'file':
                    marker.write_text('gitdir: elsewhere')
                else:
                    marker.symlink_to(parent / 'missing')
                check(context + ':reject-git-' + kind, run() != 0 and not output.exists())
                marker.rmdir() if kind == 'directory' else marker.unlink()
            check(context + ':input-preserved', source.read_bytes() == original)
    (report / 'generator-results.json').write_text(json.dumps({'checks': checks, 'passed': all(checks.values()),
        'output_sha256': migration.OUTPUT_SHA256, 'scope': 'host-only, no ARM execution or device access'}, indent=2) + '\n')
    print(str(len(checks)) + ' checks passed')


if __name__ == '__main__':
    main()
