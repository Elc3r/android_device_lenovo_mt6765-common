#!/usr/bin/env python3
"""Offline regression checks. Run from workspace root; no Android build tools."""
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, default=Path.cwd())
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    report = args.report.resolve()
    report.mkdir(parents=True, exist_ok=True)
    script = workspace / 'device/lenovo/mt6765-common/graphics-storage/migrate.py'
    source = workspace / 'vendor/lenovo/mt6765-common/proprietary/vendor/lib64/egl/libGLES_meow.so'
    spec = importlib.util.spec_from_file_location('migration', script)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    original = source.read_bytes()
    generated = m.migrate(original)
    checks = {}
    def check(name, value):
        checks[name] = bool(value)
        if not value:
            raise AssertionError(name)
    def rejects(data):
        try:
            m.migrate(data)
        except ValueError:
            return True
        return False
    check('only_reviewed_literal_slot_changed', len(original) == len(generated) and original[:m.OFFSET] == generated[:m.OFFSET] and original[m.OFFSET+len(m.OLD):] == generated[m.OFFSET+len(m.OLD):])
    # Read ELF section headers rather than assume an executable address interval.
    shoff = struct.unpack_from('<Q', original, 40)[0]
    entsize, count = struct.unpack_from('<HH', original, 58)
    sections = [struct.unpack_from('<IIQQQQIIQQ', original, shoff+i*entsize) for i in range(count)]
    check('all_executable_bytes_unchanged', all(original[s[4]:s[4]+s[5]] == generated[s[4]:s[4]+s[5]] for s in sections if s[2] & 4))
    check('relocations_unchanged', all(original[s[4]:s[4]+s[5]] == generated[s[4]:s[4]+s[5]] for s in sections if s[1] in (4, 9, 19, 0x60000001, 0x60000002, 0x6fffff00)))
    slot_sections = [s for s in sections if s[4] <= m.OFFSET and m.OFFSET+len(m.OLD) <= s[4]+s[5]]
    check('literal_in_allocated_nonwritable_nonexecutable_section', len(slot_sections) == 1 and slot_sections[0][2] & 2 and not slot_sections[0][2] & 5)
    check('fallback_table_unchanged', struct.unpack_from('<4Q', generated, 0x1dac70) == (m.OFFSET, 0x5e2f, 0xead0, 0))
    check('vendor_system_fallback_strings_unchanged', all(generated[a:generated.index(0,a)+1] == value for a, value in [(0x5e2f,b'/vendor/etc/gles_multi.cfg\0'), (0xead0,b'/system/etc/gles_multi.cfg\0')]))
    check('optional_override_migrated', m.OLD not in generated and generated[m.OFFSET:m.OFFSET+len(m.OLD)] == m.NEW.ljust(len(m.OLD), b'\0'))
    check('reject_modified_input', rejects(original[:100]+bytes([original[100]^1])+original[101:]))
    check('reject_migrated_source', rejects(generated))
    check('pinned_output', hashlib.sha256(generated).hexdigest() == m.OUTPUT_SHA256)
    with tempfile.TemporaryDirectory(dir=report) as td:
        t = Path(td)
        host = t / 'host/bin/lenovo_graphics_storage_migration'
        host.parent.mkdir(parents=True)
        # Soong's main.py uses this runpy invocation inside its embedded zip.
        stub = (workspace / 'build/soong/python/scripts/main.py').read_text().replace('ENTRY_POINT', 'migrate')
        with host.open('wb') as stream:
            stream.write(('#!' + sys.executable + '\n').encode())
        with zipfile.ZipFile(host, 'a') as archive:
            archive.writestr('__main__.py', stub)
            archive.writestr('migrate.py', script.read_bytes())
        host.chmod(0o755)
        for context, command in [('source', [sys.executable, str(script)]), ('embedded', [str(host)])]:
            prefix = context + ':'
            root = t / context / 'custom-out/lenovo-graphics-storage-migration/product'
            dest = root / 'arm64/libGLES_meow.so'
            def run(dst=dest, gen=root, src=source):
                return subprocess.run(command+[str(src), '--output', str(dst), '--generated-root', str(gen)], cwd=t, capture_output=True).returncode
            check(prefix+'generate', run() == 0 and dest.read_bytes() == generated)
            check(prefix+'mode_0644', stat.S_IMODE(dest.stat().st_mode) == 0o644)
            dest.chmod(0o600)
            inode = dest.stat().st_ino
            check(prefix+'repeat_identical', run() == 0 and dest.read_bytes() == generated)
            check(prefix+'atomic_replace_and_mode', dest.stat().st_ino != inode and stat.S_IMODE(dest.stat().st_mode) == 0o644)
            dest.write_bytes(b'foreign data')
            check(prefix+'reject_different_output', run() != 0 and dest.read_bytes() == b'foreign data')
            dest.unlink()
            check(prefix+'reject_source_overwrite', run(source, source.parent) != 0)
            dest.write_bytes(original)
            check(prefix+'reject_source_at_exact_output_path', run(src=dest) != 0 and dest.read_bytes() == original)
            dest.unlink()
            check(prefix+'reject_outside_root', run(t/'outside.so') != 0)
            check(prefix+'reject_wrong_filename', run(root/'arm64/other.so') != 0)
            check(prefix+'reject_wrong_architecture', run(root/'arm/libGLES_meow.so') != 0)
            arbitrary = t/context/'arbitrary'
            check(prefix+'reject_arbitrary_root', run(arbitrary/'arm64/libGLES_meow.so', arbitrary) != 0 and not arbitrary.exists())
            migrated = t/context/'migrated.so'
            migrated.write_bytes(generated)
            check(prefix+'reject_migrated_cli_input', run(src=migrated) != 0 and not dest.exists())
            for target in (source, t/'nonexistent'):
                dest.symlink_to(target)
                check(prefix+'reject_symlink_'+target.name, run() != 0 and dest.is_symlink())
                dest.unlink()
            os.link(source, dest)
            check(prefix+'reject_input_hardlink', run() != 0 and dest.read_bytes() == original)
            dest.unlink()
            dest.write_bytes(generated)
            alias = t/context/'alias.so'
            os.link(dest, alias)
            check(prefix+'reject_generated_hardlink', run() != 0 and alias.read_bytes() == generated)
            dest.unlink()
            alias.unlink()
            parent_link = t/context/'linked-out'
            parent_link.symlink_to(root.parent, target_is_directory=True)
            check(prefix+'reject_parent_symlink', run(parent_link/'product/arm64/libGLES_meow.so', parent_link/'product') != 0)
            input_link = t/context/'input-link'
            input_link.symlink_to(source)
            check(prefix+'reject_input_symlink', run(src=input_link) != 0)
            for marker in ('directory', 'file', 'dangling'):
                repo = t/context/marker
                repo.mkdir()
                dotgit = repo/'.git'
                if marker == 'directory':
                    dotgit.mkdir()
                elif marker == 'file':
                    dotgit.write_text('gitdir: unavailable\n')
                else:
                    dotgit.symlink_to(repo/'missing')
                gen = repo/'lenovo-graphics-storage-migration/product'
                check(prefix+'reject_git_'+marker, run(gen/'arm64/libGLES_meow.so', gen) != 0 and not gen.exists())
            # Git marker below the declared root must also be rejected.
            (dest.parent/'.git').symlink_to(t/'missing')
            check(prefix+'reject_nested_git', run() != 0 and not dest.exists())
            (dest.parent/'.git').unlink()
            dest.mkdir()
            check(prefix+'reject_directory_output', run() != 0 and dest.is_dir())
            dest.rmdir()
            fifo = dest
            os.mkfifo(fifo)
            check(prefix+'reject_fifo_output', run() != 0 and stat.S_ISFIFO(fifo.stat().st_mode))
            fifo.unlink()
        fixture = t/'recipe.mk'
        fixture.write_text('my-dir = ' + str(script.parent) + '\nhide :=\ninclude '+str(script.parent/'Android.mk')+'\n')
        for label, outdir in [('absolute', t/'make-out'), ('relative', report.relative_to(workspace)/t.name/'relative-out')]:
            dest = outdir/'lenovo-graphics-storage-migration/review_product/arm64/libGLES_meow.so'
            result = subprocess.run(['make', '--no-print-directory', '-f', str(fixture), 'OUT_DIR='+str(outdir), 'TARGET_PRODUCT=review_product', 'HOST_OUT_EXECUTABLES='+str(host.parent), str(dest)], cwd=workspace, capture_output=True, text=True)
            check('gnu_make_recipe_'+label, result.returncode == 0 and (workspace/dest).read_bytes() == generated)
    check('input_unchanged', hashlib.sha256(source.read_bytes()).hexdigest() == m.SOURCE_SHA256)
    check('existing_product_copy_matches_source', (workspace/'out/target/product/achilles6_row_data/vendor/lib64/egl/libGLES_meow.so').read_bytes() == original)
    result = {'passed': all(checks.values()), 'count': len(checks), 'checks': checks, 'input_sha256': m.SOURCE_SHA256, 'output_sha256': m.OUTPUT_SHA256, 'scope': 'offline source and simulated Soong embedded zip; GNU make with mocked host tool, no Android build'}
    (report/'validation.json').write_text(json.dumps(result, indent=2)+'\n')
    print(f'{len(checks)}/{len(checks)} passed')


if __name__ == '__main__':
    main()
