#!/usr/bin/env python3
"""Retire the pinned metadata-only proinfo worker; generate bytes, never install."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import sys

INPUT_SHA256 = '9d61663f1310a11e1eaf4da28a592c0d1be6c5b6a6776940a506ad984c3d1fa3'
R1_SHA256 = '92157804874834ab20d07963af4ddce2d78502a04f21b27fe7574644a3321eba'
OUTPUT_SHA256 = '41d32484e1a8ec35cfc1d88814d6736a15b6290e3dfd385b4bfcfbf48b0075a8'
OFFSET = 0x36FC
AFTER = bytes.fromhex('00207047')
OLD_EXIDX = bytes.fromhex('0c350000b0ab0680')
NEW_EXIDX = bytes.fromhex('0c350000b0b0b080')
OLD_DEBUG_SHA256 = 'e2d2c14cfdc14469dceac7efc8f522c99c39e5f38105619550997854f6faa1e9'
NEW_DEBUG_SHA256 = 'd9cb28d6faee4a52a2d94ca90fadff5ad4e7cc5938da41820ec0fcca74ce051e'
# Exact reviewed XZ allocation, embedded to avoid host compressor/version drift.
NEW_DEBUG = base64.b64decode(
    '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'
)
PATCHES = ((0x1F0, OLD_EXIDX, NEW_EXIDX),
           (OFFSET, bytes.fromhex('f0b587b0'), AFTER))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def transform(blob):
    if sha(blob) != INPUT_SHA256:
        raise ValueError('Unsupported nvram_daemon SHA256')
    if blob[0x6050:0x6054] != bytes.fromhex('fd360000'):
        raise ValueError('Unexpected worker table entry')
    if sha(blob[0x73FE:0x7C6A]) != OLD_DEBUG_SHA256:
        raise ValueError('Unexpected compressed debug metadata')
    changed = bytearray(blob)
    for offset, old, new in PATCHES:
        if blob[offset:offset + len(old)] != old or len(old) != len(new):
            raise ValueError('Unexpected reviewed allocation')
        changed[offset:offset + len(old)] = new
    changed[0x73FE:0x7C6A] = NEW_DEBUG
    if len(changed) != len(blob) or sha(changed) != OUTPUT_SHA256:
        raise ValueError('Generated output SHA256 mismatch')
    return bytes(changed)


def absolute(path):
    # Do not resolve symlinks away before checking them.
    return Path(os.path.abspath(path))


def directory(path, *, create=False, output=False):
    """Walk with NOFOLLOW dirfds; reject symlink ancestors and source outputs."""
    path = absolute(path)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        parts = path.parts[1:]
        for index in range(len(parts) + 1):
            if output:
                try:
                    os.stat('.git', dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise ValueError('Output has a .git ancestor (including files/symlinks)')
                # Android's multi-repository source root is not itself a git repo.
                try:
                    os.stat('.repo', dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    if index == len(parts) or parts[index] != 'out':
                        raise ValueError('Output inside Android sources is forbidden; use out/')
            if index == len(parts):
                return fd
            name = parts[index]
            try:
                next_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(name, 0o755, dir_fd=fd)
                next_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
    except BaseException:
        os.close(fd)
        raise


def read_input(path):
    path = absolute(path)
    parent = directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, 'rb') as stream:
            identity = os.fstat(stream.fileno())
            if not stat.S_ISREG(identity.st_mode) or identity.st_nlink != 1:
                raise ValueError('Input must be a regular file with one link')
            return stream.read(), identity
    finally:
        os.close(parent)


def write_candidate(input_path, output_path, data, identity, generated_root=None):
    output = absolute(output_path)
    if output == absolute(input_path):
        raise ValueError('Refusing to overwrite input')
    if generated_root is not None:
        root = absolute(generated_root)
        if root.parent.name != 'lenovo-proinfo-probe-migration' or output != root / 'nvram_daemon':
            raise ValueError('Replacement requires exact dedicated generated-root/nvram_daemon')
    parent = directory(output.parent, create=True, output=True)
    temporary = '.nvram_daemon.' + secrets.token_hex(16)
    try:
        try:
            existing = os.stat(output.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if (existing.st_dev, existing.st_ino) == (identity.st_dev, identity.st_ino):
                raise ValueError('Refusing input hardlink')
            if not stat.S_ISREG(existing.st_mode) or existing.st_nlink != 1:
                raise ValueError('Output must not be a symlink, hardlink or special file')
            if generated_root is None:
                raise FileExistsError('Output already exists; exclusive creation is the default')
            old_fd = os.open(output.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
            with os.fdopen(old_fd, 'rb') as old:
                if sha(old.read()) != OUTPUT_SHA256:
                    raise ValueError('Replacement target is not the pinned generated output')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), 0o755)
            os.fsync(stream.fileno())
        if generated_root is None:
            # Atomic publish without overwriting even if a target appears meanwhile.
            os.link(temporary, output.name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
        else:
            os.replace(temporary, output.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass
        os.close(parent)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--replace-generated', action='store_true')
    parser.add_argument('--generated-root', type=Path)
    args = parser.parse_args()
    if args.replace_generated != (args.generated_root is not None) or (args.replace_generated and args.output is None):
        parser.error('--replace-generated requires --generated-root and --output together')
    try:
        original, identity = read_input(args.input)
        changed = transform(original)
        if args.output is not None:
            write_candidate(args.input, args.output, changed, identity, args.generated_root)
    except (OSError, ValueError) as error:
        print('Error:', error, file=sys.stderr)
        return 2
    print(json.dumps({'input_sha256': INPUT_SHA256, 'r1_sha256': R1_SHA256,
                      'output_sha256': OUTPUT_SHA256, 'size': len(changed),
                      'code_range': [0x36FC, 0x3700], 'exidx_word_range': [0x1F4, 0x1F8],
                      'debug_allocation': [0x73FE, 0x7C6A], 'installed': False}, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
