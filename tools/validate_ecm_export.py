#!/usr/bin/env python3
"""Read-only ELF and init payload checks for the fixed ECM export."""
import hashlib
from pathlib import Path
import shutil
import subprocess

SYMBOLS = ('__system_property_set_ecm_snapshot', '__system_property_initialize_ecm_snapshot')
INIT_MARKERS = (
    b'ECM publisher initialization failed; RIL startup remains blocked',
    b'ECM publisher is not ready; RIL startup remains blocked',
    b'ECM snapshot storage preparation failed',
    b'ECM snapshot is published only by its canonical transaction',
)


def verify_symbols(path):
    readelf = shutil.which('readelf')
    if not readelf:
        raise ValueError('Host readelf is required to check private ECM symbols')
    result = subprocess.run([readelf, '--dyn-syms', '--wide', str(path)],
                            capture_output=True, text=True, check=True, timeout=30)
    identities = {}
    for symbol in SYMBOLS:
        records = [line.split() for line in result.stdout.splitlines()
                   if line.split() and line.split()[-1].split('@')[0] == symbol]
        if (len(records) != 1 or len(records[0]) < 8 or records[0][6] == 'UND'
                or records[0][4] not in {'GLOBAL', 'WEAK'}
                or records[0][-1] != symbol + '@@LIBC_PRIVATE'):
            raise ValueError('Missing/incorrect private ECM symbol: ' + symbol)
        identities[symbol] = records[0][-1]
    return identities


def verify_runtime(read_runtime_file, read_init, directory):
    identities = {}
    for architecture, relative in [('arm', 'lib/bionic/libc.so'), ('arm64', 'lib64/bionic/libc.so')]:
        data = read_runtime_file(relative)
        path = Path(directory) / ('ecm-' + architecture + '-libc.so')
        path.write_bytes(data)
        identities[architecture] = verify_symbols(path)
        identities[architecture]['sha256'] = hashlib.sha256(data).hexdigest()
    init = read_init()
    for marker in INIT_MARKERS:
        if marker not in init:
            raise ValueError('Missing init ECM publisher/gate marker: ' + marker.decode())
    return {'ecm_private_runtime_symbols': identities, 'ecm_init_publisher_and_gate_markers': True}
