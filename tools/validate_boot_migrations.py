#!/usr/bin/env python3
"""Recompute reviewed boot migrations for staged-image and OTA validation.

No device interaction, generated-file replacement, or Android build is performed.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
COMMON = ROOT / 'device/lenovo/mt6765-common'
VENDOR = ROOT / 'vendor/lenovo/mt6765-common/proprietary/vendor'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def expected_payloads():
    """Only the reviewed, product-selected transformations belong here."""
    graphics = load('boot_graphics_migration', COMMON / 'graphics-storage/migrate.py')
    original = (VENDOR / 'lib64/egl/libGLES_meow.so').read_bytes()
    result = graphics.migrate(original)
    logger = load('boot_logger_migration', COMMON / 'tools/prepare_modem_logger_migration.py')
    modem, evidence = logger.prepare((VENDOR / 'bin/ccci_mdinit').read_bytes())
    proinfo = load('boot_proinfo_migration', COMMON / 'tools/prepare_proinfo_probe_migration.py')
    nvram = proinfo.transform((VENDOR / 'bin/nvram_daemon').read_bytes())
    camera = load('camera_storage_migration', COMMON / 'camera-storage/migrate.py')
    stereo = camera.migrate((VENDOR / 'lib64/libstereoinfoaccessor_vsdof.so').read_bytes())
    config = load('camera_config_migration', COMMON / 'camera-config/migrate.py')
    configurations = {'lib64/' + name: config.migrate((VENDOR / 'lib64' / name).read_bytes(), name)
                      for name in config.LIBRARIES}
    ecm = load('ecm_consumer_migration', COMMON / 'ecm-consumer/migrate.py')
    configurations['lib64/libmtk-ril.so'] = ecm.migrate((VENDOR / 'lib64/libmtk-ril.so').read_bytes())
    return {**configurations, 'lib64/egl/libGLES_meow.so': result,
            'bin/ccci_mdinit': modem, 'bin/nvram_daemon': nvram,
            'lib64/libstereoinfoaccessor_vsdof.so': stereo}


def verify_reader(read_file):
    """read_file takes a vendor-relative path and returns payload bytes."""
    identities = {}
    for relative, expected in expected_payloads().items():
        actual = read_file(relative)
        if actual != expected:
            raise ValueError('Packaged boot migration differs: ' + relative)
        identities['vendor/' + relative] = hashlib.sha256(actual).hexdigest()
    return identities


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--product-out', type=Path, required=True)
    args = parser.parse_args()
    identities = verify_reader(lambda name: (args.product_out / 'vendor' / name).read_bytes())
    print(json.dumps(identities, indent=2))


if __name__ == '__main__':
    main()
