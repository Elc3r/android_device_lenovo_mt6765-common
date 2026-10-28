#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import zipfile


EXPECTED_SHA256 = "ac5bf57b05d791d900589d3786289077ac9ed666eae4af9f6101c734242a38a0"
SERVICE = "android.hardware.keymaster@4.0-service"
VENDOR_BYTES = 838860800
BLOCK_BYTES = 4096


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check_service(content):
    require(hashlib.sha256(content).hexdigest() == EXPECTED_SHA256,
            "Keymaster is not the pinned stock Beanpod executable")
    require(content[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", content, 18)[0] == 183,
            "Expected an ARM64 little-endian ELF")


def check_ota(path, expected_rc, brotli):
    with zipfile.ZipFile(path) as archive, tempfile.TemporaryDirectory(prefix="keymaster-ota-") as temporary:
        require(archive.testzip() is None, "OTA ZIP integrity check failed")
        script = archive.read("META-INF/com/google/android/updater-script").decode()
        require('getprop("ro.product.device") == "achilles6_row_data"' in script,
                "Unexpected OTA device assertion")
        require('"vendor.new.dat.br"' in script, "Expected a full vendor block OTA")
        transfer = archive.read("vendor.transfer.list").decode().splitlines()
        require(len(transfer) >= 4 and transfer[0] == "4", "Expected transfer-list version 4")
        require(transfer[2:4] == ["0", "0"], "Incremental/stashed OTA is not supported")
        commands = []
        new_bytes = 0
        for line in transfer[4:]:
            command, encoded_ranges = line.split()
            require(command in ["new", "zero", "erase"], f"Unsupported OTA command: {command}")
            ranges = [int(value) for value in encoded_ranges.split(",")]
            require(ranges[0] == len(ranges) - 1 and ranges[0] % 2 == 0,
                    "Malformed OTA block ranges")
            for start, end in zip(ranges[1::2], ranges[2::2]):
                require(0 <= start < end <= VENDOR_BYTES // BLOCK_BYTES,
                        "OTA range exceeds the configured vendor partition")
                if command == "new":
                    commands.append((start * BLOCK_BYTES, (end - start) * BLOCK_BYTES))
                    new_bytes += (end - start) * BLOCK_BYTES
        directory = Path(temporary)
        compressed = directory / "vendor.new.dat.br"
        with archive.open("vendor.new.dat.br") as source, compressed.open("wb") as destination:
            shutil.copyfileobj(source, destination)
        decompressed = directory / "vendor.new.dat"
        subprocess.run([brotli, "-d", "-o", str(decompressed), str(compressed)], check=True)
        require(decompressed.stat().st_size == new_bytes, "Unexpected decompressed vendor data size")
        image = directory / "vendor.raw.img"
        with image.open("w+b") as destination, decompressed.open("rb") as source:
            destination.truncate(VENDOR_BYTES)
            for offset, length in commands:
                destination.seek(offset)
                remaining = length
                while remaining:
                    chunk = source.read(min(remaining, 1024 * 1024))
                    require(chunk, "Truncated vendor block data")
                    destination.write(chunk)
                    remaining -= len(chunk)
        for filename, expected in [(f"/bin/hw/{SERVICE}", None),
                                   (f"/etc/init/{SERVICE}.rc", expected_rc)]:
            result = subprocess.run(["debugfs", "-R", f"cat {filename}", str(image)],
                                    check=True, capture_output=True)
            if expected is None:
                check_service(result.stdout)
            else:
                require(result.stdout == expected, "OTA Keymaster init configuration differs from source")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--product-out", type=Path)
    parser.add_argument("--ota", type=Path)
    parser.add_argument("--brotli", default="brotli")
    args = parser.parse_args()
    device = Path(__file__).resolve().parents[1]
    blob = device / "keymaster" / (SERVICE + ".beanpod")
    check_service(blob.read_bytes())
    expected_rc = (device / "keymaster" / (SERVICE + ".rc")).read_bytes()
    require(f"service vendor.keymaster-4-0 /vendor/bin/hw/{SERVICE}".encode() in expected_rc,
            "Unexpected init service path")
    require(b"interface android.hardware.keymaster@4.0::IKeymasterDevice default" in expected_rc,
            "Missing Keymaster HAL interface declaration")
    product = (device / "mt6765.mk").read_text()
    require("    android.hardware.keymaster@4.0-service \\\n" not in product,
            "Software Keymaster is still explicitly packaged")
    require(f"keymaster/{SERVICE}.beanpod:$(TARGET_COPY_OUT_VENDOR)/bin/hw/{SERVICE}" in product,
            "Missing hardware Keymaster copy rule")
    if args.product_out:
        vendor = args.product_out / "vendor"
        check_service((vendor / "bin/hw" / SERVICE).read_bytes())
        require((vendor / "etc/init" / (SERVICE + ".rc")).read_bytes() == expected_rc,
                "Built Keymaster init configuration differs from source")
    if args.ota:
        check_ota(args.ota, expected_rc, args.brotli)
    print(json.dumps({"source_service_sha256": EXPECTED_SHA256,
                      "source_configuration_checked": True,
                      "product_out": str(args.product_out.resolve()) if args.product_out else None,
                      "ota": str(args.ota.resolve()) if args.ota else None,
                      "built_vendor_checked": args.product_out is not None,
                      "ota_vendor_payload_checked": args.ota is not None,
                      "hardware_security_level_verified_on_device": False}, indent=2))


if __name__ == "__main__":
    main()
