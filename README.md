# Lenovo MT6765 common tree — LineageOS 19.1

Unofficial Android 12L / API 32 port, tested on the **Lenovo TB-X606X LTE**,
product `achilles6_row_data`. Other MT6765 products are not covered by these
hardware results. Based on `lenovo-mt6765/android_device_lenovo_mt6765-common`,
commit `1f36ce47ffbfb55838b282f46ce0c46e6f1b0a28`.

## Dependencies

- This repository → `device/lenovo/mt6765-common`
- `android_device_lenovo_achilles6_row_data` → `device/lenovo/achilles6_row_data`
- `proprietary_vendor_lenovo_mt6765-common` → `vendor/lenovo/mt6765-common`
- `lenovo-tb-x606x`: pinned manifests, platform patches, blob preparation and
  build/installation documentation.

The device tree alone is insufficient. Use the matching Bionic/init ECM
interface, logging and build compatibility patches from the integration repo.

## Tested behavior

Android cold-boots with SELinux **Enforcing**. The tested userdebug build
retains standard `su` and `backuptool` permissive domains. Hardware Beanpod
Keymaster matches recovery; FBE and PIN-protected TWRP decryption work with
the matching ROM/recovery combination.

Wi-Fi, touch, sound, both cameras, Bluetooth, rotation, sleep/wake, charging
and reboot were exercised on one TB-X606X. GSM/RIL stay running with a SIM and
MD1 configuration is published correctly. SIM detection and mobile data were
confirmed after the narrow NA77/GSM recovery repair. Calls, SMS, VoLTE, emergency
calls, roaming and BIP remain unverified. App sandbox denials and optional DSU
metadata probes remain intentionally restricted.

## Changes and build

Dedicated vendor domains, path labels, exact property ownership and narrow
access rules replace the permissive configuration. Hash-pinned generated blob
transformations relocate optional camera/graphics overrides, retire a redundant
proinfo probe and unavailable modem logger, and use the matching ECM contract.
Generated outputs stay under `OUT_DIR`; original vendor inputs are preserved.

The Beanpod executable is **not stored in this source snapshot**. Prepare the
five pinned local binary inputs with integration `scripts/prepare_blobs.py`.
That repository's `blobs.json` contains extraction paths and hashes.
See [keymaster/README.md](keymaster/README.md) for backend compatibility.

After following integration `docs/BUILD_LINEAGE.md`:

```bash
source build/envsetup.sh
lunch lineage_achilles6_row_data-userdebug
m -j4 bacon
```

Output: `out/target/product/achilles6_row_data/lineage-19.1-*-UNOFFICIAL-achilles6_row_data.zip`.
Vendor SPL is `2022-05-05`; platform baseline reports `2025-03-05`. The old
4.9.190+ prebuilt kernel/vendor binaries are not updated by SELinux Enforcing.
Do not change security-patch dates merely to remove Android warnings.

These are unofficial development sources, not official LineageOS support or
a security certification. Keep upstream history and copyright notices.
See [tools/README.md](tools/README.md) and [sepolicy/README.md](sepolicy/README.md).
Private logs, identifiers, update journals and abandoned experiments are excluded.
