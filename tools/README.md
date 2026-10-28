# Host tools

Run from the Android source root. Python 3.11+ is recommended for standalone
validators. Build-time migrations use Soong's embedded Python runtime.

- `prepare_*_migration.py`: pinned codec/media/logger/proinfo transformations.
- `validate_keymaster.py`: source/staged/optional actual full-OTA Beanpod checks;
  OTA mode also needs brotli and read-only debugfs.
- `validate_boot_migrations.py --product-out out/target/product/achilles6_row_data`:
  compare expected generated libraries/daemons against installed product files.
- `validate_ecm_export.py`: staged ECM identities.
- `device_audit.py collect --interfaces --serial YOUR_SERIAL`: explicitly uses
  ADB and writes private reports below `out/device-audits`; never commit logs.
- `device_audit.py analyze`, `ril_property_trace.py`, `selinux_inventory.py`:
  offline analysis. Consult CLI help for input/output arguments.

The development updater and frozen plan depend on private historical fixtures.
They remain in the original workspace; their checks were not silently weakened
for export. Use the integration repo's explicit build/verify/install workflow.
