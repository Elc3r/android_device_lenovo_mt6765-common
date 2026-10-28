# Media-owned property migrations

The selected tools/prepare_media_property_migration.py generator relocates the
camera dump and ARM/ARM64 OMX debug property literals to dedicated vendor names.
It preserves literal allocation length, ELF layout and original parsing/default
semantics. Product mappings choose generated outputs ahead of vendor inheritance.
Input/output identities are enforced by the generator; no property values are
copied from a device. This does not enable dump/debug options by default.
