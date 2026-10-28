# Redundant proinfo boot probe retirement

Product-selected tools/prepare_proinfo_probe_migration.py replaces the redundant
metadata/open/close worker with a leaf return. The recovered worker does not
read/write records or perform repair/default generation. Both ARM exidx and
compressed DWARF metadata are adjusted for the new leaf. No raw proinfo permission
is added. Input/output identities and generated-output guards are in the tool.
