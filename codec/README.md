# Codec log property migration

The selected generator in tools/prepare_codec_log_migration.py replaces the
pinned ARM/ARM64 libvcodec_utility.so literal `mtk.vdec.log` with `vendor.vdlog`.
The name length is unchanged. Build rules write to a dedicated OUT_DIR root;
input revisions, ELF architecture and literal offset/uniqueness are checked.
See the generator for exact hashes. The permission contract is in vendor policy.
