# Graphics optional configuration

The selected ARM64 MEOW generator moves the optional `/sdcard/gles_multi.cfg`
probe to `/vendor/etc/gles.cfg`, preserving the original vendor/system fallbacks
and executable bytes. No override file is installed. Source and output identities
are pinned in migrate.py, with bounded generated-output path checks. This removes
one demonstrated user-storage probe, not every possible graphics storage path.
