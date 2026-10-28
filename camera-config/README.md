# Camera optional configuration

Coordinates logical-module and stereo-provider setting/tuning readers and
property-gated writers at `/data/vendor/camcfg/{s.json,t.json,s.h,t.h}`. The
configuration directory is absent by default. Missing configuration follows
compiled defaults; malformed JSON is not assumed to be a safe fallback.
The migration preserves code/unwind bytes and all sixteen reviewed references.
Dedicated named file transitions apply only inside explicitly provisioned storage.
EEPROM/calibration overrides are unchanged. See migrate.py for pinned identities.
