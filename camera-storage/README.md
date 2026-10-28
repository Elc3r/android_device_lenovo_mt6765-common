# Camera dump marker storage

The selected migration moves two constructor-time opt-in marker probes and the
shared dump path into `/data/vendor/camera_dump/`. All ten reviewed references
are covered by the literal rewrite. Markers remain absent by default; existing
failure/default behavior and dump gates are preserved. Dedicated policy controls
private storage; no app/user-storage grant or calibration conversion is added.
Exact input/output identities and output guards are in migrate.py.
