# ECM consumer binding

The selected hash-pinned ARM64 libmtk-ril.so literal migration binds the existing
consumer to the matching platform ECM snapshot contract. Use only with the
Bionic/init transaction, bootstrap, readiness and private-symbol patches supplied
by the integration repo. Exact source/output hashes are in migrate.py. Running
RIL, SIM detection and mobile data work in the tested build; the specific
emergency/ECM transition and restart semantics remain untested on hardware.
