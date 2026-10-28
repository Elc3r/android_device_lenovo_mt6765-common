# Optional modem logger retirement

Product-selected tools/prepare_modem_logger_migration.py retires the unavailable
emdlogger1 selection in both dispatchers through their unsupported state. The
reviewed inline implementation preserves original stack/unwind frames, canary
behavior, other logger choices and modem/mux/RIL/fsd code. Input revision and
output bytes are pinned; generated files remain under OUT_DIR. This is not a
telephony correctness claim or a broad service-control policy workaround.
