LOCAL_PATH := $(call my-dir)

lenovo_logger_output := $(OUT_DIR)/lenovo-modem-logger-migration/$(TARGET_PRODUCT)
lenovo_logger_tool := $(HOST_OUT_EXECUTABLES)/lenovo_modem_logger_migration

$(lenovo_logger_output)/ccci_mdinit: PRIVATE_LOGGER_ROOT := $(lenovo_logger_output)
$(lenovo_logger_output)/ccci_mdinit: PRIVATE_LOGGER_TOOL := $(lenovo_logger_tool)
$(lenovo_logger_output)/ccci_mdinit: vendor/lenovo/mt6765-common/proprietary/vendor/bin/ccci_mdinit $(lenovo_logger_tool)
	@mkdir -p $(dir $@)
	$(hide) $(PRIVATE_LOGGER_TOOL) $< --replace-generated --generated-root $(PRIVATE_LOGGER_ROOT) --output $@

lenovo_logger_output :=
lenovo_logger_tool :=
