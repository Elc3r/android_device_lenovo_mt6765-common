LOCAL_PATH := $(call my-dir)

lenovo_proinfo_output := $(OUT_DIR)/lenovo-proinfo-probe-migration/$(TARGET_PRODUCT)
lenovo_proinfo_tool := $(HOST_OUT_EXECUTABLES)/lenovo_proinfo_probe_migration

$(lenovo_proinfo_output)/nvram_daemon: PRIVATE_PROINFO_ROOT := $(lenovo_proinfo_output)
$(lenovo_proinfo_output)/nvram_daemon: PRIVATE_PROINFO_TOOL := $(lenovo_proinfo_tool)
$(lenovo_proinfo_output)/nvram_daemon: vendor/lenovo/mt6765-common/proprietary/vendor/bin/nvram_daemon $(lenovo_proinfo_tool)
	@mkdir -p $(dir $@)
	$(hide) $(PRIVATE_PROINFO_TOOL) $< --replace-generated --generated-root $(PRIVATE_PROINFO_ROOT) --output $@

lenovo_proinfo_output :=
lenovo_proinfo_tool :=
