LOCAL_PATH := $(call my-dir)
lenovo_ecm_consumer_root := $(OUT_DIR)/lenovo-ecm-consumer-migration/$(TARGET_PRODUCT)
lenovo_ecm_consumer_tool := $(HOST_OUT_EXECUTABLES)/lenovo_ecm_consumer_migration

$(lenovo_ecm_consumer_root)/arm64/libmtk-ril.so: PRIVATE_ECM_ROOT := $(lenovo_ecm_consumer_root)
$(lenovo_ecm_consumer_root)/arm64/libmtk-ril.so: PRIVATE_ECM_TOOL := $(lenovo_ecm_consumer_tool)
$(lenovo_ecm_consumer_root)/arm64/libmtk-ril.so: vendor/lenovo/mt6765-common/proprietary/vendor/lib64/libmtk-ril.so $(lenovo_ecm_consumer_tool)
	@mkdir -p $(dir $@)
	$(hide) $(PRIVATE_ECM_TOOL) $< --output $@ --generated-root $(PRIVATE_ECM_ROOT)

lenovo_ecm_consumer_root :=
lenovo_ecm_consumer_tool :=
