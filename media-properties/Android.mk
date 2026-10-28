LOCAL_PATH := $(call my-dir)

lenovo_media_output := $(OUT_DIR)/lenovo-media-property-migration/$(TARGET_PRODUCT)
lenovo_media_tool := $(HOST_OUT_EXECUTABLES)/lenovo_media_property_migration
lenovo_media_inputs := vendor/lenovo/mt6765-common/proprietary/vendor
lenovo_media_targets := $(lenovo_media_output)/camera-dump/arm64/libcam.iopipe.so $(lenovo_media_output)/omx-core/arm/libMtkOmxCore.so $(lenovo_media_output)/omx-core/arm64/libMtkOmxCore.so

$(lenovo_media_targets): PRIVATE_MEDIA_ROOT := $(lenovo_media_output)
$(lenovo_media_targets): PRIVATE_MEDIA_TOOL := $(lenovo_media_tool)

$(lenovo_media_output)/camera-dump/arm64/libcam.iopipe.so: $(lenovo_media_inputs)/lib64/libcam.iopipe.so $(lenovo_media_tool)
	@mkdir -p $(dir $@)
	$(hide) $(PRIVATE_MEDIA_TOOL) $< --profile camera-dump --architecture arm64 --output $@ --replace-generated --generated-root $(PRIVATE_MEDIA_ROOT)

$(lenovo_media_output)/omx-core/arm/libMtkOmxCore.so: $(lenovo_media_inputs)/lib/libMtkOmxCore.so $(lenovo_media_tool)
	@mkdir -p $(dir $@)
	$(hide) $(PRIVATE_MEDIA_TOOL) $< --profile omx-core --architecture arm --output $@ --replace-generated --generated-root $(PRIVATE_MEDIA_ROOT)

$(lenovo_media_output)/omx-core/arm64/libMtkOmxCore.so: $(lenovo_media_inputs)/lib64/libMtkOmxCore.so $(lenovo_media_tool)
	@mkdir -p $(dir $@)
	$(hide) $(PRIVATE_MEDIA_TOOL) $< --profile omx-core --architecture arm64 --output $@ --replace-generated --generated-root $(PRIVATE_MEDIA_ROOT)

lenovo_media_output :=
lenovo_media_tool :=
lenovo_media_inputs :=
lenovo_media_targets :=
