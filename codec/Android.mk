LOCAL_PATH := $(call my-dir)

lenovo_codec_output := $(OUT_DIR)/lenovo-codec-migration/$(TARGET_PRODUCT)
lenovo_codec_tool := $(HOST_OUT_EXECUTABLES)/lenovo_codec_log_migration
lenovo_codec_inputs := vendor/lenovo/mt6765-common/proprietary/vendor

$(lenovo_codec_output)/arm/libvcodec_utility.so $(lenovo_codec_output)/arm64/libvcodec_utility.so: PRIVATE_CODEC_ROOT := $(lenovo_codec_output)

$(lenovo_codec_output)/arm/libvcodec_utility.so: PRIVATE_CODEC_TOOL := $(lenovo_codec_tool)
$(lenovo_codec_output)/arm/libvcodec_utility.so: $(lenovo_codec_inputs)/lib/libvcodec_utility.so $(lenovo_codec_tool)
	@mkdir -p $(dir $@)
	$(hide) $(PRIVATE_CODEC_TOOL) $< --architecture arm --output $@ --replace-generated --generated-root $(PRIVATE_CODEC_ROOT)

$(lenovo_codec_output)/arm64/libvcodec_utility.so: PRIVATE_CODEC_TOOL := $(lenovo_codec_tool)
$(lenovo_codec_output)/arm64/libvcodec_utility.so: $(lenovo_codec_inputs)/lib64/libvcodec_utility.so $(lenovo_codec_tool)
	@mkdir -p $(dir $@)
	$(hide) $(PRIVATE_CODEC_TOOL) $< --architecture arm64 --output $@ --replace-generated --generated-root $(PRIVATE_CODEC_ROOT)

lenovo_codec_output :=
lenovo_codec_tool :=
lenovo_codec_inputs :=
