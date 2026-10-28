LOCAL_PATH := $(call my-dir)

lenovo_camera_config_root := $(OUT_DIR)/lenovo-camera-config-migration/$(TARGET_PRODUCT)
lenovo_camera_config_tool := $(HOST_OUT_EXECUTABLES)/lenovo_camera_config_migration
lenovo_camera_config_outputs := $(addprefix $(lenovo_camera_config_root)/arm64/,libmtkcam.logicalmodule.so libfeature.stereo.provider.so)

$(lenovo_camera_config_outputs): PRIVATE_CAMERA_CONFIG_ROOT := $(lenovo_camera_config_root)
$(lenovo_camera_config_outputs): PRIVATE_CAMERA_CONFIG_TOOL := $(lenovo_camera_config_tool)
$(lenovo_camera_config_outputs): $(lenovo_camera_config_root)/arm64/%.so: vendor/lenovo/mt6765-common/proprietary/vendor/lib64/%.so $(lenovo_camera_config_tool)
	@mkdir -p $(dir $@)
	$(hide) $(PRIVATE_CAMERA_CONFIG_TOOL) $< --output $@ --generated-root $(PRIVATE_CAMERA_CONFIG_ROOT)

lenovo_camera_config_root :=
lenovo_camera_config_tool :=
lenovo_camera_config_outputs :=
