LOCAL_PATH := $(call my-dir)

lenovo_camera_storage_output := $(OUT_DIR)/lenovo-camera-storage-migration/$(TARGET_PRODUCT)
lenovo_camera_storage_tool := $(HOST_OUT_EXECUTABLES)/lenovo_camera_storage_migration

$(lenovo_camera_storage_output)/arm64/libstereoinfoaccessor_vsdof.so: PRIVATE_CAMERA_STORAGE_ROOT := $(lenovo_camera_storage_output)
$(lenovo_camera_storage_output)/arm64/libstereoinfoaccessor_vsdof.so: PRIVATE_CAMERA_STORAGE_TOOL := $(lenovo_camera_storage_tool)
$(lenovo_camera_storage_output)/arm64/libstereoinfoaccessor_vsdof.so: vendor/lenovo/mt6765-common/proprietary/vendor/lib64/libstereoinfoaccessor_vsdof.so $(lenovo_camera_storage_tool)
	@mkdir -p $(dir $@)
	$(hide) $(PRIVATE_CAMERA_STORAGE_TOOL) $< --output $@ --generated-root $(PRIVATE_CAMERA_STORAGE_ROOT)

lenovo_camera_storage_output :=
lenovo_camera_storage_tool :=
