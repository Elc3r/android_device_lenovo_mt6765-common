LOCAL_PATH := $(call my-dir)

lenovo_graphics_output := $(OUT_DIR)/lenovo-graphics-storage-migration/$(TARGET_PRODUCT)
lenovo_graphics_tool := $(HOST_OUT_EXECUTABLES)/lenovo_graphics_storage_migration

$(lenovo_graphics_output)/arm64/libGLES_meow.so: PRIVATE_GRAPHICS_ROOT := $(lenovo_graphics_output)
$(lenovo_graphics_output)/arm64/libGLES_meow.so: PRIVATE_GRAPHICS_TOOL := $(lenovo_graphics_tool)
$(lenovo_graphics_output)/arm64/libGLES_meow.so: vendor/lenovo/mt6765-common/proprietary/vendor/lib64/egl/libGLES_meow.so $(lenovo_graphics_tool)
	@mkdir -p $(dir $@)
	$(hide) $(PRIVATE_GRAPHICS_TOOL) $< --output $@ --generated-root $(PRIVATE_GRAPHICS_ROOT)

lenovo_graphics_output :=
lenovo_graphics_tool :=
