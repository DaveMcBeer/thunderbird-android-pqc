LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := oqs
LOCAL_SRC_FILES := jniLibs/$(TARGET_ARCH_ABI)/liboqs.so
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/include
include $(PREBUILT_SHARED_LIBRARY)

include $(CLEAR_VARS)

LOCAL_MODULE := oqs-jni
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_CFLAGS += -Wall
LOCAL_SRC_FILES := handle.c KEMs.c KeyEncapsulation.c Rand.c Signature.c Sigs.c
LOCAL_LDLIBS := -llog -landroid
LOCAL_SHARED_LIBRARIES := oqs

include $(BUILD_SHARED_LIBRARY)
