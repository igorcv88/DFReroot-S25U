#ifndef STUB_JNI_H
#define STUB_JNI_H
#include <stdint.h>
typedef int32_t jint; typedef uint8_t jboolean; typedef void* jobject; typedef jobject jclass;
typedef jobject jstring; typedef void* jmethodID; typedef const struct JNINativeInterface_* JNIEnv; typedef const struct JNIInvokeInterface_* JavaVM;
#define JNIEXPORT
#define JNICALL
#define JNI_VERSION_1_4 0x00010004
struct JNIInvokeInterface_;
struct JNINativeInterface_ {
  jclass (*FindClass)(JNIEnv*, const char*);
  jmethodID (*GetMethodID)(JNIEnv*, jclass, const char*, const char*);
  jstring (*NewStringUTF)(JNIEnv*, const char*);
  void (*CallVoidMethod)(JNIEnv*, jobject, jmethodID, ...);
  void (*ExceptionClear)(JNIEnv*);
  void (*DeleteLocalRef)(JNIEnv*, jobject);
};
struct JNIInvokeInterface_ { jint (*GetEnv)(JavaVM*, void**, jint); };
#endif
