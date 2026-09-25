#ifndef STUB_ALOG_H
#define STUB_ALOG_H
enum { ANDROID_LOG_DEBUG=3, ANDROID_LOG_INFO=4, ANDROID_LOG_WARN=5, ANDROID_LOG_ERROR=6 };
int __android_log_print(int, const char*, const char*, ...);
#endif
