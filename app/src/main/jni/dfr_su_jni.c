/*
 * dfr_su_jni.c - marshalling only.
 *
 * Every decision lives in dfr_su_core.c, which is host-tested with the
 * privileged syscalls faked (tools/tests/test_su_core.sh). This file converts
 * strings and builds argv, and must stay that thin: logic that lands here
 * becomes logic no test can reach, which is what AGENTS.md 5 exists to prevent.
 * tools/profile_binding_audit.py asserts its shape for the same reason.
 */
#define _GNU_SOURCE

#include "dfr_su_core.h"

#include <jni.h>
#include <stdlib.h>
#include <string.h>

#define DFR_SU_OUT_CAP 8192
#define DFR_SU_SHELL "/system/bin/sh"

static jobjectArray pack(JNIEnv *env, const struct dfr_su_result *res,
                         const char *out)
{
    char token[160];
    jobjectArray array;
    jclass string_class = (*env)->FindClass(env, "java/lang/String");
    jstring j_token;
    jstring j_out;

    if (!string_class) {
        return NULL;
    }
    dfr_su_status_token(res, token, sizeof(token));
    array = (*env)->NewObjectArray(env, 2, string_class, NULL);
    if (!array) {
        return NULL;
    }
    j_token = (*env)->NewStringUTF(env, token);
    if (!j_token) {
        return NULL;
    }
    (*env)->SetObjectArrayElement(env, array, 0, j_token);
    j_out = (*env)->NewStringUTF(env, out);
    if (!j_out) {
        return NULL;
    }
    (*env)->SetObjectArrayElement(env, array, 1, j_out);
    return array;
}

/*
 * A command's output is whatever the daemon or the shell wrote; it is not
 * guaranteed to be valid UTF-8, and NewStringUTF on invalid input is undefined.
 * Every caller runs this first rather than handing the VM bytes it cannot
 * represent.
 */
static void sanitize(char *s)
{
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;

        if (c == '\n' || c == '\t') {
            continue;
        }
        if (c < 0x20 || c > 0x7e) {
            *s = '?';
        }
    }
}

JNIEXPORT jobjectArray JNICALL
Java_com_polygraphene_df_reroot_RootTransport_nativeRunRootShell(
    JNIEnv *env, jobject thiz, jstring j_comm, jstring j_command,
    jlong timeout_ms, jboolean transport_fix_allowed)
{
    struct dfr_su_result res;
    char out[DFR_SU_OUT_CAP];
    const char *comm;
    const char *command;
    char *argv[4];
    jobjectArray packed;

    (void)thiz;
    if (!j_comm || !j_command) {
        return NULL;
    }
    comm = (*env)->GetStringUTFChars(env, j_comm, NULL);
    command = (*env)->GetStringUTFChars(env, j_command, NULL);
    if (!comm || !command) {
        if (comm) {
            (*env)->ReleaseStringUTFChars(env, j_comm, comm);
        }
        if (command) {
            (*env)->ReleaseStringUTFChars(env, j_command, command);
        }
        return NULL;
    }

    argv[0] = (char *)DFR_SU_SHELL;
    argv[1] = (char *)"-c";
    argv[2] = (char *)command;
    argv[3] = NULL;

    (void)dfr_su_spawn(&dfr_su_real_ops, comm, argv, NULL, (long)timeout_ms,
                       1 /* a hung probe shell is housekeeping */,
                       transport_fix_allowed == JNI_TRUE, out, sizeof(out), &res);
    sanitize(out);
    packed = pack(env, &res, out);

    (*env)->ReleaseStringUTFChars(env, j_comm, comm);
    (*env)->ReleaseStringUTFChars(env, j_command, command);
    return packed;
}

JNIEXPORT jobjectArray JNICALL
Java_com_polygraphene_df_reroot_RootTransport_nativeExecPinnedDaemon(
    JNIEnv *env, jobject thiz, jstring j_comm, jstring j_path,
    jstring j_pinned, jstring j_arg, jlong timeout_ms,
    jboolean transport_fix_allowed)
{
    struct dfr_su_result res;
    char out[DFR_SU_OUT_CAP];
    const char *comm = NULL;
    const char *path = NULL;
    const char *pinned = NULL;
    const char *arg = NULL;
    char *argv[3];
    jobjectArray packed = NULL;

    (void)thiz;
    if (!j_comm || !j_path || !j_pinned || !j_arg) {
        return NULL;
    }
    comm = (*env)->GetStringUTFChars(env, j_comm, NULL);
    path = (*env)->GetStringUTFChars(env, j_path, NULL);
    pinned = (*env)->GetStringUTFChars(env, j_pinned, NULL);
    arg = (*env)->GetStringUTFChars(env, j_arg, NULL);
    if (comm && path && pinned && arg) {
        argv[0] = (char *)path;
        argv[1] = (char *)arg;
        argv[2] = NULL;

        /*
         * kill_on_timeout is 0 here, and that is the whole difference from the
         * probe above: past exec this task IS the pinned daemon carrying out
         * the lifecycle operation, and killing it mid-teardown would be worse
         * than the uncertainty. The timeout is reported as UNDETERMINED, which
         * the receiver keeps apart from a dispatch.
         */
        (void)dfr_su_spawn(&dfr_su_real_ops, comm, argv, pinned,
                           (long)timeout_ms, 0,
                           transport_fix_allowed == JNI_TRUE, out, sizeof(out),
                           &res);
        sanitize(out);
        packed = pack(env, &res, out);
    }

    if (comm) {
        (*env)->ReleaseStringUTFChars(env, j_comm, comm);
    }
    if (path) {
        (*env)->ReleaseStringUTFChars(env, j_path, path);
    }
    if (pinned) {
        (*env)->ReleaseStringUTFChars(env, j_pinned, pinned);
    }
    if (arg) {
        (*env)->ReleaseStringUTFChars(env, j_arg, arg);
    }
    return packed;
}
