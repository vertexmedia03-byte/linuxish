#define _POSIX_C_SOURCE 200809L
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#endif
#include "asbestos/profile.h"
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#if defined(__APPLE__)
#include <dlfcn.h>
#endif
#if defined(ISH_PROFILE) && defined(__APPLE__) && \
    (defined(__aarch64__) || defined(__arm64__))
#define ISH_PROFILE_HOST_PC_SAMPLER 1
#include <sys/time.h>
#include <ucontext.h>
extern __thread volatile sig_atomic_t in_jit;
#else
#define ISH_PROFILE_HOST_PC_SAMPLER 0
#endif
#ifdef ISH_JIT
#include "asbestos/guest-arm64/jit.h"
#endif

#define ISH_PROFILE_SYSCALL_MAX 512
#define ISH_PROFILE_SYSCALL_TOP 8
#define ISH_PROFILE_GUEST_PC_BUCKETS 4096
#define ISH_PROFILE_GUEST_PC_PROBES 16
#define ISH_PROFILE_GUEST_PC_SHIFT 8
#define ISH_PROFILE_HOST_PC_BUCKETS 4096
#define ISH_PROFILE_HOST_PC_PROBES 16
#define ISH_PROFILE_HOST_PC_SHIFT 8

_Atomic unsigned char ish_profile_enabled;

static _Atomic uint64_t prof_dispatch_ticks;
static _Atomic uint64_t prof_guest_ticks;
static _Atomic uint64_t prof_guest_blocks;
static _Atomic uint64_t prof_guest_insns;
static _Atomic uint64_t prof_guest_cpu_sample_ns;
static _Atomic uint64_t prof_guest_cpu_samples;
static _Atomic uint64_t prof_guest_cpu_dropped_samples;
static struct {
    _Atomic uint64_t pc_bucket;
    _Atomic uint64_t sample_ns;
    _Atomic uint64_t samples;
} prof_guest_pc[ISH_PROFILE_GUEST_PC_BUCKETS];
static struct {
    _Atomic uint64_t pc_bucket;
    _Atomic uint64_t samples;
} prof_host_pc[ISH_PROFILE_HOST_PC_BUCKETS];
static _Atomic uint64_t prof_host_pc_translated_samples;
static _Atomic uint64_t prof_host_pc_native_samples;
static _Atomic uint64_t prof_host_pc_dropped_samples;
static _Atomic uint64_t prof_gadget_ticks;
static _Atomic uint64_t prof_gadget_calls;
static _Atomic uint64_t prof_tlb_ticks;
static _Atomic uint64_t prof_tlb_misses;
static _Atomic uint64_t prof_syscall_ticks;
static _Atomic uint64_t prof_syscall_calls;
static _Atomic uint64_t prof_syscall_by_num[ISH_PROFILE_SYSCALL_MAX];
static _Atomic uint64_t prof_syscall_ticks_by_num[ISH_PROFILE_SYSCALL_MAX];
static _Atomic uint64_t prof_syscall_cpu_ns;
static _Atomic uint64_t prof_syscall_cpu_samples;
static _Atomic uint64_t prof_syscall_cpu_ns_by_num[ISH_PROFILE_SYSCALL_MAX];
static _Atomic uint64_t prof_jit_decode_ticks;
static _Atomic uint64_t prof_jit_translate_ticks;
static int prof_host_sampler_errno;
#if ISH_PROFILE_HOST_PC_SAMPLER
static bool prof_host_sampler_active;
static bool prof_host_sampler_installed;

static void profile_host_pc_signal(int sig, siginfo_t *info, void *context) {
    (void) sig;
    (void) info;
    if (!ish_profile_active() || !in_jit)
        return;
    const ucontext_t *uc = context;
    uintptr_t pc = (uintptr_t) uc->uc_mcontext->__ss.__pc;
    bool translated = false;
#ifdef ISH_JIT
    translated = jit_host_pc_is_translated(pc);
#endif
    ish_profile_record_host_pc(pc, translated);
}
#endif

bool ish_profile_active(void) {
    return atomic_load_explicit(&ish_profile_enabled, memory_order_relaxed) != 0;
}

uint64_t ish_profile_ticks(void) {
#if defined(__aarch64__)
    uint64_t ticks;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(ticks));
    return ticks;
#else
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    return (uint64_t) ts.tv_sec * 1000000000 + (uint64_t) ts.tv_nsec;
#endif
}

uint64_t ish_profile_ticks_per_second(void) {
#if defined(__aarch64__)
    uint64_t frequency;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(frequency));
    return frequency;
#else
    return 1000000000;
#endif
}

bool ish_profile_thread_cpu_time(uint64_t *nanoseconds) {
#if defined(CLOCK_THREAD_CPUTIME_ID)
    struct timespec ts;
    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts) != 0)
        return false;
    *nanoseconds = (uint64_t) ts.tv_sec * 1000000000 + (uint64_t) ts.tv_nsec;
    return true;
#else
    (void) nanoseconds;
    return false;
#endif
}

int ish_profile_host_sampler_start(void) {
#if ISH_PROFILE_HOST_PC_SAMPLER
    prof_host_sampler_errno = 0;
    if (prof_host_sampler_active)
        return 0;
    if (!atomic_is_lock_free(&prof_host_pc[0].pc_bucket)) {
        prof_host_sampler_errno = ENOTSUP;
        return -1;
    }

    struct itimerval previous_timer;
    if (getitimer(ITIMER_PROF, &previous_timer) != 0) {
        prof_host_sampler_errno = errno;
        return -1;
    }
    if (previous_timer.it_value.tv_sec || previous_timer.it_value.tv_usec ||
        previous_timer.it_interval.tv_sec || previous_timer.it_interval.tv_usec) {
        prof_host_sampler_errno = EBUSY;
        return -1;
    }

    struct sigaction previous_action;
    if (sigaction(SIGPROF, NULL, &previous_action) != 0) {
        prof_host_sampler_errno = errno;
        return -1;
    }
    bool our_handler = (previous_action.sa_flags & SA_SIGINFO) &&
                       previous_action.sa_sigaction == profile_host_pc_signal;
    if (prof_host_sampler_installed && !our_handler) {
        prof_host_sampler_errno = EBUSY;
        return -1;
    }
    if (!prof_host_sampler_installed && previous_action.sa_handler != SIG_DFL) {
        prof_host_sampler_errno = EBUSY;
        return -1;
    }
    if (!prof_host_sampler_installed) {
        struct sigaction action = {0};
        action.sa_sigaction = profile_host_pc_signal;
        action.sa_flags = SA_SIGINFO | SA_RESTART;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGPROF, &action, NULL) != 0) {
            prof_host_sampler_errno = errno;
            return -1;
        }
        // Keep the handler installed so a pending timer signal can't hit SIG_DFL
        // after stop disarms the interval timer.
        prof_host_sampler_installed = true;
    }

    struct itimerval timer = {0};
    timer.it_value.tv_usec = 1000;
    timer.it_interval.tv_usec = 1000;
    if (setitimer(ITIMER_PROF, &timer, NULL) != 0) {
        prof_host_sampler_errno = errno;
        return -1;
    }
    prof_host_sampler_active = true;
    prof_host_sampler_errno = 0;
    return 0;
#else
    return 0;
#endif
}

int ish_profile_host_sampler_stop(void) {
#if ISH_PROFILE_HOST_PC_SAMPLER
    if (!prof_host_sampler_active)
        return 0;
    struct itimerval timer = {0};
    if (setitimer(ITIMER_PROF, &timer, NULL) != 0) {
        prof_host_sampler_errno = errno;
        return -1;
    }
    prof_host_sampler_active = false;
    prof_host_sampler_errno = 0;
    return 0;
#else
    return 0;
#endif
}

void ish_profile_reset(void) {
    atomic_store_explicit(&prof_dispatch_ticks, 0, memory_order_relaxed);
    atomic_store_explicit(&prof_guest_ticks, 0, memory_order_relaxed);
    atomic_store_explicit(&prof_guest_blocks, 0, memory_order_relaxed);
    atomic_store_explicit(&prof_guest_insns, 0, memory_order_relaxed);
    atomic_store_explicit(&prof_guest_cpu_sample_ns, 0, memory_order_relaxed);
    atomic_store_explicit(&prof_guest_cpu_samples, 0, memory_order_relaxed);
    atomic_store_explicit(&prof_guest_cpu_dropped_samples, 0, memory_order_relaxed);
    for (unsigned i = 0; i < ISH_PROFILE_GUEST_PC_BUCKETS; i++) {
        atomic_store_explicit(&prof_guest_pc[i].pc_bucket, 0, memory_order_relaxed);
        atomic_store_explicit(&prof_guest_pc[i].sample_ns, 0, memory_order_relaxed);
        atomic_store_explicit(&prof_guest_pc[i].samples, 0, memory_order_relaxed);
    }
    for (unsigned i = 0; i < ISH_PROFILE_HOST_PC_BUCKETS; i++) {
        atomic_store_explicit(&prof_host_pc[i].pc_bucket, 0, memory_order_relaxed);
        atomic_store_explicit(&prof_host_pc[i].samples, 0, memory_order_relaxed);
    }
    atomic_store_explicit(&prof_host_pc_translated_samples, 0, memory_order_relaxed);
    atomic_store_explicit(&prof_host_pc_native_samples, 0, memory_order_relaxed);
    atomic_store_explicit(&prof_host_pc_dropped_samples, 0, memory_order_relaxed);
    atomic_store_explicit(&prof_gadget_ticks, 0, memory_order_relaxed);
    atomic_store_explicit(&prof_gadget_calls, 0, memory_order_relaxed);
    atomic_store_explicit(&prof_tlb_ticks, 0, memory_order_relaxed);
    atomic_store_explicit(&prof_tlb_misses, 0, memory_order_relaxed);
    atomic_store_explicit(&prof_syscall_ticks, 0, memory_order_relaxed);
    atomic_store_explicit(&prof_syscall_calls, 0, memory_order_relaxed);
    atomic_store_explicit(&prof_syscall_cpu_ns, 0, memory_order_relaxed);
    atomic_store_explicit(&prof_syscall_cpu_samples, 0, memory_order_relaxed);
    for (unsigned i = 0; i < ISH_PROFILE_SYSCALL_MAX; i++) {
        atomic_store_explicit(&prof_syscall_by_num[i], 0, memory_order_relaxed);
        atomic_store_explicit(&prof_syscall_ticks_by_num[i], 0, memory_order_relaxed);
        atomic_store_explicit(&prof_syscall_cpu_ns_by_num[i], 0, memory_order_relaxed);
    }
    atomic_store_explicit(&prof_jit_decode_ticks, 0, memory_order_relaxed);
    atomic_store_explicit(&prof_jit_translate_ticks, 0, memory_order_relaxed);
}

void ish_profile_record_host_pc(uintptr_t pc, bool translated) {
    if (translated)
        atomic_fetch_add_explicit(&prof_host_pc_translated_samples, 1, memory_order_relaxed);
    else
        atomic_fetch_add_explicit(&prof_host_pc_native_samples, 1, memory_order_relaxed);

    uint64_t bucket = (uint64_t) pc & ~((UINT64_C(1) << ISH_PROFILE_HOST_PC_SHIFT) - 1);
    if (bucket == 0) {
        atomic_fetch_add_explicit(&prof_host_pc_dropped_samples, 1, memory_order_relaxed);
        return;
    }
    unsigned slot = (unsigned) ((bucket * UINT64_C(11400714819323198485)) >>
                                (64 - 12));
    for (unsigned probe = 0; probe < ISH_PROFILE_HOST_PC_PROBES; probe++) {
        unsigned i = (slot + probe) & (ISH_PROFILE_HOST_PC_BUCKETS - 1);
        uint64_t found = atomic_load_explicit(&prof_host_pc[i].pc_bucket, memory_order_relaxed);
        if (found == bucket ||
            (found == 0 && atomic_compare_exchange_strong_explicit(
                &prof_host_pc[i].pc_bucket, &found, bucket,
                memory_order_relaxed, memory_order_relaxed))) {
            atomic_fetch_add_explicit(&prof_host_pc[i].samples, 1, memory_order_relaxed);
            return;
        }
    }
    atomic_fetch_add_explicit(&prof_host_pc_dropped_samples, 1, memory_order_relaxed);
}

void ish_profile_add_dispatch(uint64_t ticks) {
    atomic_fetch_add_explicit(&prof_dispatch_ticks, ticks, memory_order_relaxed);
}

void ish_profile_add_guest(uint64_t ticks, uint64_t blocks, uint64_t insns,
                           uint64_t gadget_ticks, uint64_t gadget_calls) {
    atomic_fetch_add_explicit(&prof_guest_ticks, ticks, memory_order_relaxed);
    atomic_fetch_add_explicit(&prof_guest_blocks, blocks, memory_order_relaxed);
    atomic_fetch_add_explicit(&prof_guest_insns, insns, memory_order_relaxed);
    atomic_fetch_add_explicit(&prof_gadget_ticks, gadget_ticks, memory_order_relaxed);
    atomic_fetch_add_explicit(&prof_gadget_calls, gadget_calls, memory_order_relaxed);
}

void ish_profile_add_guest_cpu(int module, uint64_t guest_pc, uint64_t file_offset,
                               uint64_t sampled_ns) {
    atomic_fetch_add_explicit(&prof_guest_cpu_sample_ns, sampled_ns, memory_order_relaxed);
    atomic_fetch_add_explicit(&prof_guest_cpu_samples, 1, memory_order_relaxed);
    uint64_t offset_bucket = (file_offset >> ISH_PROFILE_GUEST_PC_SHIFT) + 1;
    uint64_t module_key = module >= 0 && module < 65535 ? (uint64_t) module + 1 : 0;
    if (offset_bucket >= (UINT64_C(1) << 48)) {
        module_key = 0;
        offset_bucket = (guest_pc >> ISH_PROFILE_GUEST_PC_SHIFT) + 1;
    }
    uint64_t key = (module_key << 48) | offset_bucket;
    unsigned slot = (unsigned) ((key * UINT64_C(11400714819323198485)) >>
                                (64 - 12));
    for (unsigned probe = 0; probe < ISH_PROFILE_GUEST_PC_PROBES; probe++) {
        unsigned i = (slot + probe) & (ISH_PROFILE_GUEST_PC_BUCKETS - 1);
        uint64_t found = atomic_load_explicit(&prof_guest_pc[i].pc_bucket, memory_order_relaxed);
        if (found == key ||
            (found == 0 && atomic_compare_exchange_strong_explicit(
                &prof_guest_pc[i].pc_bucket, &found, key,
                memory_order_relaxed, memory_order_relaxed))) {
            atomic_fetch_add_explicit(&prof_guest_pc[i].sample_ns, sampled_ns,
                                      memory_order_relaxed);
            atomic_fetch_add_explicit(&prof_guest_pc[i].samples, 1, memory_order_relaxed);
            return;
        }
    }
    atomic_fetch_add_explicit(&prof_guest_cpu_dropped_samples, 1, memory_order_relaxed);
}

void ish_profile_add_tlb_miss(uint64_t ticks) {
    atomic_fetch_add_explicit(&prof_tlb_ticks, ticks, memory_order_relaxed);
    atomic_fetch_add_explicit(&prof_tlb_misses, 1, memory_order_relaxed);
}

void ish_profile_add_syscall(unsigned syscall_num, uint64_t wall_ticks,
                              uint64_t thread_cpu_ns, bool thread_cpu_available) {
    atomic_fetch_add_explicit(&prof_syscall_ticks, wall_ticks, memory_order_relaxed);
    atomic_fetch_add_explicit(&prof_syscall_calls, 1, memory_order_relaxed);
    if (thread_cpu_available) {
        atomic_fetch_add_explicit(&prof_syscall_cpu_ns, thread_cpu_ns, memory_order_relaxed);
        atomic_fetch_add_explicit(&prof_syscall_cpu_samples, 1, memory_order_relaxed);
    }
    if (syscall_num < ISH_PROFILE_SYSCALL_MAX) {
        atomic_fetch_add_explicit(&prof_syscall_by_num[syscall_num], 1, memory_order_relaxed);
        atomic_fetch_add_explicit(&prof_syscall_ticks_by_num[syscall_num], wall_ticks, memory_order_relaxed);
        if (thread_cpu_available)
            atomic_fetch_add_explicit(&prof_syscall_cpu_ns_by_num[syscall_num], thread_cpu_ns,
                                      memory_order_relaxed);
    }
}

void ish_profile_add_jit_decode(uint64_t ticks) {
    atomic_fetch_add_explicit(&prof_jit_decode_ticks, ticks, memory_order_relaxed);
}

void ish_profile_add_jit_translate(uint64_t ticks) {
    atomic_fetch_add_explicit(&prof_jit_translate_ticks, ticks, memory_order_relaxed);
}

static double ticks_ms(uint64_t ticks, uint64_t frequency) {
    return frequency ? (double) ticks * 1000.0 / (double) frequency : 0;
}

static size_t profile_append(char *buf, size_t size, size_t used, const char *format, ...) {
    if (used >= size - 1)
        return used;
    va_list args;
    va_start(args, format);
    int n = vsnprintf(buf + used, size - used, format, args);
    va_end(args);
    if (n < 0)
        return used;
    return (size_t) n >= size - used ? size - 1 : used + (size_t) n;
}

int ish_profile_control(const char *cmd, size_t len) {
    while (len && (cmd[len - 1] == '\n' || cmd[len - 1] == '\r' || cmd[len - 1] == ' '))
        len--;
    if (len == 5 && !memcmp(cmd, "start", 5)) {
        atomic_store_explicit(&ish_profile_enabled, 0, memory_order_release);
        if (ish_profile_host_sampler_stop() != 0)
            return -1;
        ish_profile_reset();
        if (ish_profile_host_sampler_start() != 0)
            return -1;
        atomic_store_explicit(&ish_profile_enabled, 1, memory_order_release);
        return 0;
    }
    if (len == 4 && !memcmp(cmd, "stop", 4)) {
        atomic_store_explicit(&ish_profile_enabled, 0, memory_order_release);
        return ish_profile_host_sampler_stop();
    }
    if (len == 5 && !memcmp(cmd, "reset", 5)) {
        ish_profile_reset();
        return 0;
    }
    return -1;
}

size_t ish_profile_describe(char *buf, size_t size) {
    if (size == 0)
        return 0;
    uint64_t frequency = ish_profile_ticks_per_second();
    uint64_t guest_ticks = atomic_load_explicit(&prof_guest_ticks, memory_order_relaxed);
    uint64_t gadget_ticks = atomic_load_explicit(&prof_gadget_ticks, memory_order_relaxed);
    uint64_t guest_cpu_sample_ns =
        atomic_load_explicit(&prof_guest_cpu_sample_ns, memory_order_relaxed);
    uint64_t guest_cpu_samples =
        atomic_load_explicit(&prof_guest_cpu_samples, memory_order_relaxed);
    struct {
        uint64_t pc_bucket;
        uint64_t sample_ns;
        uint64_t samples;
    } top_guest_pc[ISH_PROFILE_SYSCALL_TOP] = {};
    struct {
        uint64_t pc_bucket;
        uint64_t samples;
    } top_host_pc[ISH_PROFILE_SYSCALL_TOP] = {};
    struct {
        unsigned syscall_num;
        uint64_t calls;
        uint64_t cpu_ns;
        uint64_t wall_ticks;
    } top[ISH_PROFILE_SYSCALL_TOP] = {};
    for (unsigned syscall_num = 0; syscall_num < ISH_PROFILE_SYSCALL_MAX; syscall_num++) {
        uint64_t calls = atomic_load_explicit(&prof_syscall_by_num[syscall_num], memory_order_relaxed);
        uint64_t cpu_ns = atomic_load_explicit(&prof_syscall_cpu_ns_by_num[syscall_num], memory_order_relaxed);
        if (calls == 0 || cpu_ns == 0)
            continue;
        unsigned pos = ISH_PROFILE_SYSCALL_TOP;
        while (pos > 0 && cpu_ns > top[pos - 1].cpu_ns)
            pos--;
        if (pos == ISH_PROFILE_SYSCALL_TOP)
            continue;
        for (unsigned i = ISH_PROFILE_SYSCALL_TOP - 1; i > pos; i--)
            top[i] = top[i - 1];
        top[pos].syscall_num = syscall_num;
        top[pos].calls = calls;
        top[pos].cpu_ns = cpu_ns;
        top[pos].wall_ticks = atomic_load_explicit(&prof_syscall_ticks_by_num[syscall_num],
                                                   memory_order_relaxed);
    }
    for (unsigned i = 0; i < ISH_PROFILE_GUEST_PC_BUCKETS; i++) {
        uint64_t sample_ns = atomic_load_explicit(&prof_guest_pc[i].sample_ns,
                                                  memory_order_relaxed);
        if (sample_ns == 0)
            continue;
        unsigned pos = ISH_PROFILE_SYSCALL_TOP;
        while (pos > 0 && sample_ns > top_guest_pc[pos - 1].sample_ns)
            pos--;
        if (pos == ISH_PROFILE_SYSCALL_TOP)
            continue;
        for (unsigned j = ISH_PROFILE_SYSCALL_TOP - 1; j > pos; j--)
            top_guest_pc[j] = top_guest_pc[j - 1];
        top_guest_pc[pos].pc_bucket =
            atomic_load_explicit(&prof_guest_pc[i].pc_bucket, memory_order_relaxed);
        top_guest_pc[pos].sample_ns = sample_ns;
        top_guest_pc[pos].samples =
            atomic_load_explicit(&prof_guest_pc[i].samples, memory_order_relaxed);
    }
    for (unsigned i = 0; i < ISH_PROFILE_HOST_PC_BUCKETS; i++) {
        uint64_t samples = atomic_load_explicit(&prof_host_pc[i].samples,
                                                memory_order_relaxed);
        if (samples == 0)
            continue;
        unsigned pos = ISH_PROFILE_SYSCALL_TOP;
        while (pos > 0 && samples > top_host_pc[pos - 1].samples)
            pos--;
        if (pos == ISH_PROFILE_SYSCALL_TOP)
            continue;
        for (unsigned j = ISH_PROFILE_SYSCALL_TOP - 1; j > pos; j--)
            top_host_pc[j] = top_host_pc[j - 1];
        top_host_pc[pos].pc_bucket =
            atomic_load_explicit(&prof_host_pc[i].pc_bucket, memory_order_relaxed);
        top_host_pc[pos].samples = samples;
    }
    int n = snprintf(buf, size,
        "state: %s\n"
        "guest engine (inclusive): %.3f ms\n"
        "guest engine excluding measured gadgets (estimate): %.3f ms\n"
        "  fiber entries: %llu, dispatched-block instructions (estimate): %llu\n"
        "gadgets (subset of guest engine): %.3f ms, %llu transfers\n"
        "dispatch before guest execution: %.3f ms\n"
        "TLB miss handling (subset of guest engine): %.3f ms, %llu misses\n"
        "syscalls: wall sum %.3f ms across threads; thread CPU %.3f ms (%llu/%llu calls timed)\n"
        "  top by thread CPU (number: calls, CPU ms, wall ms):\n",
        ish_profile_active() ? "running" : "stopped",
        ticks_ms(guest_ticks, frequency),
        ticks_ms(guest_ticks > gadget_ticks ? guest_ticks - gadget_ticks : 0, frequency),
        (unsigned long long) atomic_load_explicit(&prof_guest_blocks, memory_order_relaxed),
        (unsigned long long) atomic_load_explicit(&prof_guest_insns, memory_order_relaxed),
        ticks_ms(gadget_ticks, frequency),
        (unsigned long long) atomic_load_explicit(&prof_gadget_calls, memory_order_relaxed),
        ticks_ms(atomic_load_explicit(&prof_dispatch_ticks, memory_order_relaxed), frequency),
        ticks_ms(atomic_load_explicit(&prof_tlb_ticks, memory_order_relaxed), frequency),
        (unsigned long long) atomic_load_explicit(&prof_tlb_misses, memory_order_relaxed),
        ticks_ms(atomic_load_explicit(&prof_syscall_ticks, memory_order_relaxed), frequency),
        ticks_ms(atomic_load_explicit(&prof_syscall_cpu_ns, memory_order_relaxed), 1000000000),
        (unsigned long long) atomic_load_explicit(&prof_syscall_cpu_samples, memory_order_relaxed),
        (unsigned long long) atomic_load_explicit(&prof_syscall_calls, memory_order_relaxed));
    if (n < 0)
        return 0;
    size_t used = (size_t) n < size ? (size_t) n : size - 1;
    uint64_t host_translated_samples =
        atomic_load_explicit(&prof_host_pc_translated_samples, memory_order_relaxed);
    uint64_t host_native_samples =
        atomic_load_explicit(&prof_host_pc_native_samples, memory_order_relaxed);
#if ISH_PROFILE_HOST_PC_SAMPLER
    used = profile_append(buf, size, used,
                          "host PC samples (SIGPROF, 1 ms; only while fiber_enter is active): %llu total, %llu translated-code, %llu native/helper, %llu dropped\n",
                          (unsigned long long) (host_translated_samples + host_native_samples),
                          (unsigned long long) host_translated_samples,
                          (unsigned long long) host_native_samples,
                          (unsigned long long) atomic_load_explicit(
                              &prof_host_pc_dropped_samples, memory_order_relaxed));
#else
    used = profile_append(buf, size, used, "host PC samples: unsupported on this platform\n");
#endif
    if (prof_host_sampler_errno)
        used = profile_append(buf, size, used, "  host sampler setup/stop error: %d\n",
                              prof_host_sampler_errno);
    if (host_translated_samples + host_native_samples != 0)
        used = profile_append(buf, size, used, "  hottest host PC buckets (256-byte, sample count):\n");
    for (unsigned i = 0; i < ISH_PROFILE_SYSCALL_TOP && top_host_pc[i].samples != 0; i++) {
        uintptr_t pc = (uintptr_t) top_host_pc[i].pc_bucket;
        bool translated = false;
#ifdef ISH_JIT
        translated = jit_host_pc_is_translated(pc);
#endif
#ifdef ISH_JIT
        uint64_t jit_offset;
        if (translated && jit_host_pc_offset(pc, &jit_offset)) {
            used = profile_append(buf, size, used, "    translated code+0x%llx: %llu\n",
                                  (unsigned long long) (jit_offset &
                                      ~((UINT64_C(1) << ISH_PROFILE_HOST_PC_SHIFT) - 1)),
                                  (unsigned long long) top_host_pc[i].samples);
            continue;
        }
#endif
#if defined(__APPLE__)
        Dl_info image;
        if (!translated && dladdr((void *) pc, &image) != 0 && image.dli_fname &&
            image.dli_fbase) {
            const char *name = strrchr(image.dli_fname, '/');
            used = profile_append(buf, size, used, "    %s+0x%llx: %llu\n",
                                  name ? name + 1 : image.dli_fname,
                                  (unsigned long long) (pc - (uintptr_t) image.dli_fbase),
                                  (unsigned long long) top_host_pc[i].samples);
            continue;
        }
#endif
        used = profile_append(buf, size, used, "    %s host PC 0x%llx: %llu\n",
                              translated ? "AOT" : "native",
                              (unsigned long long) pc,
                              (unsigned long long) top_host_pc[i].samples);
    }
    if (guest_cpu_samples != 0)
        used = profile_append(buf, size, used,
                              "fiber_enter thread CPU (sampled estimate, 1 in 256 entries): %.3f ms (%llu samples, %llu dropped by PC table)\n",
                              ticks_ms(guest_cpu_sample_ns * 256, 1000000000),
                              (unsigned long long) guest_cpu_samples,
                              (unsigned long long) atomic_load_explicit(
                                  &prof_guest_cpu_dropped_samples, memory_order_relaxed));
    else
        used = profile_append(buf, size, used,
                              "fiber_enter thread CPU: unavailable (no samples or thread CPU clock unsupported)\n");
    if (guest_cpu_samples != 0)
        used = profile_append(buf, size, used,
                              "  hottest guest module/file-offset ranges (256-byte buckets; estimated CPU ms, samples):\n");
    for (unsigned i = 0; guest_cpu_samples != 0 && i < ISH_PROFILE_SYSCALL_TOP &&
                            top_guest_pc[i].samples != 0; i++) {
        uint64_t module_key = top_guest_pc[i].pc_bucket >> 48;
        uint64_t offset_bucket = top_guest_pc[i].pc_bucket & ((UINT64_C(1) << 48) - 1);
        if (module_key != 0) {
#ifdef ISH_JIT
            char module_path[1024];
            jit_module_path((int) module_key - 1, module_path, sizeof(module_path));
            used = profile_append(buf, size, used, "    %s+0x%llx: %.3f ms, %llu\n",
                                  module_path,
                                  (unsigned long long) ((offset_bucket - 1) <<
                                                        ISH_PROFILE_GUEST_PC_SHIFT),
                                  ticks_ms(top_guest_pc[i].sample_ns * 256, 1000000000),
                                  (unsigned long long) top_guest_pc[i].samples);
#else
            used = profile_append(buf, size, used, "    module %llu+0x%llx: %.3f ms, %llu\n",
                                  (unsigned long long) module_key - 1,
                                  (unsigned long long) ((offset_bucket - 1) <<
                                                        ISH_PROFILE_GUEST_PC_SHIFT),
                                  ticks_ms(top_guest_pc[i].sample_ns * 256, 1000000000),
                                  (unsigned long long) top_guest_pc[i].samples);
#endif
        } else {
            used = profile_append(buf, size, used, "    guest PC 0x%llx: %.3f ms, %llu\n",
                                  (unsigned long long) ((offset_bucket - 1) <<
                                                        ISH_PROFILE_GUEST_PC_SHIFT),
                                  ticks_ms(top_guest_pc[i].sample_ns * 256, 1000000000),
                                  (unsigned long long) top_guest_pc[i].samples);
        }
    }
    bool has_cpu_profile = false;
    for (unsigned i = 0; i < ISH_PROFILE_SYSCALL_TOP && top[i].cpu_ns != 0; i++) {
        has_cpu_profile = true;
        used = profile_append(buf, size, used, "    %u: %llu, %.3f, %.3f ms\n",
                              top[i].syscall_num, (unsigned long long) top[i].calls,
                              ticks_ms(top[i].cpu_ns, 1000000000),
                              ticks_ms(top[i].wall_ticks, frequency));
    }
    if (!has_cpu_profile)
        used = profile_append(buf, size, used, "    unavailable (thread CPU clock unsupported or no calls timed)\n");
    used = profile_append(buf, size, used,
                          "JIT decode: %.3f ms\n"
                          "JIT translation/lookup: %.3f ms\n"
                          "note: syscall wall time includes blocking; sampled fiber_enter thread CPU excludes descheduling and includes JIT/runtime/gadget work; sampling adds clock-read overhead. Gadget/TLB overlap guest; JIT overlaps dispatch.\n",
                          ticks_ms(atomic_load_explicit(&prof_jit_decode_ticks, memory_order_relaxed), frequency),
                          ticks_ms(atomic_load_explicit(&prof_jit_translate_ticks, memory_order_relaxed), frequency));
    return used;
}
