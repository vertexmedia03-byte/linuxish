#define _POSIX_C_SOURCE 200809L
#include "asbestos/profile.h"
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define ISH_PROFILE_SYSCALL_MAX 512
#define ISH_PROFILE_SYSCALL_TOP 8
#define ISH_PROFILE_GUEST_PC_BUCKETS 4096
#define ISH_PROFILE_GUEST_PC_PROBES 16
#define ISH_PROFILE_GUEST_PC_SHIFT 8

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

void ish_profile_add_guest_cpu(uint64_t guest_pc, uint64_t sampled_ns) {
    atomic_fetch_add_explicit(&prof_guest_cpu_sample_ns, sampled_ns, memory_order_relaxed);
    atomic_fetch_add_explicit(&prof_guest_cpu_samples, 1, memory_order_relaxed);
    uint64_t key = (guest_pc >> ISH_PROFILE_GUEST_PC_SHIFT) + 1;
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
        ish_profile_reset();
        atomic_store_explicit(&ish_profile_enabled, 1, memory_order_release);
        return 0;
    }
    if (len == 4 && !memcmp(cmd, "stop", 4)) {
        atomic_store_explicit(&ish_profile_enabled, 0, memory_order_release);
        return 0;
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
            atomic_load_explicit(&prof_guest_pc[i].pc_bucket, memory_order_relaxed) - 1;
        top_guest_pc[pos].sample_ns = sample_ns;
        top_guest_pc[pos].samples =
            atomic_load_explicit(&prof_guest_pc[i].samples, memory_order_relaxed);
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
    if (guest_cpu_samples != 0) {
        used = profile_append(buf, size, used,
                              "  hottest guest PC ranges (256-byte buckets; estimated CPU ms, samples):\n");
        for (unsigned i = 0; i < ISH_PROFILE_SYSCALL_TOP && top_guest_pc[i].samples != 0; i++)
            used = profile_append(buf, size, used, "    0x%llx: %.3f ms, %llu\n",
                                  (unsigned long long) (top_guest_pc[i].pc_bucket <<
                                                        ISH_PROFILE_GUEST_PC_SHIFT),
                                  ticks_ms(top_guest_pc[i].sample_ns * 256, 1000000000),
                                  (unsigned long long) top_guest_pc[i].samples);
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
