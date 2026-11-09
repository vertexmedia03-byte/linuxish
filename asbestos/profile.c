#include "asbestos/profile.h"
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define ISH_PROFILE_SYSCALL_MAX 512
#define ISH_PROFILE_SYSCALL_TOP 8

_Atomic unsigned char ish_profile_enabled;

static _Atomic uint64_t prof_dispatch_ticks;
static _Atomic uint64_t prof_guest_ticks;
static _Atomic uint64_t prof_guest_blocks;
static _Atomic uint64_t prof_guest_insns;
static _Atomic uint64_t prof_gadget_ticks;
static _Atomic uint64_t prof_gadget_calls;
static _Atomic uint64_t prof_tlb_ticks;
static _Atomic uint64_t prof_tlb_misses;
static _Atomic uint64_t prof_syscall_ticks;
static _Atomic uint64_t prof_syscall_calls;
static _Atomic uint64_t prof_syscall_by_num[ISH_PROFILE_SYSCALL_MAX];
static _Atomic uint64_t prof_syscall_ticks_by_num[ISH_PROFILE_SYSCALL_MAX];
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

void ish_profile_reset(void) {
    atomic_store_explicit(&prof_dispatch_ticks, 0, memory_order_relaxed);
    atomic_store_explicit(&prof_guest_ticks, 0, memory_order_relaxed);
    atomic_store_explicit(&prof_guest_blocks, 0, memory_order_relaxed);
    atomic_store_explicit(&prof_guest_insns, 0, memory_order_relaxed);
    atomic_store_explicit(&prof_gadget_ticks, 0, memory_order_relaxed);
    atomic_store_explicit(&prof_gadget_calls, 0, memory_order_relaxed);
    atomic_store_explicit(&prof_tlb_ticks, 0, memory_order_relaxed);
    atomic_store_explicit(&prof_tlb_misses, 0, memory_order_relaxed);
    atomic_store_explicit(&prof_syscall_ticks, 0, memory_order_relaxed);
    atomic_store_explicit(&prof_syscall_calls, 0, memory_order_relaxed);
    for (unsigned i = 0; i < ISH_PROFILE_SYSCALL_MAX; i++) {
        atomic_store_explicit(&prof_syscall_by_num[i], 0, memory_order_relaxed);
        atomic_store_explicit(&prof_syscall_ticks_by_num[i], 0, memory_order_relaxed);
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

void ish_profile_add_tlb_miss(uint64_t ticks) {
    atomic_fetch_add_explicit(&prof_tlb_ticks, ticks, memory_order_relaxed);
    atomic_fetch_add_explicit(&prof_tlb_misses, 1, memory_order_relaxed);
}

void ish_profile_add_syscall(unsigned syscall_num, uint64_t ticks) {
    atomic_fetch_add_explicit(&prof_syscall_ticks, ticks, memory_order_relaxed);
    atomic_fetch_add_explicit(&prof_syscall_calls, 1, memory_order_relaxed);
    if (syscall_num < ISH_PROFILE_SYSCALL_MAX) {
        atomic_fetch_add_explicit(&prof_syscall_by_num[syscall_num], 1, memory_order_relaxed);
        atomic_fetch_add_explicit(&prof_syscall_ticks_by_num[syscall_num], ticks, memory_order_relaxed);
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
    struct {
        unsigned syscall_num;
        uint64_t calls;
        uint64_t ticks;
    } top[ISH_PROFILE_SYSCALL_TOP] = {};
    for (unsigned syscall_num = 0; syscall_num < ISH_PROFILE_SYSCALL_MAX; syscall_num++) {
        uint64_t calls = atomic_load_explicit(&prof_syscall_by_num[syscall_num], memory_order_relaxed);
        uint64_t ticks = atomic_load_explicit(&prof_syscall_ticks_by_num[syscall_num], memory_order_relaxed);
        if (calls == 0)
            continue;
        unsigned pos = ISH_PROFILE_SYSCALL_TOP;
        while (pos > 0 && ticks > top[pos - 1].ticks)
            pos--;
        if (pos == ISH_PROFILE_SYSCALL_TOP)
            continue;
        for (unsigned i = ISH_PROFILE_SYSCALL_TOP - 1; i > pos; i--)
            top[i] = top[i - 1];
        top[pos].syscall_num = syscall_num;
        top[pos].calls = calls;
        top[pos].ticks = ticks;
    }
    int n = snprintf(buf, size,
        "state: %s\n"
        "guest engine (inclusive): %.3f ms\n"
        "  fiber entries: %llu, dispatched-block instructions (estimate): %llu\n"
        "gadgets (subset of guest engine): %.3f ms, %llu transfers\n"
        "dispatch before guest execution: %.3f ms\n"
        "TLB miss handling (subset of guest engine): %.3f ms, %llu misses\n"
        "syscall handler wall-time sum (all threads): %.3f ms, %llu calls\n"
        "  top syscalls by time (number: calls, ms):\n"
        "    %u: %llu, %.3f ms\n"
        "    %u: %llu, %.3f ms\n"
        "    %u: %llu, %.3f ms\n"
        "    %u: %llu, %.3f ms\n"
        "    %u: %llu, %.3f ms\n"
        "    %u: %llu, %.3f ms\n"
        "    %u: %llu, %.3f ms\n"
        "    %u: %llu, %.3f ms\n"
        "JIT decode: %.3f ms\n"
        "JIT translation/lookup: %.3f ms\n"
        "note: syscall times sum across threads and can include blocking; gadget and TLB overlap guest time; JIT overlaps dispatch.\n",
        ish_profile_active() ? "running" : "stopped",
        ticks_ms(atomic_load_explicit(&prof_guest_ticks, memory_order_relaxed), frequency),
        (unsigned long long) atomic_load_explicit(&prof_guest_blocks, memory_order_relaxed),
        (unsigned long long) atomic_load_explicit(&prof_guest_insns, memory_order_relaxed),
        ticks_ms(atomic_load_explicit(&prof_gadget_ticks, memory_order_relaxed), frequency),
        (unsigned long long) atomic_load_explicit(&prof_gadget_calls, memory_order_relaxed),
        ticks_ms(atomic_load_explicit(&prof_dispatch_ticks, memory_order_relaxed), frequency),
        ticks_ms(atomic_load_explicit(&prof_tlb_ticks, memory_order_relaxed), frequency),
        (unsigned long long) atomic_load_explicit(&prof_tlb_misses, memory_order_relaxed),
        ticks_ms(atomic_load_explicit(&prof_syscall_ticks, memory_order_relaxed), frequency),
        (unsigned long long) atomic_load_explicit(&prof_syscall_calls, memory_order_relaxed),
        top[0].syscall_num, (unsigned long long) top[0].calls, ticks_ms(top[0].ticks, frequency),
        top[1].syscall_num, (unsigned long long) top[1].calls, ticks_ms(top[1].ticks, frequency),
        top[2].syscall_num, (unsigned long long) top[2].calls, ticks_ms(top[2].ticks, frequency),
        top[3].syscall_num, (unsigned long long) top[3].calls, ticks_ms(top[3].ticks, frequency),
        top[4].syscall_num, (unsigned long long) top[4].calls, ticks_ms(top[4].ticks, frequency),
        top[5].syscall_num, (unsigned long long) top[5].calls, ticks_ms(top[5].ticks, frequency),
        top[6].syscall_num, (unsigned long long) top[6].calls, ticks_ms(top[6].ticks, frequency),
        top[7].syscall_num, (unsigned long long) top[7].calls, ticks_ms(top[7].ticks, frequency),
        ticks_ms(atomic_load_explicit(&prof_jit_decode_ticks, memory_order_relaxed), frequency),
        ticks_ms(atomic_load_explicit(&prof_jit_translate_ticks, memory_order_relaxed), frequency));
    return n < 0 ? 0 : (size_t) n < size ? (size_t) n : size - 1;
}
