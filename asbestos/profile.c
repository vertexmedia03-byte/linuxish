#include "asbestos/profile.h"
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

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

void ish_profile_add_syscall(uint64_t ticks) {
    atomic_fetch_add_explicit(&prof_syscall_ticks, ticks, memory_order_relaxed);
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
    int n = snprintf(buf, size,
        "state: %s\n"
        "guest engine (inclusive): %.3f ms\n"
        "  fiber entries: %llu, dispatched-block instructions (estimate): %llu\n"
        "gadgets (subset of guest engine): %.3f ms, %llu transfers\n"
        "dispatch before guest execution: %.3f ms\n"
        "TLB miss handling (subset of guest engine): %.3f ms, %llu misses\n"
        "syscall handling: %.3f ms\n"
        "JIT decode: %.3f ms\n"
        "JIT translation/lookup: %.3f ms\n"
        "note: gadget and TLB timings overlap guest-engine time; JIT timings overlap dispatch; do not sum them.\n",
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
        ticks_ms(atomic_load_explicit(&prof_jit_decode_ticks, memory_order_relaxed), frequency),
        ticks_ms(atomic_load_explicit(&prof_jit_translate_ticks, memory_order_relaxed), frequency));
    return n < 0 ? 0 : (size_t) n < size ? (size_t) n : size - 1;
}
