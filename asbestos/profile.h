#ifndef ASBESTOS_PROFILE_H
#define ASBESTOS_PROFILE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool ish_profile_active(void);
bool ish_profile_cpu_clock_enabled(void);
uint64_t ish_profile_ticks(void);
uint64_t ish_profile_ticks_per_second(void);
bool ish_profile_thread_cpu_time(uint64_t *nanoseconds);
void ish_profile_reset(void);
void ish_profile_add_dispatch(uint64_t ticks);
void ish_profile_add_guest(uint64_t ticks, uint64_t blocks, uint64_t insns,
                           uint64_t gadget_ticks, uint64_t gadget_calls);
void ish_profile_add_guest_cpu(int module, uint64_t guest_pc, uint64_t file_offset,
                               uint64_t sampled_ns);
void ish_profile_add_tlb_miss(uint64_t ticks);
void ish_profile_add_syscall(unsigned syscall_num, uint64_t wall_ticks,
                             uint64_t thread_cpu_ns, bool thread_cpu_available);
void ish_profile_add_jit_decode(uint64_t ticks);
void ish_profile_add_jit_translate(uint64_t ticks);
void ish_profile_record_host_pc(uintptr_t pc, uintptr_t lr, bool translated);
int ish_profile_host_sampler_start(void);
int ish_profile_host_sampler_stop(void);
int ish_profile_control(const char *cmd, size_t len);
size_t ish_profile_describe(char *buf, size_t size);

#endif
