#include <stdint.h>
#include <stdio.h>

uint64_t ldr64_add_imm(const void *p);
uint64_t ldr32_add_imm(const void *p);
uint64_t ldrb_add_imm(const void *p);
uint64_t ldrh_add_imm(const void *p);
uint32_t ldrb_reg(const void *p, uint64_t index);
uint32_t ldrh_reg(const void *p, uint64_t index);

static int failures;

static void check(const char *name, uint64_t got, uint64_t expected) {
    if (got == expected) {
        printf("  PASS  %-16s 0x%016llx\n", name, (unsigned long long)got);
    } else {
        printf("  FAIL  %-16s got 0x%016llx want 0x%016llx\n", name,
               (unsigned long long)got, (unsigned long long)expected);
        failures++;
    }
}

int main(void) {
    const uint64_t values[] = {
        UINT64_C(0x8123456789abcdef), UINT64_C(0xf1234567),
        UINT64_C(0x88776655443322ab), UINT64_C(0x123456789abcdef0)
    };

    check("LDR X + ADD", ldr64_add_imm(values),
          values[1] + (UINT64_C(0x123) << 12));
    check("LDR W + ADD", ldr32_add_imm(values),
          (uint64_t)(uint32_t)(values[0] >> 32) + UINT64_C(0x321));
    check("LDRB + ADD", ldrb_add_imm(values), UINT64_C(0x89) + 0x7f);
    check("LDRH + ADD", ldrh_add_imm(values), UINT64_C(0x89ab) + 0x21);
    check("LDRB register", ldrb_reg(values, 0), 0xef);
    check("LDRH register", ldrh_reg(values, 1), 0x89ab);
    printf("\n  FAIL=%d\n", failures);
    return failures != 0;
}
