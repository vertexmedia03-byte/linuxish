#ifdef __APPLE__
#define NAME(x) _##x
#else
#define NAME(x) x
#endif
.text

.global NAME(ldr64_add_imm)
.align 4
NAME(ldr64_add_imm):
    ldr x8, [x0, #8]
    add x8, x8, #0x123, lsl #12
    mov x0, x8
    ret

.global NAME(ldr32_add_imm)
.align 4
NAME(ldr32_add_imm):
    ldr w8, [x0, #4]
    add x8, x8, #0x321
    mov x0, x8
    ret

.global NAME(ldrb_add_imm)
.align 4
NAME(ldrb_add_imm):
    ldrb w8, [x0, #3]
    add x8, x8, #0x7f
    mov x0, x8
    ret

.global NAME(ldrh_add_imm)
.align 4
NAME(ldrh_add_imm):
    ldrh w8, [x0, #2]
    add x8, x8, #0x21
    mov x0, x8
    ret

.global NAME(ldrb_reg)
.align 4
NAME(ldrb_reg):
    ldrb w8, [x0, x1]
    mov w0, w8
    ret

.global NAME(ldrh_reg)
.align 4
NAME(ldrh_reg):
    ldrh w8, [x0, x1, lsl #1]
    mov w0, w8
    ret
