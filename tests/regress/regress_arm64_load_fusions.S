#ifdef __APPLE__
#define NAME(x) _##x
#else
#define NAME(x) x
#endif
.text

.data
.align 3
.global NAME(adrp_fusion_data)
NAME(adrp_fusion_data):
    .byte 0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87
    .byte 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f

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

.global NAME(adrp_ldrb)
.align 4
NAME(adrp_ldrb):
    adrp x9, NAME(adrp_fusion_data)
    ldrb w9, [x9, :lo12:NAME(adrp_fusion_data)+1]
    mov x0, x9
    ret

.global NAME(adrp_ldrh)
.align 4
NAME(adrp_ldrh):
    adrp x9, NAME(adrp_fusion_data)
    ldrh w9, [x9, :lo12:NAME(adrp_fusion_data)+2]
    mov x0, x9
    ret

.global NAME(adrp_ldrw)
.align 4
NAME(adrp_ldrw):
    adrp x9, NAME(adrp_fusion_data)
    ldr w9, [x9, :lo12:NAME(adrp_fusion_data)+4]
    mov x0, x9
    ret

.global NAME(adrp_ldrx)
.align 4
NAME(adrp_ldrx):
    adrp x9, NAME(adrp_fusion_data)
    ldr x9, [x9, :lo12:NAME(adrp_fusion_data)+8]
    mov x0, x9
    ret
