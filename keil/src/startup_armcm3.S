.syntax unified
.arch armv7-m
.thumb

.section STACK, "aw", %nobits
.align 3
.space 0x1800
.global __initial_sp
__initial_sp:

.section HEAP, "aw", %nobits
.align 3
.global __heap_base
__heap_base:
.space 0x200
.global __heap_limit
__heap_limit:

.thumb_func
.global Reset_Handler
.type Reset_Handler, %function
.thumb_func
.global Default_Handler
.type Default_Handler, %function

.section RESET, "ax"
.align 2
.global __Vectors
__Vectors:
    .word __initial_sp
    .word Reset_Handler
    .word Default_Handler
    .word Default_Handler
    .word Default_Handler
    .word Default_Handler
    .word Default_Handler
    .word 0
    .word 0
    .word 0
    .word 0
    .word Default_Handler
    .word Default_Handler
    .word 0
    .word Default_Handler
    .word Default_Handler
    .rept 32
    .word Default_Handler
    .endr

.thumb_func
Reset_Handler:
    bl SystemInit
    bl __main
    b .

.thumb_func
Default_Handler:
    b .

.global SystemInit
.global __main
