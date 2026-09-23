/* SPDX-License-Identifier: GPL-2.0-or-later OR LGPL-3.0-or-later */
/* Embed the compiled BPF objects in libebpfdivert.so. */
    .section .rodata.ebpfdivert_bpf, "a"
    .balign 8
    .globl ebpfdivert_bpf_obj
    .hidden ebpfdivert_bpf_obj
    .type ebpfdivert_bpf_obj, @object
ebpfdivert_bpf_obj:
    .incbin EBPFDIVERT_BPF_OBJ
    .globl ebpfdivert_bpf_obj_end
    .hidden ebpfdivert_bpf_obj_end
ebpfdivert_bpf_obj_end:

    .balign 8
    .globl ebpfdivert_events_obj
    .hidden ebpfdivert_events_obj
    .type ebpfdivert_events_obj, @object
ebpfdivert_events_obj:
    .incbin EBPFDIVERT_EVENTS_OBJ
    .globl ebpfdivert_events_obj_end
    .hidden ebpfdivert_events_obj_end
ebpfdivert_events_obj_end:
    .section .note.GNU-stack, "", @progbits
