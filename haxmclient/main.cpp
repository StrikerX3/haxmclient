#include <cstdio>

#include "haxm.h"

void printRegs(struct vcpu_state_t *regs) {
    printf("EAX = %08x   EBX = %08x   ECX = %08x   EDX = %08x   ESI = %08x   EDI = %08x  EFER = %08x\n", regs->_eax, regs->_ebx, regs->_ecx, regs->_edx, regs->_esi, regs->_edi, regs->_efer);
    printf("CR0 = %08x   CR2 = %08x   CR3 = %08x   CR4 = %08x   ESP = %08x   EBP = %08x   GDT = %08x:%04x\n", regs->_cr0, regs->_cr2, regs->_cr3, regs->_cr4, regs->_esp, regs->_ebp, regs->_gdt.base, regs->_gdt.limit);
    printf("DR0 = %08x   DR1 = %08x   DR2 = %08x   DR3 = %08x   DR6 = %08x   DR7 = %08x   IDT = %08x:%04x\n", regs->_dr0, regs->_dr1, regs->_dr2, regs->_dr3, regs->_dr6, regs->_dr7, regs->_idt.base, regs->_idt.limit);
    printf(" CS = %04x   DS = %04x   ES = %04x   FS = %04x   GS = %04x   SS = %04x   TR = %04x   PDE = %08x   LDT = %08x:%04x\n", regs->_cs.selector, regs->_ds.selector, regs->_es.selector, regs->_fs.selector, regs->_gs.selector, regs->_ss.selector, regs->_tr.selector, regs->_pde, regs->_ldt.base, regs->_ldt.limit);
    printf("EIP = %08x   EFLAGS = %08x\n", regs->_eip, regs->_eflags);
}

void printFPURegs(struct fx_layout *fpu) {
    printf("FCW =     %04x   FSW =     %04x   FTW =       %02x   FOP =     %04x   MXCSR = %08x\n", fpu->fcw, fpu->fsw, fpu->ftw, fpu->fop, fpu->mxcsr);
    printf("FIP = %08x   FCS =     %04x   FDP = %08x   FDS = %08x    mask = %08x\n", fpu->fip, fpu->fcs, fpu->fdp, fpu->fds, fpu->mxcsr_mask);
    for (int i = 0; i < 8; i++) {
        printf("  ST%d = %010x   %+.20Le\n", i, *(uint64_t *)&fpu->st_mm[i], *(long double *)&fpu->st_mm[i]);
    }
    for (int i = 0; i < 8; i++) {
        printf(" XMM%d = %08x %08x %08x %08x     %+.7e %+.7e %+.7e %+.7e     %+.15le %+.15le\n", i,
            *(uint32_t *)&fpu->mmx_1[i][0], *(uint32_t *)&fpu->mmx_1[i][4], *(uint32_t *)&fpu->mmx_1[i][8], *(uint32_t *)&fpu->mmx_1[i][12],
            *(float *)&fpu->mmx_1[i][0], *(float *)&fpu->mmx_1[i][4], *(float *)&fpu->mmx_1[i][8], *(float *)&fpu->mmx_1[i][12],
            *(double *)&fpu->mmx_1[i][0], *(double *)&fpu->mmx_1[i][8]
        );
    }
}

//#define DO_MANUAL_INIT
//#define DO_MANUAL_JMP
//#define DO_MANUAL_PAGING

int main() {
    // Allocate memory for the RAM and ROM
    const uint32_t ramSize = 256 * 4096; // 1 MiB
    const uint32_t ramBase = 0x00000000;
    const uint32_t romSize = 16 * 4096; // 64 KiB
    const uint32_t romBase = 0xFFFF0000;

    char *ram = (char *)_aligned_malloc(ramSize, 0x1000);
    memset(ram, 0, ramSize);

    char *rom = (char *)_aligned_malloc(romSize, 0x1000);
    memset(rom, 0xf4, romSize);

    // Write initialization code to ROM and a simple program to RAM
    {
        uint32_t addr;
        #define emit(buf, code) {memcpy(&buf[addr], code, sizeof(code) - 1); addr += sizeof(code) - 1;}

        // --- Start of ROM code ----------------------------------------------------------------------------------------------

        // --- GDT and IDT tables ---------------------------------------------------------------------------------------------

        // GDT table
        addr = 0x0000;
        emit(rom, "\x00\x00\x00\x00\x00\x00\x00\x00"); // [0x0000] GDT entry 0: null
        emit(rom, "\xff\xff\x00\x00\x00\x9b\xcf\x00"); // [0x0008] GDT entry 1: code (full access to 4 GB linear space)
        emit(rom, "\xff\xff\x00\x00\x00\x93\xcf\x00"); // [0x0010] GDT entry 2: data (full access to 4 GB linear space)

        // IDT table (system)
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0018] Vector 0x00: Divide by zero
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0020] Vector 0x01: Reserved
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0028] Vector 0x02: Non-maskable interrupt
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0030] Vector 0x03: Breakpoint (INT3)
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0038] Vector 0x04: Overflow (INTO)
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0040] Vector 0x05: Bounds range exceeded (BOUND)
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0048] Vector 0x06: Invalid opcode (UD2)
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0050] Vector 0x07: Device not available (WAIT/FWAIT)
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0058] Vector 0x08: Double fault
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0060] Vector 0x09: Coprocessor segment overrun
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0068] Vector 0x0A: Invalid TSS
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0070] Vector 0x0B: Segment not present
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0078] Vector 0x0C: Stack-segment fault
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0080] Vector 0x0D: General protection fault
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0088] Vector 0x0E: Page fault
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0090] Vector 0x0F: Reserved
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0098] Vector 0x10: x87 FPU error
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x00a0] Vector 0x11: Alignment check
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x00a8] Vector 0x12: Machine check
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x00b0] Vector 0x13: SIMD Floating-Point Exception
        for (uint8_t i = 0x14; i <= 0x1f; i++) {
            emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x00b8..0x0110] Vector 0x14..0x1F: Reserved
        }

        // IDT table (user defined)
        emit(rom, "\x00\x10\x08\x00\x00\x8f\x00\x10"); // [0x0118] Vector 0x20: Just IRET
        emit(rom, "\x02\x10\x08\x00\x00\x8f\x00\x10"); // [0x0120] Vector 0x21: HLT, then IRET

        // --- 32-bit protected mode ------------------------------------------------------------------------------------------

        // Prepare memory for paging
        // (based on https://github.com/unicorn-engine/unicorn/blob/master/tests/unit/test_x86_soft_paging.c)
        // 0x1000 = Page directory
        // 0x2000 = Page table (identity map RAM)
        // 0x3000 = Page table (identity map ROM)
        // 0x4000 = Page table (0x10000xxx .. 0x10001xxx -> 0x00005xxx .. 0x00006xxx)
        // 0x5000 = Data area (first dword reads 0xdeadbeef)
        // 0x6000 = Interrupt handler code area
        // 0xe000 = Page table (identity map first page of MMIO: 0xe00000xxx)

        // Load segment registers
        addr = 0xff00;
        #ifdef DO_MANUAL_PAGING
        emit(rom, "\xf4");                             // [0xff00] hlt
        emit(rom, "\x90");                             // [0xff01] nop
        #else
        emit(rom, "\x33\xc0");                         // [0xff00] xor    eax, eax
        #endif
        emit(rom, "\xb0\x10");                         // [0xff02] mov     al, 0x10
        emit(rom, "\x8e\xd8");                         // [0xff04] mov     ds, eax
        emit(rom, "\x8e\xc0");                         // [0xff06] mov     es, eax
        emit(rom, "\x8e\xd0");                         // [0xff08] mov     ss, eax

        // Clear page directory
        emit(rom, "\xbf\x00\x10\x00\x00");             // [0xff0a] mov    edi, 0x1000
        emit(rom, "\xb9\x00\x10\x00\x00");             // [0xff0f] mov    ecx, 0x1000
        emit(rom, "\x31\xc0");                         // [0xff14] xor    eax, eax
        emit(rom, "\xf3\xab");                         // [0xff16] rep    stosd

        // Write 0xdeadbeef at physical memory address 0x5000
        emit(rom, "\xbf\x00\x50\x00\x00");             // [0xff18] mov    edi, 0x5000
        emit(rom, "\xb8\xef\xbe\xad\xde");             // [0xff1d] mov    eax, 0xdeadbeef
        emit(rom, "\x89\x07");                         // [0xff22] mov    [edi], eax

        // Identity map the RAM to 0x00000000
        emit(rom, "\xb9\x00\x01\x00\x00");             // [0xff24] mov    ecx, 0x100
        emit(rom, "\xbf\x00\x20\x00\x00");             // [0xff29] mov    edi, 0x2000
        emit(rom, "\xb8\x03\x00\x00\x00");             // [0xff2e] mov    eax, 0x0003
        // aLoop:
        emit(rom, "\xab");                             // [0xff33] stosd
        emit(rom, "\x05\x00\x10\x00\x00");             // [0xff34] add    eax, 0x1000
        emit(rom, "\xe2\xf8");                         // [0xff39] loop   aLoop

        // Identity map the ROM
        emit(rom, "\xb9\x10\x00\x00\x00");             // [0xff3b] mov    ecx, 0x10
        emit(rom, "\xbf\xc0\x3f\x00\x00");             // [0xff40] mov    edi, 0x3fc0
        emit(rom, "\xb8\x03\x00\xff\xff");             // [0xff45] mov    eax, 0xffff0003
        // bLoop:
        emit(rom, "\xab");                             // [0xff4a] stosd
        emit(rom, "\x05\x00\x10\x00\x00");             // [0xff4b] add    eax, 0x1000
        emit(rom, "\xe2\xf8");                         // [0xff50] loop   bLoop

        // Map physical address 0x5000 to virtual address 0x10000000
        emit(rom, "\xbf\x00\x40\x00\x00");             // [0xff52] mov    edi, 0x4000
        emit(rom, "\xb8\x03\x50\x00\x00");             // [0xff57] mov    eax, 0x5003
        emit(rom, "\x89\x07");                         // [0xff5c] mov    [edi], eax

        // Map physical address 0x6000 to virtual address 0x10001000
        emit(rom, "\xbf\x04\x40\x00\x00");             // [0xff5e] mov    edi, 0x4004
        emit(rom, "\xb8\x03\x60\x00\x00");             // [0xff63] mov    eax, 0x6003
        emit(rom, "\x89\x07");                         // [0xff68] mov    [edi], eax

        // Map physical address 0xe0000000 to virtual address 0xe0000000 (for MMIO)
        emit(rom, "\xbf\x00\xe0\x00\x00");             // [0xff6a] mov    edi, 0xe000
        emit(rom, "\xb8\x03\x00\x00\xe0");             // [0xff6f] mov    eax, 0xe0000003
        emit(rom, "\x89\x07");                         // [0xff74] mov    [edi], eax

        // Add page tables into page directory
        emit(rom, "\xbf\x00\x10\x00\x00");             // [0xff76] mov    edi, 0x1000
        emit(rom, "\xb8\x03\x20\x00\x00");             // [0xff7b] mov    eax, 0x2003
        emit(rom, "\x89\x07");                         // [0xff80] mov    [edi], eax
        emit(rom, "\xbf\xfc\x1f\x00\x00");             // [0xff82] mov    edi, 0x1ffc
        emit(rom, "\xb8\x03\x30\x00\x00");             // [0xff87] mov    eax, 0x3003
        emit(rom, "\x89\x07");                         // [0xff8c] mov    [edi], eax
        emit(rom, "\xbf\x00\x11\x00\x00");             // [0xff8e] mov    edi, 0x1100
        emit(rom, "\xb8\x03\x40\x00\x00");             // [0xff93] mov    eax, 0x4003
        emit(rom, "\x89\x07");                         // [0xff98] mov    [edi], eax
        emit(rom, "\xbf\x00\x1e\x00\x00");             // [0xff9a] mov    edi, 0x1e00
        emit(rom, "\xb8\x03\xe0\x00\x00");             // [0xff9f] mov    eax, 0xe003
        emit(rom, "\x89\x07");                         // [0xffa4] mov    [edi], eax

        // Load the page directory register
        emit(rom, "\xb8\x00\x10\x00\x00");             // [0xffa6] mov    eax, 0x1000
        emit(rom, "\x0f\x22\xd8");                     // [0xffab] mov    cr3, eax

        // Enable paging
        emit(rom, "\x0f\x20\xc0");                     // [0xffae] mov    eax, cr0
        emit(rom, "\x0d\x00\x00\x00\x80");             // [0xffb1] or     eax, 0x80000000
        emit(rom, "\x0f\x22\xc0");                     // [0xffb6] mov    cr0, eax

        // Clear EAX
        emit(rom, "\x31\xc0");                         // [0xffb9] xor    eax, eax

        // Load using virtual memory address; EAX = 0xdeadbeef
        emit(rom, "\xbe\x00\x00\x00\x10");             // [0xffbb] mov    esi, 0x10000000
        emit(rom, "\x8b\x06");                         // [0xffc0] mov    eax, [esi]

        // First stop
        emit(rom, "\xf4");                             // [0xffc2] hlt

        // Jump to RAM
        emit(rom, "\xe9\x3c\x00\x00\x10");             // [0xffc3] jmp    0x10000004
        // .. ends at 0xffc7

        // --- 16-bit real mode transition to 32-bit protected mode -----------------------------------------------------------

        // Load GDT and IDT tables
        addr = 0xffd0;
        emit(rom, "\x66\x2e\x0f\x01\x16\xf2\xff");     // [0xffd0] lgdt   [cs:0xfff2]
        emit(rom, "\x66\x2e\x0f\x01\x1e\xf8\xff");     // [0xffd7] lidt   [cs:0xfff8]

        // Enter protected mode
        emit(rom, "\x0f\x20\xc0");                     // [0xffde] mov    eax, cr0
        emit(rom, "\x0c\x01");                         // [0xffe1] or      al, 1
        emit(rom, "\x0f\x22\xc0");                     // [0xffe3] mov    cr0, eax
        #ifdef DO_MANUAL_JMP
        emit(rom, "\xf4")                              // [0xffe6] hlt
        // Fill the rest with HLTs
        while (addr < 0xfff0) {
            emit(rom, "\xf4");                         // [0xffe7..0xffef] hlt
        }
        #else
        emit(rom, "\x66\xea\x00\xff\xff\xff\x08\x00"); // [0xffe6] jmp    dword 0x8:0xffffff00
        emit(rom, "\xf4");                             // [0xffef] hlt
        #endif

        // --- 16-bit real mode start -----------------------------------------------------------------------------------------

        // Jump to initialization code and define GDT/IDT table pointer
        addr = 0xfff0;
        #ifdef DO_MANUAL_INIT
        emit(rom, "\xf4");                             // [0xfff0] hlt
        emit(rom, "\x90");                             // [0xfff1] nop
        #else
        emit(rom, "\xeb\xde");                         // [0xfff0] jmp    short 0x1d0
        #endif
        emit(rom, "\x18\x00\x00\x00\xff\xff");         // [0xfff2] GDT pointer: 0xffff0000:0x0018
        emit(rom, "\x10\x01\x18\x00\xff\xff");         // [0xfff8] IDT pointer: 0xffff0018:0x0110
        // There's room for two bytes at the end, so let's fill it up with HLTs
        emit(rom, "\xf4");                             // [0xfffe] hlt
        emit(rom, "\xf4");                             // [0xffff] hlt

        // --- End of ROM code ------------------------------------------------------------------------------------------------

        // --- Start of RAM code ----------------------------------------------------------------------------------------------
        addr = 0x5004; // Addresses 0x5000..0x5003 are reserved for 0xdeadbeef
        // Note that these addresses are mapped to virtual addresses 0x10000000 through 0x10000fff

        // Do some basic stuff
        emit(ram, "\xba\x78\x56\x34\x12");             // [0x5004] mov    edx, 0x12345678
        emit(ram, "\xbf\x00\x00\x00\x10");             // [0x5009] mov    edi, 0x10000000
        emit(ram, "\x31\xd0");                         // [0x500e] xor    eax, edx
        emit(ram, "\x89\x07");                         // [0x5010] mov    [edi], eax
        emit(ram, "\xf4");                             // [0x5012] hlt

        // Setup a proper stack
        emit(ram, "\x31\xed");                         // [0x5013] xor    ebp, ebp
        emit(ram, "\xbc\x00\x00\x10\x00");             // [0x5015] mov    esp, 0x100000

        // Test the stack
        emit(ram, "\x68\xfe\xca\x0d\xf0");             // [0x501a] push   0xf00dcafe
        emit(ram, "\x5a");                             // [0x501f] pop    edx
        emit(ram, "\xf4");                             // [0x5020] hlt

        // -------------------------------

        // Call interrupts
        emit(ram, "\xcd\x20");                         // [0x5021] int    0x20
        emit(ram, "\xcd\x21");                         // [0x5023] int    0x21
        emit(ram, "\xf4");                             // [0x5025] hlt

        // -------------------------------

        // Basic PMIO
        emit(ram, "\x66\xba\x00\x10");                 // [0x5026] mov     dx, 0x1000
        emit(ram, "\xec");                             // [0x502a] in      al, dx
        emit(ram, "\x66\x42");                         // [0x502b] inc     dx
        emit(ram, "\x34\xff");                         // [0x502d] xor     al, 0xff
        emit(ram, "\xee");                             // [0x502f] out     dx, al
        emit(ram, "\x66\x42");                         // [0x5030] inc     dx
        emit(ram, "\x66\xed");                         // [0x5032] in      ax, dx
        emit(ram, "\x66\x42");                         // [0x5034] inc     dx
        emit(ram, "\x66\x83\xf0\xff");                 // [0x5036] xor     ax, 0xffff
        emit(ram, "\x66\xef");                         // [0x503a] out     dx, ax
        emit(ram, "\x66\x42");                         // [0x503c] inc     dx
        emit(ram, "\xed");                             // [0x503e] in     eax, dx
        emit(ram, "\x66\x42");                         // [0x503f] inc     dx
        emit(ram, "\x83\xf0\xff");                     // [0x5041] xor    eax, 0xffffffff
        emit(ram, "\xef");                             // [0x5044] out     dx, eax

        // -------------------------------

        // Basic MMIO
        emit(ram, "\xbf\x00\x00\x00\xe0");             // [0x5045] mov    edi, 0xe0000000
        emit(ram, "\x8b\x1f");                         // [0x504a] mov    ebx, [edi]
        emit(ram, "\x83\xc7\x04");                     // [0x504c] add    edi, 4
        emit(ram, "\x89\x1f");                         // [0x504f] mov    [edi], ebx

        // Advanced MMIO
        emit(ram, "\xb9\x00\x00\x00\x10");             // [0x5051] mov    ecx, 0x10000000
        emit(ram, "\x85\x0f");                         // [0x5056] test   [edi], ecx

        // -------------------------------

        // Test single stepping
        emit(ram, "\xb9\x11\x00\x00\x00");             // [0x5058] mov    ecx, 0x11
        emit(ram, "\xb9\x00\x22\x00\x00");             // [0x505d] mov    ecx, 0x2200
        emit(ram, "\xb9\x00\x00\x33\x00");             // [0x5062] mov    ecx, 0x330000
        emit(ram, "\xb9\x00\x00\x00\x44");             // [0x5067] mov    ecx, 0x44000000

        // -------------------------------

        // Test software and hardware breakpoints
        emit(ram, "\xb9\xff\x00\x00\x00");             // [0x506c] mov    ecx, 0xff
        emit(ram, "\xb9\x00\xee\x00\x00");             // [0x5071] mov    ecx, 0xee00
        emit(ram, "\xb9\x00\x00\xdd\x00");             // [0x5076] mov    ecx, 0xdd0000
        emit(ram, "\xb9\x00\x00\x00\xcc");             // [0x507b] mov    ecx, 0xcc000000
        emit(ram, "\xb9\xff\xee\xdd\xcc");             // [0x5080] mov    ecx, 0xccddeeff

        // -------------------------------

        // End
        emit(ram, "\xf4");                             // [0x5085] hlt

        // -------------------------------

        addr = 0x6000; // Interrupt handlers
        // Note that these addresses are mapped to virtual addresses 0x10001000 through 0x10001fff
        // 0x20: Just IRET
        emit(ram, "\xfb");                             // [0x6000] sti
        emit(ram, "\xcf");                             // [0x6001] iretd

        // 0x21: HLT, then IRET
        emit(ram, "\xf4");                             // [0x6002] hlt
        emit(ram, "\xfb");                             // [0x6003] sti
        emit(ram, "\xcf");                             // [0x6004] iretd

        // 0x00 .. 0x1F: Clear stack then IRET
        emit(ram, "\x83\xc4\x04");                     // [0x6005] add    esp, 4
        emit(ram, "\xfb");                             // [0x6008] sti
        emit(ram, "\xcf");                             // [0x6009] iretd

        #undef emit
    }


    Haxm haxm;

    HaxmStatus status = haxm.Initialize();
    switch (status) {
    case HXS_NOT_FOUND: printf("HAXM module not found: %d\n", haxm.GetLastError()); return -1;
    case HXS_INIT_FAILED: printf("Failed to open HAXM device %d\n", haxm.GetLastError()); return -1;
    default: break;
    }

    // Check version
    auto ver = haxm.GetModuleVersion();
    printf("HAXM module loaded\n");
    printf("  Current version: %d\n", ver->cur_version);
    printf("  Compatibility version: %d\n", ver->compat_version);

    // Check capabilities
    auto caps = haxm.GetCapabilities();
    printf("\nCapabilities:\n");
    if (caps->wstatus & HAX_CAP_STATUS_WORKING) {
        printf("  HAXM can be used on this host\n");
        if (caps->winfo & HAX_CAP_FASTMMIO) {
            printf("  HAXM kernel module supports fast MMIO\n");
        }
        if (caps->winfo & HAX_CAP_EPT) {
            printf("  Host CPU supports Extended Page Tables (EPT)\n");
        }
        if (caps->winfo & HAX_CAP_UG) {
            printf("  Host CPU supports Unrestricted Guest (UG)\n");
        }
        if (caps->winfo & HAX_CAP_64BIT_SETRAM) {
            printf("  64-bit RAM functionality is present\n");
        }
        if ((caps->wstatus & HAX_CAP_MEMQUOTA) && caps->mem_quota != 0) {
            printf("    Global memory quota enabled: %lld MB available\n", caps->mem_quota);
        }
        if (caps->winfo & HAX_CAP_TUNNEL_PAGE) {
            printf("  Tunnel is allocated on a full page\n");
        }
        if (caps->winfo & HAX_CAP_RAM_PROTECTION) {
            printf("  Guest RAM protection\n");
        }
        if (caps->winfo & HAX_CAP_DEBUG) {
            printf("  Guest debugging\n");
        }
    }
    else {
        printf("  HAXM cannot be used on this host\n");
        if (caps->winfo & HAX_CAP_FAILREASON_VT) {
            printf("  Intel VT-x not supported or disabled\n");
        }
        if (caps->winfo & HAX_CAP_FAILREASON_NX) {
            printf("  Intel Execute Disable Bit (NX) not supported or disabled\n");
        }
        return -1;
    }
	
    // ------------------------------------------------------------------------

    // Now let's have some fun!

    // Create a VM
    HaxmVM *vm;
    HaxmVMStatus vmStatus = haxm.CreateVM(&vm);
    switch (vmStatus) {
    case HXVMS_CREATE_FAILED: printf("Failed to create VM: %d\n", haxm.GetLastError()); return -1;
    }

    printf("\nVM created: ID %x\n", vm->ID());
    if (vm->FastMMIOEnabled()) {
	    printf("  Fast MMIO enabled\n");
    }

    // Allocate RAM
    vmStatus = vm->AllocateMemory(ram, ramSize, ramBase, HXVM_MEM_RAM);
    switch (vmStatus) {
    case HXVMS_MEM_MISALIGNED: printf("Failed to allocate RAM: host memory block is misaligned\n"); return -1;
    case HXVMS_MEMSIZE_MISALIGNED: printf("Failed to allocate RAM: memory block is misaligned\n"); return -1;
    case HXVMS_ALLOC_MEM_FAILED: printf("Failed to allocate RAM: %d\n", vm->GetLastError()); return -1;
    case HXVMS_SET_MEM_FAILED: printf("Failed to configure RAM: %d\n", vm->GetLastError()); return -1;
    }

    printf("  Allocated %d bytes of RAM at physical address 0x%08x\n", ramSize, ramBase);

    // Allocate ROM
    vmStatus = vm->AllocateMemory(rom, romSize, romBase, HXVM_MEM_ROM);
    switch (vmStatus) {
    case HXVMS_MEM_MISALIGNED: printf("Failed to allocate ROM: host memory block is misaligned\n"); return -1;
    case HXVMS_MEMSIZE_MISALIGNED: printf("Failed to allocate ROM: memory block is misaligned\n"); return -1;
    case HXVMS_ALLOC_MEM_FAILED: printf("Failed to allocate ROM: %d\n", vm->GetLastError()); return -1;
    case HXVMS_SET_MEM_FAILED: printf("Failed to configure ROM: %d\n", vm->GetLastError()); return -1;
    }

    printf("  Allocated %d bytes of ROM at physical address 0x%08x\n", romSize, romBase);

    // Add a virtual CPU to the VM
    HaxmVCPU *vcpu;
    HaxmVCPUStatus vcpuStatus = vm->CreateVCPU(&vcpu);
    switch (vcpuStatus) {
    case HXVCPUS_CREATE_FAILED: printf("Failed to create VCPU for VM: %d\n", vm->GetLastError()); return -1;
    }

    printf("  VCPU created with ID %d\n", vcpu->ID());
    printf("    VCPU Tunnel allocated at 0x%016llx\n", (uint64_t)vcpu->Tunnel());
    printf("    VCPU I/O tunnel allocated at 0x%016llx\n", (uint64_t)vcpu->IOTunnel());
    printf("\n");

    // Get CPU registers
    struct vcpu_state_t regs;
    vcpuStatus = vcpu->GetRegisters(&regs);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU registers: %d\n", vcpu->GetLastError()); return -1;
    }
	
    // Get FPU registers
    struct fx_layout fpu;
    vcpuStatus = vcpu->GetFPURegisters(&fpu);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU floating point registers: %d\n", vcpu->GetLastError()); return -1;
    }

    #ifdef DO_MANUAL_INIT
    // Load GDT table
    regs._gdt.base = 0xffff0000;
    regs._gdt.limit = 0x0018;

    // Load IDT table
    regs._idt.base = 0xffff0018;
    regs._idt.limit = 0x0110;

    // Enter protected mode
    regs._cr0 |= 1;

    // Skip initialization code
    regs._eip = 0xffe6;

    vcpu->SetRegisters(&regs);
    #endif
	
    printf("\nInitial CPU register state:\n");
    printRegs(&regs);
    //printFPURegs(&fpu);
    printf("\n");

    // ----- Start of emulation -----------------------------------------------------------------------------------------------

    // The CPU starts in 16-bit real mode.
    // Memory addressing is based on segments and offsets, where a segment is basically a 16-byte offset.

    // Run the CPU!
    vcpu->Run();

    #ifdef DO_MANUAL_JMP
    // Do the jmp dword 0x8:0xffffff00 manually
    vcpu->GetRegisters(&regs);

    // Set basic register data
    regs._cs.selector = 0x0008;
    regs._eip = 0xffffff00;

    // Find GDT entry in memory
    uint64_t gdtEntry;
    if (regs._gdt.base >= ramBase && regs._gdt.base <= ramBase + ramSize - 1) {
	    // GDT is in RAM
	    gdtEntry = *(uint64_t *)&ram[regs._gdt.base - ramBase + regs._cs.selector];
    }
    else if (regs._gdt.base >= romBase && regs._gdt.base <= romBase + romSize - 1) {
	    // GDT is in ROM
	    gdtEntry = *(uint64_t *)&rom[regs._gdt.base - romBase + regs._cs.selector];
    }

    // Fill in the rest of the CS info with data from the GDT entry
    regs._cs.ar = ((gdtEntry >> 40) & 0xf0ff);
    regs._cs.base = ((gdtEntry >> 16) & 0xfffff) | (((gdtEntry >> 56) & 0xff) << 20);
    regs._cs.limit = ((gdtEntry & 0xffff) | (((gdtEntry >> 48) & 0xf) << 16));
    if (regs._cs.ar & 0x8000) {
	    // 4 KB pages
	    regs._cs.limit = (regs._cs.limit << 12) | 0xfff;
    }

    vcpu->SetRegisters(&regs);

    // Run the CPU again!
    vcpu->Run();
    #endif

    #ifdef DO_MANUAL_PAGING
    // Prepare the registers
    vcpu->GetRegisters(&regs);
    regs._eax = 0;
    regs._esi = 0x10000000;
    regs._eip = 0xffffffc0;
    regs._cr0 = 0xe0000011;
    regs._cr3 = 0x1000;
    regs._ss.selector = regs._ds.selector = regs._es.selector = 0x0010; 
    regs._ss.limit = regs._ds.limit = regs._es.limit = 0xffffffff;
    regs._ss.base = regs._ds.base = regs._es.base = 0;
    regs._ss.ar = regs._ds.ar = regs._es.ar = 0xc093;

    vcpu->SetRegisters(&regs);

    // Clear page directory
    memset(&ram[0x1000], 0, 0x1000);
	
    // Write 0xdeadbeef at physical memory address 0x5000
    *(uint32_t *)&ram[0x5000] = 0xdeadbeef;

    // Identity map the RAM to 0x00000000
    for (uint32_t i = 0; i < 0x100; i++) {
	    *(uint32_t *)&ram[0x2000 + i * 4] = 0x0003 + i * 0x1000;
    }

    // Identity map the ROM
    for (uint32_t i = 0; i < 0x10; i++) {
	    *(uint32_t *)&ram[0x3fc0 + i * 4] = 0xffff0003 + i * 0x1000;
    }

    // Map physical address 0x5000 to virtual address 0x10000000
    *(uint32_t *)&ram[0x4000] = 0x5003;

    // Map physical address 0x6000 to virtual address 0x10001000
    *(uint32_t *)&ram[0x4004] = 0x6003;

    // Map physical address 0xe0000000 to virtual address 0xe0000000
    *(uint32_t *)&ram[0xe000] = 0xe0000003;

    // Add page tables into page directory
    *(uint32_t *)&ram[0x1000] = 0x2003;
    *(uint32_t *)&ram[0x1ffc] = 0x3003;
    *(uint32_t *)&ram[0x1100] = 0x4003;
    *(uint32_t *)&ram[0x1e00] = 0xe003;

    // Run the CPU again!
    vcpu->Run();
    #endif

    // ----- First part -------------------------------------------------------------------------------------------------------

    printf("Testing data in virtual memory\n\n");

    // Get CPU status
    auto tunnel = vcpu->Tunnel();
    switch (tunnel->_exit_status) {
    case HAX_EXIT_HLT:
	    printf("Emulation exited due to HLT instruction as expected!\n");
	    break;
    default:
	    printf("Emulation exited for another reason: %d\n", tunnel->_exit_status);
	    break;
    }

    // Get CPU registers again
    vcpuStatus = vcpu->GetRegisters(&regs);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU registers: %d\n", vcpu->GetLastError()); return -1;
    }

    // Get FPU registers again
    vcpuStatus = vcpu->GetFPURegisters(&fpu);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU floating point registers: %d\n", vcpu->GetLastError()); return -1;
    }

    // Validate first stop output
    if (regs._eip == 0xffffffc3 && regs._cs.selector == 0x0008) {
	    printf("Emulation stopped at the right place!\n");
	    if (regs._eax == 0xdeadbeef) {
		    printf("And we got the right result!\n");
	    }
    }

    printf("\nFirst stop CPU register state:\n");
    printRegs(&regs);
    //printFPURegs(&fpu);
    printf("\n");

    // ----- Second part ------------------------------------------------------------------------------------------------------
	
    printf("Testing code in virtual memory\n\n");

    // Run CPU once more
    vcpu->Run();
    switch (tunnel->_exit_status) {
    case HAX_EXIT_HLT:
	    printf("Emulation exited due to HLT instruction as expected!\n");
	    break;
    default:
	    printf("Emulation exited for another reason: %d\n", tunnel->_exit_status);
	    break;
    }

    // Refresh CPU registers
    vcpuStatus = vcpu->GetRegisters(&regs);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU registers: %d\n", vcpu->GetLastError()); return -1;
    }

    // Refresh FPU registers
    vcpuStatus = vcpu->GetFPURegisters(&fpu);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU floating point registers: %d\n", vcpu->GetLastError()); return -1;
    }

    // Validate second stop output
    if (regs._eip == 0x10000013) {
	    printf("Emulation stopped at the right place!\n");
	    uint32_t memValue = *(uint32_t *)&ram[0x5000];
	    if (regs._eax == 0xcc99e897 && regs._edx == 0x12345678 && memValue == 0xcc99e897) {
		    printf("And we got the right result!\n");
	    }
    }

    printf("\nCPU register state:\n");
    printRegs(&regs);
    //printFPURegs(&fpu);
    printf("\n");

    // ----- Stack ------------------------------------------------------------------------------------------------------------

    printf("Testing the stack\n\n");

    // Run CPU once more
    vcpu->Run();
    switch (tunnel->_exit_status) {
    case HAX_EXIT_HLT:
	    printf("Emulation exited due to HLT instruction as expected!\n");
	    break;
    default:
	    printf("Emulation exited for another reason: %d\n", tunnel->_exit_status);
	    break;
    }

    // Refresh CPU registers
    vcpuStatus = vcpu->GetRegisters(&regs);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU registers: %d\n", vcpu->GetLastError()); return -1;
    }

    // Refresh FPU registers
    vcpuStatus = vcpu->GetFPURegisters(&fpu);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU floating point registers: %d\n", vcpu->GetLastError()); return -1;
    }

    // Validate stack results
    if (regs._eip == 0x10000021) {
	    printf("Emulation stopped at the right place!\n");
	    uint32_t memValue = *(uint32_t *)&ram[0xffffc];
	    if (regs._edx == 0xf00dcafe && regs._esp == 0x00100000 && memValue == 0xf00dcafe) {
		    printf("And we got the right result!\n");
	    }
    }

    printf("\nCPU register state:\n");
    printRegs(&regs);
    //printFPURegs(&fpu);
    printf("\n");

    // ----- Interrupts -------------------------------------------------------------------------------------------------------

    printf("Testing interrupts\n\n");
	
    // First stop at the HLT inside INT 0x21
    vcpu->Run();
    switch (tunnel->_exit_status) {
    case HAX_EXIT_HLT:
	    printf("Emulation exited due to HLT instruction as expected!\n");
	    break;
    default:
	    printf("Emulation exited for another reason: %d\n", tunnel->_exit_status);
	    break;
    }

    // Refresh CPU registers
    vcpuStatus = vcpu->GetRegisters(&regs);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU registers: %d\n", vcpu->GetLastError()); return -1;
    }

    // Refresh FPU registers
    vcpuStatus = vcpu->GetFPURegisters(&fpu);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU floating point registers: %d\n", vcpu->GetLastError()); return -1;
    }

    // Validate registers
    if (regs._eip == 0x10001002) {
	    printf("Emulation stopped at the right place!\n");
    }

    printf("\nCPU register state:\n");
    printRegs(&regs);
    //printFPURegs(&fpu);
    printf("\n");

	
    // Now we should hit the HLT after INT 0x21
    vcpu->Run();
    switch (tunnel->_exit_status) {
    case HAX_EXIT_HLT:
	    printf("Emulation exited due to HLT instruction as expected!\n");
	    break;
    default:
	    printf("Emulation exited for another reason: %d\n", tunnel->_exit_status);
	    break;
    }

    // Refresh CPU registers
    vcpuStatus = vcpu->GetRegisters(&regs);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU registers: %d\n", vcpu->GetLastError()); return -1;
    }

    // Refresh FPU registers
    vcpuStatus = vcpu->GetFPURegisters(&fpu);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU floating point registers: %d\n", vcpu->GetLastError()); return -1;
    }

    // Validate registers
    if (regs._eip == 0x10000026) {
	    printf("Emulation stopped at the right place!\n");
    }

    printf("\nCPU register state:\n");
    printRegs(&regs);
    //printFPURegs(&fpu);
    printf("\n");


    // Enable interrupts
    regs._eflags |= 0x200;
    vcpu->SetRegisters(&regs);

    // Do an INT 0x21 from the host
    vcpu->Interrupt(0x21);
    vcpu->Run();

    switch (tunnel->_exit_status) {
    case HAX_EXIT_HLT:
	    printf("Emulation exited due to HLT instruction as expected!\n");
	    break;
    default:
	    printf("Emulation exited for another reason: %d\n", tunnel->_exit_status);
	    break;
    }

    // Refresh CPU registers
    vcpuStatus = vcpu->GetRegisters(&regs);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU registers: %d\n", vcpu->GetLastError()); return -1;
    }

    // Refresh FPU registers
    vcpuStatus = vcpu->GetFPURegisters(&fpu);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU floating point registers: %d\n", vcpu->GetLastError()); return -1;
    }

    printf("\nCPU register state:\n");
    printRegs(&regs);
    //printFPURegs(&fpu);
    printf("\n");
    
    // ----- PMIO -------------------------------------------------------------------------------------------------------------

    printf("Testing PMIO\n\n");

    // Run CPU until 8-bit IN
    vcpu->Run();

    switch (tunnel->_exit_status) {
    case HAX_EXIT_IO: {
	    printf("Emulation exited due to PMIO as expected!\n");
	    if (tunnel->io._direction == HAX_IO_IN && tunnel->io._port == 0x1000 && tunnel->io._size == 1 && tunnel->io._count == 1) {
		    printf("And we got the right address and direction!\n");
            *(uint8_t*)vcpu->IOTunnel() = 0xac;
	    }
	    break;
    }
    default:
	    printf("Emulation exited for another reason: %d\n", tunnel->_exit_status);
	    break;
    }

    // Refresh CPU registers
    vcpuStatus = vcpu->GetRegisters(&regs);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU registers: %d\n", vcpu->GetLastError()); return -1;
    }

    // Refresh FPU registers
    vcpuStatus = vcpu->GetFPURegisters(&fpu);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU floating point registers: %d\n", vcpu->GetLastError()); return -1;
    }

    printf("\nCPU register state:\n");
    printRegs(&regs);
    //printFPURegs(&fpu);
    printf("\n");

    // Run CPU until 8-bit OUT
    vcpu->Run();

    switch (tunnel->_exit_status) {
    case HAX_EXIT_IO: {
        printf("Emulation exited due to PMIO as expected!\n");
        if (tunnel->io._direction == HAX_IO_OUT && tunnel->io._port == 0x1001 && tunnel->io._size == 1 && tunnel->io._count == 1) {
            printf("And we got the right address and direction!\n");
            uint8_t val = *(uint8_t*)vcpu->IOTunnel();
            if (val == 0x53) {
                printf("And the right result too!\n");
            }
        }
        break;
    }
    default:
        printf("Emulation exited for another reason: %d\n", tunnel->_exit_status);
        break;
    }

    // Refresh CPU registers
    vcpuStatus = vcpu->GetRegisters(&regs);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU registers: %d\n", vcpu->GetLastError()); return -1;
    }

    // Refresh FPU registers
    vcpuStatus = vcpu->GetFPURegisters(&fpu);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU floating point registers: %d\n", vcpu->GetLastError()); return -1;
    }

    printf("\nCPU register state:\n");
    printRegs(&regs);
    //printFPURegs(&fpu);
    printf("\n");

    // Run CPU until 16-bit IN
    vcpu->Run();

    switch (tunnel->_exit_status) {
    case HAX_EXIT_IO: {
        printf("Emulation exited due to PMIO as expected!\n");
        if (tunnel->io._direction == HAX_IO_IN && tunnel->io._port == 0x1002 && tunnel->io._size == 2 && tunnel->io._count == 1) {
            printf("And we got the right address and direction!\n");
            *(uint16_t*)vcpu->IOTunnel() = 0xfade;
        }
        break;
    }
    default:
        printf("Emulation exited for another reason: %d\n", tunnel->_exit_status);
        break;
    }

    // Refresh CPU registers
    vcpuStatus = vcpu->GetRegisters(&regs);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU registers: %d\n", vcpu->GetLastError()); return -1;
    }

    // Refresh FPU registers
    vcpuStatus = vcpu->GetFPURegisters(&fpu);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU floating point registers: %d\n", vcpu->GetLastError()); return -1;
    }

    printf("\nCPU register state:\n");
    printRegs(&regs);
    //printFPURegs(&fpu);
    printf("\n");

    // Run CPU until 16-bit OUT
    vcpu->Run();

    switch (tunnel->_exit_status) {
    case HAX_EXIT_IO: {
        printf("Emulation exited due to PMIO as expected!\n");
        if (tunnel->io._direction == HAX_IO_OUT && tunnel->io._port == 0x1003 && tunnel->io._size == 2 && tunnel->io._count == 1) {
            printf("And we got the right address and direction!\n");
            uint16_t val = *(uint16_t*)vcpu->IOTunnel();
            if (val == 0x0521) {
                printf("And the right result too!\n");
            }
        }
        break;
    }
    default:
        printf("Emulation exited for another reason: %d\n", tunnel->_exit_status);
        break;
    }

    // Refresh CPU registers
    vcpuStatus = vcpu->GetRegisters(&regs);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU registers: %d\n", vcpu->GetLastError()); return -1;
    }

    // Refresh FPU registers
    vcpuStatus = vcpu->GetFPURegisters(&fpu);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU floating point registers: %d\n", vcpu->GetLastError()); return -1;
    }

    printf("\nCPU register state:\n");
    printRegs(&regs);
    //printFPURegs(&fpu);
    printf("\n");

    // Run CPU until 32-bit IN
    vcpu->Run();

    switch (tunnel->_exit_status) {
    case HAX_EXIT_IO: {
        printf("Emulation exited due to PMIO as expected!\n");
        if (tunnel->io._direction == HAX_IO_IN && tunnel->io._port == 0x1004 && tunnel->io._size == 4 && tunnel->io._count == 1) {
            printf("And we got the right address and direction!\n");
            *(uint32_t*)vcpu->IOTunnel() = 0xfeedbabe;
        }
        break;
    }
    default:
        printf("Emulation exited for another reason: %d\n", tunnel->_exit_status);
        break;
    }

    // Refresh CPU registers
    vcpuStatus = vcpu->GetRegisters(&regs);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU registers: %d\n", vcpu->GetLastError()); return -1;
    }

    // Refresh FPU registers
    vcpuStatus = vcpu->GetFPURegisters(&fpu);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU floating point registers: %d\n", vcpu->GetLastError()); return -1;
    }

    printf("\nCPU register state:\n");
    printRegs(&regs);
    //printFPURegs(&fpu);
    printf("\n");

    // Run CPU until 8-bit OUT
    vcpu->Run();

    switch (tunnel->_exit_status) {
    case HAX_EXIT_IO: {
        printf("Emulation exited due to PMIO as expected!\n");
        if (tunnel->io._direction == HAX_IO_OUT && tunnel->io._port == 0x1005 && tunnel->io._size == 4 && tunnel->io._count == 1) {
            printf("And we got the right address and direction!\n");
            uint32_t val = *(uint32_t*)vcpu->IOTunnel();
            if (val == 0x01124541) {
                printf("And the right result too!\n");
            }
        }
        break;
    }
    default:
        printf("Emulation exited for another reason: %d\n", tunnel->_exit_status);
        break;
    }

    // Refresh CPU registers
    vcpuStatus = vcpu->GetRegisters(&regs);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU registers: %d\n", vcpu->GetLastError()); return -1;
    }

    // Refresh FPU registers
    vcpuStatus = vcpu->GetFPURegisters(&fpu);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU floating point registers: %d\n", vcpu->GetLastError()); return -1;
    }

    printf("\nCPU register state:\n");
    printRegs(&regs);
    //printFPURegs(&fpu);
    printf("\n");

    // ----- MMIO -------------------------------------------------------------------------------------------------------------

    printf("Testing MMIO\n\n");

    // Run CPU. Will leave "hardware" INT 0x21 and continue into the MMIO code
    vcpu->Run();

    switch (tunnel->_exit_status) {
    case HAX_EXIT_FAST_MMIO: {
	    printf("Emulation exited due to fast MMIO as expected!\n");
	    hax_fastmmio *mmio = (hax_fastmmio*)vcpu->IOTunnel();
	    if (mmio->direction == HAX_IO_OUT && mmio->gpa == 0xe0000000) {
		    printf("And we got the right address and direction!\n");
		    mmio->value = 0xbaadc0de;
	    }
	    break;
    }
    case HAX_EXIT_MMIO: {
	    // TODO: direction? value?
	    printf("Emulation exited due to MMIO as expected!\n");
	    if (tunnel->mmio.gla == 0xe0000000) {
		    printf("And we got the right address!\n");
	    }
	    break;
    }
    default:
	    printf("Emulation exited for another reason: %d\n", tunnel->_exit_status);
	    break;
    }

    // Refresh CPU registers
    vcpuStatus = vcpu->GetRegisters(&regs);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU registers: %d\n", vcpu->GetLastError()); return -1;
    }

    // Refresh FPU registers
    vcpuStatus = vcpu->GetFPURegisters(&fpu);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU floating point registers: %d\n", vcpu->GetLastError()); return -1;
    }

    printf("\nCPU register state:\n");
    printRegs(&regs);
    //printFPURegs(&fpu);
    printf("\n");

    // Will now hit the MMIO read
    vcpu->Run();

    switch (tunnel->_exit_status) {
    case HAX_EXIT_FAST_MMIO: {
	    printf("Emulation exited due to fast MMIO as expected!\n");
	    hax_fastmmio *mmio = (hax_fastmmio*)vcpu->IOTunnel();
	    if (mmio->direction == HAX_IO_IN && mmio->gpa == 0xe0000004, mmio->value == 0xbaadc0de) {
		    printf("And we got the right address, direction and value!\n");
	    }
	    break;
    }
    case HAX_EXIT_MMIO: {
	    // TODO: direction? value?
	    printf("Emulation exited due to MMIO as expected!\n");
	    if (tunnel->mmio.gla == 0xe0000000) {
		    printf("And we got the right address!\n");
	    }
	    break;
    }
    default:
	    printf("Emulation exited for another reason: %d\n", tunnel->_exit_status);
	    break;
    }

    // Refresh CPU registers
    vcpuStatus = vcpu->GetRegisters(&regs);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU registers: %d\n", vcpu->GetLastError()); return -1;
    }

    // Refresh FPU registers
    vcpuStatus = vcpu->GetFPURegisters(&fpu);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU floating point registers: %d\n", vcpu->GetLastError()); return -1;
    }

    printf("\nCPU register state:\n");
    printRegs(&regs);
    //printFPURegs(&fpu);
    printf("\n");

    // Will now hit the first part of TEST instruction with MMIO address
    vcpu->Run();

    switch (tunnel->_exit_status) {
    case HAX_EXIT_FAST_MMIO: {
	    printf("Emulation exited due to fast MMIO as expected!\n");
	    hax_fastmmio *mmio = (hax_fastmmio*)vcpu->IOTunnel();
	    if (mmio->direction == HAX_IO_IN && mmio->gpa == 0xe0000004, mmio->value == 0xbaadc0de) {
		    printf("And we got the right address, direction and value!\n");
	    }
	    break;
    }
    case HAX_EXIT_MMIO: {
	    // TODO: direction? value?
	    printf("Emulation exited due to MMIO as expected!\n");
	    if (tunnel->mmio.gla == 0xe0000000) {
		    printf("And we got the right address!\n");
	    }
	    break;
    }
    case HAX_EXIT_STATECHANGE: {
	    // https://github.com/intel/haxm/issues/12
	    // haxm_panic:Unexpected MMIO instruction (opcode=0x85, exit_instr_length=2, num=0, gpa=0xe0000004, instr[0..5]=0x85 0xf 0xf4 0x0 0x0 0x0)
	    printf("Emulation exited due to a HAXM bug; exit_reason = 0x%x\n", tunnel->_exit_reason);
	    printf("Kernel debug log will probably mention Unexpected MMIO instruction\n");
	    break;
    }
    default:
	    printf("Emulation exited for another reason: %d\n", tunnel->_exit_status);
	    break;
    }

    // Refresh CPU registers
    vcpuStatus = vcpu->GetRegisters(&regs);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU registers: %d\n", vcpu->GetLastError()); return -1;
    }

    // Refresh FPU registers
    vcpuStatus = vcpu->GetFPURegisters(&fpu);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU floating point registers: %d\n", vcpu->GetLastError()); return -1;
    }

    printf("\nCPU register state:\n");
    printRegs(&regs);
    //printFPURegs(&fpu);
    printf("\n");

    // Will now hit the second part of TEST instruction with MMIO address
    vcpu->Run();

    switch (tunnel->_exit_status) {
    case HAX_EXIT_FAST_MMIO: {
        printf("Emulation exited due to fast MMIO as expected!\n");
        hax_fastmmio *mmio = (hax_fastmmio*)vcpu->IOTunnel();
        if (mmio->direction == HAX_IO_OUT && mmio->gpa == 0xe0000004, mmio->value == 0xbaadc0de) {
            printf("And we got the right address, direction and value!\n");
        }
        break;
    }
    case HAX_EXIT_MMIO: {
        // TODO: direction? value?
        printf("Emulation exited due to MMIO as expected!\n");
        if (tunnel->mmio.gla == 0xe0000000) {
            printf("And we got the right address!\n");
        }
        break;
    }
    case HAX_EXIT_STATECHANGE: {
        // https://github.com/intel/haxm/issues/12
        // haxm_panic:Unexpected MMIO instruction (opcode=0x85, exit_instr_length=2, num=0, gpa=0xe0000004, instr[0..5]=0x85 0xf 0xf4 0x0 0x0 0x0)
        printf("Emulation exited due to a HAXM bug; exit_reason = 0x%x\n", tunnel->_exit_reason);
        printf("Kernel debug log will probably mention Unexpected MMIO instruction\n");
        break;
    }
    default:
        printf("Emulation exited for another reason: %d\n", tunnel->_exit_status);
        break;
    }

    // Refresh CPU registers
    vcpuStatus = vcpu->GetRegisters(&regs);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU registers: %d\n", vcpu->GetLastError()); return -1;
    }

    // Refresh FPU registers
    vcpuStatus = vcpu->GetFPURegisters(&fpu);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU floating point registers: %d\n", vcpu->GetLastError()); return -1;
    }

    printf("\nCPU register state:\n");
    printRegs(&regs);
    //printFPURegs(&fpu);
    printf("\n");

    // ----- Single stepping --------------------------------------------------------------------------------------------------

    printf("Testing single stepping\n\n");

    // Step CPU
    vcpu->Step();

    // Refresh CPU registers
    vcpuStatus = vcpu->GetRegisters(&regs);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU registers: %d\n", vcpu->GetLastError()); return -1;
    }

    // Refresh FPU registers
    vcpuStatus = vcpu->GetFPURegisters(&fpu);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU floating point registers: %d\n", vcpu->GetLastError()); return -1;
    }

    switch (tunnel->_exit_status) {
    case HAX_EXIT_DEBUG: {
        printf("Emulation exited due to single stepping as expected!\n");
        if (tunnel->debug.rip == 0x1000005d) {
            printf("And stopped at the right place!\n");
        }
        if (regs._ecx == 0x11) {
            printf("And got the right result!\n");
        }
        printf("DR6 = %08x  DR7 = %08x\n", tunnel->debug.dr6, tunnel->debug.dr7);
        break;
    }
    default:
        printf("Emulation exited for another reason: %d\n", tunnel->_exit_status);
        break;
    }

    printf("\nCPU register state:\n");
    printRegs(&regs);
    //printFPURegs(&fpu);
    printf("\n");

    // Step CPU
    vcpu->Step();

    // Refresh CPU registers
    vcpuStatus = vcpu->GetRegisters(&regs);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU registers: %d\n", vcpu->GetLastError()); return -1;
    }

    // Refresh FPU registers
    vcpuStatus = vcpu->GetFPURegisters(&fpu);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU floating point registers: %d\n", vcpu->GetLastError()); return -1;
    }

    switch (tunnel->_exit_status) {
    case HAX_EXIT_DEBUG: {
        printf("Emulation exited due to single stepping as expected!\n");
        if (tunnel->debug.rip == 0x10000062) {
            printf("And stopped at the right place!\n");
        }
        if (regs._ecx == 0x2200) {
            printf("And got the right result!\n");
        }
        printf("DR6 = %08x  DR7 = %08x\n", tunnel->debug.dr6, tunnel->debug.dr7);
        break;
    }
    default:
        printf("Emulation exited for another reason: %d\n", tunnel->_exit_status);
        break;
    }

    printf("\nCPU register state:\n");
    printRegs(&regs);
    //printFPURegs(&fpu);
    printf("\n");

    // Step CPU
    vcpu->Step();

    // Refresh CPU registers
    vcpuStatus = vcpu->GetRegisters(&regs);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU registers: %d\n", vcpu->GetLastError()); return -1;
    }

    // Refresh FPU registers
    vcpuStatus = vcpu->GetFPURegisters(&fpu);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU floating point registers: %d\n", vcpu->GetLastError()); return -1;
    }

    switch (tunnel->_exit_status) {
    case HAX_EXIT_DEBUG: {
        printf("Emulation exited due to single stepping as expected!\n");
        if (tunnel->debug.rip == 0x10000067) {
            printf("And stopped at the right place!\n");
        }
        if (regs._ecx == 0x330000) {
            printf("And got the right result!\n");
        }
        printf("DR6 = %08x  DR7 = %08x\n", tunnel->debug.dr6, tunnel->debug.dr7);
        break;
    }
    default:
        printf("Emulation exited for another reason: %d\n", tunnel->_exit_status);
        break;
    }

    printf("\nCPU register state:\n");
    printRegs(&regs);
    //printFPURegs(&fpu);
    printf("\n");

    // Step CPU
    vcpu->Step();

    // Refresh CPU registers
    vcpuStatus = vcpu->GetRegisters(&regs);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU registers: %d\n", vcpu->GetLastError()); return -1;
    }

    // Refresh FPU registers
    vcpuStatus = vcpu->GetFPURegisters(&fpu);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU floating point registers: %d\n", vcpu->GetLastError()); return -1;
    }

    switch (tunnel->_exit_status) {
    case HAX_EXIT_DEBUG: {
        printf("Emulation exited due to single stepping as expected!\n");
        if (tunnel->debug.rip == 0x1000006c) {
            printf("And stopped at the right place!\n");
        }
        if (regs._ecx == 0x44000000) {
            printf("And got the right result!\n");
        }
        printf("DR6 = %08x  DR7 = %08x\n", tunnel->debug.dr6, tunnel->debug.dr7);
        break;
    }
    default:
        printf("Emulation exited for another reason: %d\n", tunnel->_exit_status);
        break;
    }

    printf("\nCPU register state:\n");
    printRegs(&regs);
    //printFPURegs(&fpu);
    printf("\n");

    // ----- Software breakpoints ---------------------------------------------------------------------------------------------
    
    // Enable software breakpoints and place a breakpoint
    vcpuStatus = vcpu->EnableSoftwareBreakpoints(true);
    if (vcpuStatus != HXVCPUS_SUCCESS) {
        printf("Failed to enable software breakpoints: %d\n", vcpu->GetLastError());
        return -1;
    }
    uint8_t swBpBackup = ram[0x5071];
    ram[0x5071] = 0xCC;
    
    // Run CPU. Should hit the breakpoint
    vcpu->Run();

    // Refresh CPU registers
    vcpuStatus = vcpu->GetRegisters(&regs);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU registers: %d\n", vcpu->GetLastError()); return -1;
    }

    // Refresh FPU registers
    vcpuStatus = vcpu->GetFPURegisters(&fpu);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU floating point registers: %d\n", vcpu->GetLastError()); return -1;
    }

    switch (tunnel->_exit_status) {
    case HAX_EXIT_DEBUG: {
        printf("Emulation exited due to software breakpoint as expected!\n");
        if (tunnel->debug.rip == 0x10000071) {
            printf("And triggered the correct breakpoint!\n");
        }
        if (regs._eip == 0x10000071) {
            printf("And stopped at the right place!\n");
        }
        if (regs._ecx == 0x000000ff) {
            printf("And got the right result!\n");
        }
        printf("DR6 = %08x  DR7 = %08x\n", tunnel->debug.dr6, tunnel->debug.dr7);
        break;
    }
    default:
        printf("Emulation exited for another reason: %d\n", tunnel->_exit_status);
        break;
    }

    printf("\nCPU register state:\n");
    printRegs(&regs);
    //printFPURegs(&fpu);
    printf("\n");

    // Disable software breakpoints and revert instruction
    vcpuStatus = vcpu->EnableSoftwareBreakpoints(false);
    if (vcpuStatus != HXVCPUS_SUCCESS) {
        printf("Failed to disable software breakpoints: %d\n", vcpu->GetLastError());
        return -1;
    }
    ram[0x5071] = swBpBackup;

    // ----- Hardware breakpoints ---------------------------------------------------------------------------------------------

    // Place hardware breakpoint
    HaxmHardwareBreakpoint bps[4] = { 0 };
    bps[0].address = 0x1000007b;
    bps[0].localEnable = true;
    bps[0].globalEnable = false;
    bps[0].trigger = HXBPT_EXECUTION;
    bps[0].length = HXBPL_1_BYTE;
    vcpuStatus = vcpu->SetHardwareBreakpoints(bps);
    if (vcpuStatus != HXVCPUS_SUCCESS) {
        printf("Failed to set hardware breakpoint: %d\n", vcpu->GetLastError());
        return -1;
    }

    // Run CPU. Should hit the breakpoint
    vcpu->Run();

    // Refresh CPU registers
    vcpuStatus = vcpu->GetRegisters(&regs);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU registers: %d\n", vcpu->GetLastError()); return -1;
    }

    // Refresh FPU registers
    vcpuStatus = vcpu->GetFPURegisters(&fpu);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU floating point registers: %d\n", vcpu->GetLastError()); return -1;
    }

    switch (tunnel->_exit_status) {
    case HAX_EXIT_DEBUG: {
        printf("Emulation exited due to hardware breakpoint as expected!\n");
        if (tunnel->debug.dr6 == 1) {
            printf("And triggered the correct breakpoint!\n");
        }
        if (regs._eip == 0x1000007b) {
            printf("And stopped at the right place!\n");
        }
        if (regs._ecx == 0x00dd0000) {
            printf("And got the right result!\n");
        }
        printf("DR6 = %08x  DR7 = %08x\n", tunnel->debug.dr6, tunnel->debug.dr7);
        break;
    }
    default:
        printf("Emulation exited for another reason: %d\n", tunnel->_exit_status);
        break;
    }

    printf("\nCPU register state:\n");
    printRegs(&regs);
    //printFPURegs(&fpu);
    printf("\n");

    // Clear hardware breakpoints
    vcpu->ClearHardwareBreakpoints();
    printf("Hardware breakpoints cleared\n");

    // Run CPU. Should continue to the end
    vcpu->Run();

    // Refresh CPU registers
    vcpuStatus = vcpu->GetRegisters(&regs);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU registers: %d\n", vcpu->GetLastError()); return -1;
    }

    // Refresh FPU registers
    vcpuStatus = vcpu->GetFPURegisters(&fpu);
    switch (vcpuStatus) {
    case HXVCPUS_FAILED: printf("Failed to get VCPU floating point registers: %d\n", vcpu->GetLastError()); return -1;
    }

    printf("\nCPU register state:\n");
    printRegs(&regs);
    //printFPURegs(&fpu);
    printf("\n");

    // ----- End --------------------------------------------------------------------------------------------------------------
    
    printf("\nFinal CPU register state:\n");
    printRegs(&regs);
    //printFPURegs(&fpu);

    _aligned_free(rom);
    _aligned_free(ram);
	
    return 0;
}
