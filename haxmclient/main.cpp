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
			*(double *)&fpu->mmx_1[i][0],  *(double *)&fpu->mmx_1[i][8]
		);
	}
}

int main() {
	// Allocate memory for the RAM and ROM
	const uint32_t ramSize = 256 * 4096; // 1 MB
	const uint32_t ramBase = 0x00000000;
	const uint32_t romSize = 16 * 4096; // 64 KB
	const uint32_t romBase = 0xFFFF0000;

	char *ram;
	ram = (char *)_aligned_malloc(ramSize, 0x1000);
	memset(ram, 0, ramSize);

	char *rom;
	rom = (char *)_aligned_malloc(romSize, 0x1000);
	memset(rom, 0xf4, romSize);

	// Write a simple program to ROM
	{
		uint32_t addr = 0xfff0;
		#define emit(buf, code) {memcpy(&buf[addr], code, sizeof(code) - 1); addr += sizeof(code) - 1;}
		emit(rom, "\x01\xcb");   // add   bx, cx
		emit(rom, "\x31\xc9");   // xor   cx, cx
		emit(rom, "\xf4");       // hlt
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
	printf("    VCPU I/O tunnel allocated at 0x%016llx with %d bytes\n", (uint64_t)vcpu->IOTunnel(), vcpu->IOTunnelSize());
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
	
	printf("\nInitial CPU register state:\n");
	printRegs(&regs);
	//printFPURegs(&fpu);
	printf("\n");

	// Manipulate CPU registers
	regs._bx = 0x1234;
	regs._cx = 0x8765;
	vcpuStatus = vcpu->SetRegisters(&regs);
	switch (vcpuStatus) {
	case HXVCPUS_FAILED: printf("Failed to set VCPU registers: %d\n", vcpu->GetLastError()); return -1;
	}

	printf("\CPU registers after manipulation:\n");
	printRegs(&regs);
	//printFPURegs(&fpu);
	printf("\n");

	// The CPU starts in 16-bit real mode.
	// Memory addressing is based on segments and offsets, where a segment is basically a 16-byte offset.

	// Run the CPU!
	vcpu->Run();

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

	if (regs._eip == 0xfff5 && regs._cs.selector == 0xf000) {
		printf("Emulation stopped at the right place!\n");
		if (regs._bx == 0x1234 + 0x8765 && regs._cx == 0x0000) {
			printf("And we got the right result!\n");
		}
	}

	printf("\nFinal CPU register state:\n");
	printRegs(&regs);
	//printFPURegs(&fpu);

	_aligned_free(rom);
	_aligned_free(ram);
	
	return 0;
}
