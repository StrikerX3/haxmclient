#include "hax_interface.h"

#include <cstdio>
#include <Windows.h>

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
	HANDLE hHAXM = CreateFileW(L"\\\\.\\HAX", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hHAXM == INVALID_HANDLE_VALUE) {
		printf("Failed to open HAXM device: %d\n", GetLastError());
		return -1;
	}

	const uint32_t ramSize = 256 * 4096; // 1 MB
	const uint32_t romSize = 16 * 4096; // 64 KB

	int result = 0;
	DWORD returnSize;
	BOOL bResult;

	// Check version
	struct hax_module_version ver;
	bResult = DeviceIoControl(hHAXM,
		HAX_IOCTL_VERSION,
		NULL, 0,
		&ver, sizeof(ver),
		&returnSize,
		(LPOVERLAPPED)NULL);
	if (!bResult) {
		printf("Failed to read HAXM version information: %d\n", GetLastError());
		result = -1;
		goto exit;
	}

	printf("HAXM module loaded\n");
	printf("  Current version: %d\n", ver.cur_version);
	printf("  Compatibility version: %d\n", ver.compat_version);

	// Check capabilities
	struct hax_capabilityinfo caps;
	bResult = DeviceIoControl(hHAXM,
		HAX_IOCTL_CAPABILITY,
		NULL, 0,
		&caps, sizeof(caps),
		&returnSize,
		(LPOVERLAPPED)NULL);
	if (!bResult) {
		printf("Failed to read HAXM capabilities: %d\n", GetLastError());
		result = -1;
		goto exit;
	}

	printf("\nCapabilities:\n");
	if (caps.wstatus & HAX_CAP_STATUS_WORKING) {
		printf("  HAXM can be used on this host\n");
		if (caps.winfo & HAX_CAP_FASTMMIO) {
			printf("  HAXM kernel module supports fast MMIO\n");
		}
		if (caps.winfo & HAX_CAP_EPT) {
			printf("  Host CPU supports Extended Page Tables (EPT)\n");
		}
		if (caps.winfo & HAX_CAP_UG) {
			printf("  Host CPU supports Unrestricted Guest (UG)\n");
		}
		if (caps.winfo & HAX_CAP_64BIT_SETRAM) {
			printf("  64-bit RAM functionality is present\n");
		}
		if ((caps.wstatus & HAX_CAP_MEMQUOTA) && caps.mem_quota != 0) {
			printf("    Global memory quota enabled: %lld MB available\n", caps.mem_quota);
		}
	}
	else {
		printf("  HAXM cannot be used on this host\n");
		if (caps.winfo & HAX_CAP_FAILREASON_VT) {
			printf("  Intel VT-x not supported or disabled\n");
		}
		if (caps.winfo & HAX_CAP_FAILREASON_NX) {
			printf("  Intel Execute Disable Bit (NX) not supported or disabled\n");
		}
	}
	
	// ------------------------------------------------------------------------

	// Now let's have some fun!

	// Create a VM
	uint32_t vmID;
	bResult = DeviceIoControl(hHAXM,
		HAX_IOCTL_CREATE_VM,
		NULL, 0,
		&vmID, sizeof(vmID),
		&returnSize,
		(LPOVERLAPPED)NULL);
	if (!bResult) {
		printf("Failed to create VM: %d\n", GetLastError());
		result = -1;
		goto exit;
	}

	printf("\nVM created: ID %x\n", vmID);

	wchar_t vmName[100];
	swprintf_s(vmName, L"\\\\.\\hax_vm%02d", vmID);
	HANDLE hVM;
	hVM = CreateFileW(vmName, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hVM == INVALID_HANDLE_VALUE) {
		printf("Failed to open VM device: %d\n", GetLastError());
		result = -1;
		goto exit;
	}

	// Report QEMU API version 4 to enable fast MMIO
	if (caps.winfo & HAX_CAP_FASTMMIO) {
		struct hax_qemu_version qversion;
		qversion.cur_version = 0x4;
		qversion.least_version = 0x1;
		bResult = DeviceIoControl(hVM,
			HAX_VM_IOCTL_NOTIFY_QEMU_VERSION,
			&qversion, sizeof(qversion),
			NULL, 0,
			&returnSize,
			(LPOVERLAPPED)NULL);
		if (!bResult) {
			printf("Failed to notify QEMU API version: %d\n", GetLastError());
		}
		else {
			printf("Notified QEMU version 4; fast MMIO enabled!\n");
		}
	}

	// Add a virtual CPU to the VM
	uint32_t vm_vcpuID;
	vm_vcpuID = 0;
	bResult = DeviceIoControl(hVM,
		HAX_VM_IOCTL_VCPU_CREATE,
		&vm_vcpuID, sizeof(vm_vcpuID),
		NULL, 0,
		&returnSize,
		(LPOVERLAPPED)NULL);
	if (!bResult) {
		printf("Failed to create VCPU for VM: %d\n", GetLastError());
		result = -1;
		goto exitVM;
	}

	printf("VCPU created with ID %d\n", vm_vcpuID);

	wchar_t vcpuName[100];
	swprintf_s(vcpuName, L"\\\\.\\hax_vm%02d_vcpu%02d", vmID, vm_vcpuID);
	HANDLE hVCPU;
	hVCPU = CreateFileW(vcpuName, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hVM == INVALID_HANDLE_VALUE) {
		printf("Failed to open VCPU: %d\n", GetLastError());
		result = -1;
		goto exit;
	}

	// Allocate RAM
	char *ram;
	ram = (char *)_aligned_malloc(ramSize, 0x1000);
	memset(ram, 0, ramSize);

	struct hax_alloc_ram_info ramInfo;
	ramInfo.va = (uint64_t)ram;
	ramInfo.size = ramSize;
	bResult = DeviceIoControl(hVM,
		HAX_VM_IOCTL_ALLOC_RAM,
		&ramInfo, sizeof(ramInfo),
		NULL, 0,
		&returnSize,
		(LPOVERLAPPED)NULL);
	if (!bResult) {
		printf("Failed to allocate RAM for the VM\n");
		result = -1;
		goto exitVM;
	}

	printf("RAM allocated: %d bytes\n", ramSize);

	// Map the physical memory to address 0
	struct hax_set_ram_info setRamInfo;
	setRamInfo.pa_start = 0;
	setRamInfo.va = (uint64_t)ram;
	setRamInfo.size = ramSize;
	setRamInfo.flags = 0;
	bResult = DeviceIoControl(hVM,
		HAX_VM_IOCTL_SET_RAM,
		&setRamInfo, sizeof(setRamInfo),
		NULL, 0,
		&returnSize,
		(LPOVERLAPPED)NULL);
	if (!bResult) {
		printf("Failed to map RAM to address 0\n");
		result = -1;
		goto exitVM;
	}

	printf("RAM mapped to physical address 0x%08x\n", setRamInfo.pa_start);

	// Allocate ROM
	char *rom;
	rom = (char *)_aligned_malloc(romSize, 0x1000);
	memset(rom, 0xf4, romSize);

	struct hax_alloc_ram_info romInfo;
	romInfo.va = (uint64_t)rom;
	romInfo.size = romSize;
	bResult = DeviceIoControl(hVM,
		HAX_VM_IOCTL_ALLOC_RAM,
		&romInfo, sizeof(romInfo),
		NULL, 0,
		&returnSize,
		(LPOVERLAPPED)NULL);
	if (!bResult) {
		printf("Failed to allocate ROM for the VM\n");
		result = -1;
		goto exitROM;
	}

	printf("ROM allocated: %d bytes\n", romSize);

	// Map the ROM to address 0xFFFF0000 and mark it as ROM
	struct hax_set_ram_info setRomInfo;
	setRomInfo.pa_start = 0xFFFF0000;
	setRomInfo.va = (uint64_t)rom;
	setRomInfo.size = romSize;
	setRomInfo.flags = HAX_RAM_INFO_ROM;
	bResult = DeviceIoControl(hVM,
		HAX_VM_IOCTL_SET_RAM,
		&setRomInfo, sizeof(setRomInfo),
		NULL, 0,
		&returnSize,
		(LPOVERLAPPED)NULL);
	if (!bResult) {
		printf("Failed to map ROM to address 0xFFFF0000\n");
		result = -1;
		goto exitVM;
	}

	printf("ROM mapped to physical address 0x%08x\n", setRomInfo.pa_start);

	// Setup tunnel
	struct hax_tunnel_info tunnelInfo;
	bResult = DeviceIoControl(hVCPU,
		HAX_VCPU_IOCTL_SETUP_TUNNEL,
		NULL, 0,
		&tunnelInfo, sizeof(tunnelInfo),
		&returnSize,
		(LPOVERLAPPED)NULL);
	if (!bResult) {
		printf("Failed to setup VCPU tunnel: %d\n", GetLastError());
		result = -1;
		goto exitVM;
	}

	struct hax_tunnel *tunnel;
	tunnel = (struct hax_tunnel *) (intptr_t) tunnelInfo.va;
	unsigned char *ioTunnel;
	ioTunnel = (unsigned char *) (intptr_t) tunnelInfo.io_va;

	printf("VCPU tunnel setup\n");
	printf("  Virtual address: 0x%016llx\n", tunnelInfo.va);
	printf("  I/O virtual address: 0x%016llx\n", tunnelInfo.io_va);
	printf("  Size: %d bytes\n", tunnelInfo.size);

	// Get CPU registers
	struct vcpu_state_t regs;
	bResult = DeviceIoControl(hVCPU,
		HAX_VCPU_GET_REGS,
		NULL, 0,
		&regs, sizeof(regs),
		&returnSize,
		(LPOVERLAPPED)NULL);
	if (!bResult) {
		printf("Failed to read VCPU registers: %d\n", GetLastError());
		result = -1;
		goto exitVM;
	}
	
	// Get FPU registers
	struct fx_layout fpu;
	bResult = DeviceIoControl(hVCPU,
		HAX_VCPU_GET_REGS,
		NULL, 0,
		&fpu, sizeof(fpu),
		&returnSize,
		(LPOVERLAPPED)NULL);
	if (!bResult) {
		printf("Failed to read VCPU floating point registers: %d\n", GetLastError());
		result = -1;
		goto exitVM;
	}

	printf("\nInitial CPU register state:\n");
	printRegs(&regs);
	//printFPURegs(&fpu);
	printf("\n");

	// Manipulate CPU registers
	regs._bx = 0x1234;
	regs._cx = 0x8765;
	bResult = DeviceIoControl(hVCPU,
		HAX_VCPU_SET_REGS,
		&regs, sizeof(regs),
		NULL, 0,
		&returnSize,
		(LPOVERLAPPED)NULL);
	if (!bResult) {
		printf("Failed to write VCPU registers: %d\n", GetLastError());
		result = -1;
		goto exitVM;
	}

	printf("\CPU registers after manipulation:\n");
	printRegs(&regs);
	//printFPURegs(&fpu);
	printf("\n");

	// The CPU starts in 16-bit real mode.
	// Memory addressing is based on segments and offsets, where a segment is basically a 16-byte offset.

	// Write a simple program to RAM at CS:EIP
	{
		uint32_t addr = 0xfff0;
		#define emit(buf, code) {memcpy(&buf[addr], code, sizeof(code) - 1); addr += sizeof(code) - 1;}
		emit(rom, "\x01\xcb");   // add   bx, cx
		emit(rom, "\x31\xc9");   // xor   cx, cx
		emit(rom, "\xf4");       // hlt
		#undef emit
	}

	// Run the CPU!
	bResult = DeviceIoControl(hVCPU,
		HAX_VCPU_IOCTL_RUN,
		NULL, 0,
		NULL, 0,
		&returnSize,
		(LPOVERLAPPED)NULL);
	if (!bResult) {
		printf("Failed to run VCPU: %d\n", GetLastError());
		result = -1;
		goto exitVM;
	}
	
	switch (tunnel->_exit_status) {
	case HAX_EXIT_HLT:
		printf("Emulation exited due to HLT instruction as expected!\n");
		break;
	default:
		printf("Emulation exited for another reason: %d\n", tunnel->_exit_status);
		break;
	}

	// Get CPU registers again
	bResult = DeviceIoControl(hVCPU,
		HAX_VCPU_GET_REGS,
		NULL, 0,
		&regs, sizeof(regs),
		&returnSize,
		(LPOVERLAPPED)NULL);
	if (!bResult) {
		printf("Failed to read VCPU registers: %d\n", GetLastError());
		result = -1;
		goto exitVM;
	}

	// Get FPU registers again
	bResult = DeviceIoControl(hVCPU,
		HAX_VCPU_GET_REGS,
		NULL, 0,
		&fpu, sizeof(fpu),
		&returnSize,
		(LPOVERLAPPED)NULL);
	if (!bResult) {
		printf("Failed to read VCPU floating point registers: %d\n", GetLastError());
		result = -1;
		goto exitVM;
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

	// TODO: implement the following IOCTLs
	// https://github.com/intel/haxm/blob/master/API.md

	// HAX_IOCTL_SET_MEMLIMIT

	// HAX_VM_IOCTL_ADD_RAMBLOCK
	// HAX_VM_IOCTL_SET_RAM2

	// HAX_VCPU_IOCTL_SET_MSRS
	// HAX_VCPU_IOCTL_GET_MSRS

	// HAX_VCPU_IOCTL_SET_FPU
	
	// HAX_VCPU_IOCTL_INTERRUPT

exitROM:
	_aligned_free(rom);

exitRAM:
	_aligned_free(ram);

exitVM:
	// We must close the VM handle so that it is properly cleaned up
	CloseHandle(hVM);

exit:
	CloseHandle(hHAXM);

	return result;
}
