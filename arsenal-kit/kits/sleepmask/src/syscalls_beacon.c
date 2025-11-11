
#ifdef _M_IX86
__declspec(naked) BOOL local_is_wow64(void)
{
	asm(
		"mov eax, fs:[0xc0] \n"
		"test eax, eax \n"
		"jne wow64 \n"
		"mov eax, 0 \n"
		"ret \n"
		"wow64: \n"
		"mov eax, 1 \n"
		"ret \n"
	);
}
#endif

PVOID protectVirtualMemoryJmpAddr = NULL;
DWORD protectVirtualMemorySysnum = 0;

EXTERN_C BOOL initializeSyscalls() {
	BEACON_SYSCALLS info = {0};
	BOOL status = FALSE;

	// Get the system call information from beacon and resolve system call information if necessary
	status = BeaconGetSyscallInformation(&info, sizeof(BEACON_SYSCALLS), TRUE);

	// Validate the information that is returned.
	if (!status ||
		info.syscalls.ntProtectVirtualMemory.jmpAddr == NULL ||
		info.syscalls.ntProtectVirtualMemory.sysnum == 0) {
		return FALSE;
	}

	// Only save the information needed to support NtProtectVirtualMemory.
	protectVirtualMemoryJmpAddr = info.syscalls.ntProtectVirtualMemory.jmpAddr;
	protectVirtualMemorySysnum = info.syscalls.ntProtectVirtualMemory.sysnum;
	return TRUE;
}

EXTERN_C DWORD GetSyscallNumber()
{
	// Return the system call number for NtProtectVirtualMemory
	return protectVirtualMemorySysnum;
}

EXTERN_C PVOID GetSyscallAddress()
{
	// Return the system call jump address for NtProtectVirtualMemory
	return protectVirtualMemoryJmpAddr;
}

#if defined(__GNUC__)

__declspec(naked) NTSTATUS NtProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect)
{
	asm(
#if defined(_WIN64)
		"call GetSyscallAddress \n"
		"mov r11, rax \n"
		"call GetSyscallNumber \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push edi \n"
		"push ebx \n"
		"push ebp \n"
		"mov ebp, esp \n"
		"call _GetSyscallAddress \n"
		"mov edi, eax \n"
		"call _GetSyscallNumber \n"
		"mov ecx, 0x5 \n"
	"push_argument: \n"
		"dec ecx \n"
		"push [ebp + 16 + ecx * 4] \n"
		"jnz push_argument \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog] \n"
		"push ebx \n"
		"call do_sysenter_interrupt \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"pop ebx \n"
		"pop edi \n"
		"ret \n"
	"do_sysenter_interrupt: \n"
		"mov edx, esp \n"
		"call _local_is_wow64 \n"
		"test eax, eax \n"
		"je is_native \n"
		"add edx, 8 \n"
	"is_native: \n"
		"mov eax, ecx \n"
		"xor ecx, ecx \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

#endif