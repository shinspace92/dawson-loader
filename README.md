# Dawson-Loader

> **CTE Tradition of Baking Products during TDYs**

## Overview

**Dawson-Loader** is a custom User-Defined Reflective Loader (uDRL) for Cobalt Strike that implements **jopcall** (ROP/JOP-based syscall obfuscation) for **both** the Beacon loading phase and runtime operations, providing comprehensive call stack spoofing throughout the entire Beacon lifecycle.

### Key Features

- ✅ **uDRL with Jopcall** - Obfuscates syscalls during Beacon loading
- ✅ **BeaconGate with Jopcall** - Obfuscates syscalls during Beacon runtime
- ✅ **16 Syscall Wrappers** - Covers all core NT APIs used by Beacon
- ✅ **Dynamic Gadget Discovery** - Finds ROP/JOP gadgets at runtime from ntdll
- ✅ **Randomized Gadget Selection** - Increases diversity to evade signatures
- ✅ **Cross-Architecture** - x64 support (x86 possible with modifications)

## Quick Start

### 1. Build DawsonLoader uDRL

```bash
# Prerequisites: mingw-w64
sudo apt install mingw-w64

# Build
make clean
make dawsonloader

# Output: dist/DawsonLoader.x64.o (25KB)
```

### 2. Start Cobalt Strike with Test Profile

```bash
# On your Cobalt Strike server
./teamserver <YOUR_IP> <PASSWORD> /path/to/dawson-loader/profiles/dawson-test.profile
```

### 3. Load in Cobalt Strike Client

1. Connect Cobalt Strike client to team server
2. Open **Script Manager** (Cobalt Strike → Script Manager)
3. Click **Load** and select: `dist/DawsonLoader.cna`
4. Verify script loaded: Check Script Console

### 4. Generate and Test Beacon

```
1. Cobalt Strike → Listeners → Add (create HTTPS listener)
2. Attacks → Packages → Windows Stageless Payload
3. Select: x64 EXE, your listener
4. Generate → Save as beacon_test.exe
5. Execute on test system
6. Beacon should call back with jopcall-obfuscated syscalls
```

**For detailed testing instructions**, see [TESTING_GUIDE.md](TESTING_GUIDE.md)

### Build Sleepmask-VS (BeaconGate)

**Option 1: Linux Build (Advanced)**

Due to the BOF-VS framework using Windows-style paths, Linux builds require preprocessing:

```bash
# Prerequisites
sudo apt install mingw-w64

# Initialize submodules
cd Sleepmask-VS
git submodule init && git submodule update

# Build (requires path preprocessing)
cd sleepmask-vs
# See Makefile.linux for build configuration
# Note: May require fixing backslash paths in library files
```

**Option 2: Windows Build (Recommended)**

Sleepmask-VS is designed for Windows/Visual Studio tooling:

1. Open `Sleepmask-VS/sleepmask-vs.sln` in Visual Studio 2022
2. Install Clang compiler for Windows (if not already)
3. Set build configuration to **Release, x64**
4. Build → Build Solution
5. Output: `x64/Release/jopcall-sleepmask.o`

For detailed Windows build instructions, see `Sleepmask-VS/README.md`.

## Documentation

📖 **Complete Guide**: See [JOPCALL_INTEGRATION_GUIDE.md](JOPCALL_INTEGRATION_GUIDE.md) for:
- Detailed architecture overview
- Technical deep dive into jopcall
- Cobalt Strike integration steps
- Troubleshooting and debugging
- Performance considerations
- Advanced customization options

## Project Structure

```
dawson-loader/
├── src/                          # uDRL source code
│   ├── DawsonLoader.c            # Main loader with jopcall integration
│   ├── DawsonLoader.h            # Headers and structures
│   └── jopcall_integration.c     # Gadget discovery functions
├── dist/                         # Build outputs
│   ├── DawsonLoader.x64.o        # Compiled uDRL object ✓
│   └── DawsonLoader.cna          # Aggressor script
├── Sleepmask-VS/                 # BeaconGate implementation
│   └── sleepmask-vs/
│       ├── jopcall-sleepmask.cpp             # Entry point
│       └── library/
│           ├── jopcallsyscalls.h             # Jopcall header
│           └── jopcallsyscalls.cpp           # Runtime jopcall
├── Makefile                      # Build system
├── README.md                     # This file
└── JOPCALL_INTEGRATION_GUIDE.md  # Comprehensive documentation
```

## How It Works

### Phase 1: Beacon Loading (uDRL)

```
┌─────────────────────────────────────────┐
│ 1. DawsonLoader initializes             │
│ 2. Scans ntdll for ROP/JOP gadgets      │
│ 3. Allocates memory with NtAllocateVM   │
│    via jop_syscall()                    │
│ 4. Maps Beacon sections                 │
│ 5. Changes protections with NtProtectVM │
│    via jop_syscall()                    │
│ 6. Transfers control to Beacon          │
└─────────────────────────────────────────┘
```

### Phase 2: Beacon Runtime (BeaconGate)

```
┌─────────────────────────────────────────┐
│ 1. Beacon calls VirtualAlloc()          │
│ 2. BeaconGate intercepts call           │
│ 3. Routes to _NtAllocateVirtualMemory() │
│ 4. Executes via DoJopSyscall()          │
│ 5. Returns through ROP gadget chain     │
│ 6. Result returned to Beacon            │
└─────────────────────────────────────────┘
```

### Call Stack Comparison

**WITHOUT Jopcall** (❌ Detected):
```
[0] ntdll!NtAllocateVirtualMemory+0x14
[1] beacon.dll+0x4523                  ← UNBACKED MEMORY
[2] beacon.dll+0x1234                  ← SUSPICIOUS
```

**WITH Jopcall** (✅ Appears Legitimate):
```
[0] ntdll!NtAllocateVirtualMemory+0x14
[1] ntdll!RtlQueryPerformanceCounter+0x1a  ← Legitimate ntdll code
[2] ntdll!RtlCaptureContext+0x2f           ← Legitimate ntdll code
[3] ntdll!RtlUserThreadStart+0x21          ← Legitimate ntdll code
```

## EDR Evasion

### What Jopcall Defeats

✅ **Call Stack Scanning** - EDR sees legitimate ntdll call chains
✅ **Return Address Analysis** - All returns point to valid ntdll code
✅ **Heuristic Detection** - Syscalls appear to originate from ntdll

### What It Doesn't Defeat

❌ **Userland API Hooks** - Use direct syscalls (which jopcall does)
❌ **Kernel Callbacks** - Combine with other techniques
❌ **Memory Scanning** - Use with memory encryption/obfuscation

## Supported Syscalls

**uDRL (Loading)**:
- NtAllocateVirtualMemory
- NtProtectVirtualMemory

**BeaconGate (Runtime)** - 16 total:
- Memory: NtAllocateVirtualMemory, NtProtectVirtualMemory, NtFreeVirtualMemory, NtQueryVirtualMemory
- Sections: NtCreateSection, NtMapViewOfSection, NtUnmapViewOfSection
- Process Memory: NtReadVirtualMemory, NtWriteVirtualMemory
- Threads: NtCreateThreadEx, NtGetContextThread, NtSetContextThread, NtResumeThread
- Handles: NtOpenProcess, NtOpenThread, NtClose, NtDuplicateObject

## Testing

### Quick Smoke Test

```bash
# 1. Build
make dawsonloader

# 2. Verify output
file dist/DawsonLoader.x64.o
# Expected: Intel amd64 COFF object file

# 3. Load in CS and generate beacon
# 4. Execute on test system
# 5. Beacon should call back successfully
```

### Debug Mode

Enable logging in `Sleepmask-VS/sleepmask-vs/debug.h`:
```c
#define ENABLE_LOGGING 1
```

Use **DbgView** or **WinDbg** to view output:
```
SLEEPMASK: Initializing jopcall ROP/JOP gadgets from ntdll...
SLEEPMASK: Jopcall context initialized successfully. Gadget count: 4
```

## Credits

- **Jopcall**: Noah Kirchner ([@noahkirchner](https://github.com/noahkirchner)) - https://github.com/NoahKirchner/jopcall
- **BokuLoader**: Bobby Cooke ([@0xBoku](https://github.com/boku7)) - https://github.com/boku7/BokuLoader
- **Sleepmask-VS**: Fortra/Cobalt Strike Team
- **DawsonLoader**: CTE Offensive Security Research Division

## References

- [Jopcall Original Project](https://github.com/NoahKirchner/jopcall)
- [BeaconGate Blog Post](https://www.cobaltstrike.com/blog/instrumenting-beacon-with-beacongate-for-call-stack-spoofing)
- [Cobalt Strike uDRL Documentation](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2-extend_user-defined-rdll.htm)
- [Return-Oriented Programming](https://en.wikipedia.org/wiki/Return-oriented_programming)

## License

See LICENSE.md

## Disclaimer

This tool is provided for authorized security testing and research purposes only. Users are responsible for compliance with all applicable laws and regulations. The authors assume no liability for misuse or damage.

---

**Happy Hacking! 🔐**
