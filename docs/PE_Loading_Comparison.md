# PE Loading Comparison: Traditional vs DawsonLoader UDRL

## Table of Contents
1. [Executive Summary](#executive-summary)
2. [Traditional PE Loading](#traditional-pe-loading)
3. [DawsonLoader Custom Loading](#dawsonloader-custom-loading)
4. [Side-by-Side Comparison](#side-by-side-comparison)
5. [Evasion Techniques Explained](#evasion-techniques-explained)
6. [Detection Surface Analysis](#detection-surface-analysis)

---

## Executive Summary

**Traditional PE Loading** relies on the Windows OS loader (`ntdll.dll`'s `LdrLoadDll`) to map executables/DLLs into memory, resolve imports, apply relocations, and execute entry points. This process leaves **numerous forensic artifacts** that EDR solutions monitor.

**DawsonLoader UDRL (User-Defined Reflective Loader)** is a custom loader that bypasses the OS loader entirely, performing all loading operations manually in memory. It combines multiple evasion techniques:
- **Reflective DLL Injection** - Self-contained loading without filesystem artifacts
- **Module Stomping** - Overwriting legitimate DLLs to hide memory allocations
- **Indirect Syscalls** - Direct NT syscalls bypassing API hooks
- **ROP/JOP Call Stack Spoofing** - Obfuscating return addresses with gadget chains

---

## Traditional PE Loading

### Overview
When you execute `malware.exe` or load a DLL via `LoadLibrary()`, the Windows loader performs a well-documented, observable series of steps.

### Process Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    TRADITIONAL PE LOADING                        │
└─────────────────────────────────────────────────────────────────┘

    User Action: CreateProcess("malware.exe")
         │
         ▼
    ┌────────────────────────────────────────┐
    │   1. KERNEL PROCESS CREATION           │
    │   - NtCreateUserProcess()              │
    │   - Allocate PEB/TEB structures        │
    │   - Create initial thread (suspended)  │
    └────────────────┬───────────────────────┘
                     │
                     ▼
    ┌────────────────────────────────────────┐
    │   2. NTDLL.DLL INITIALIZATION          │
    │   - Map ntdll.dll to process memory    │
    │   - Execute LdrInitializeThunk         │
    └────────────────┬───────────────────────┘
                     │
                     ▼
    ┌────────────────────────────────────────┐
    │   3. MAP EXECUTABLE TO MEMORY          │
    │   - Read PE headers from disk          │
    │   - Allocate memory at ImageBase       │
    │   - Copy sections (.text, .data, etc)  │
    │   - Mark sections with RWX perms       │
    └────────────────┬───────────────────────┘
                     │
                     ▼
    ┌────────────────────────────────────────┐
    │   4. PROCESS RELOCATIONS               │
    │   - Read .reloc section                │
    │   - Fix absolute addresses if needed   │
    │   - Update ImageBase references        │
    └────────────────┬───────────────────────┘
                     │
                     ▼
    ┌────────────────────────────────────────┐
    │   5. RESOLVE IMPORTS (IAT)             │
    │   - Parse Import Directory Table       │
    │   - Call LoadLibrary for each DLL      │
    │     (kernel32.dll, advapi32.dll, ...)  │
    │   - GetProcAddress for each function   │
    │   - Fill Import Address Table (IAT)    │
    └────────────────┬───────────────────────┘
                     │
                     ▼
    ┌────────────────────────────────────────┐
    │   6. EXECUTE TLS CALLBACKS             │
    │   - Thread Local Storage initialization│
    │   - Run TLS callback functions         │
    └────────────────┬───────────────────────┘
                     │
                     ▼
    ┌────────────────────────────────────────┐
    │   7. EXECUTE ENTRY POINT               │
    │   - Call DllMain() or WinMain()        │
    │   - Resume initial thread              │
    └────────────────────────────────────────┘

         Normal Program Execution
```

### Memory Layout (Traditional)

```
┌─────────────────────────────────────────────────────────────────┐
│                      PROCESS VIRTUAL MEMORY                      │
├─────────────────────────────────────────────────────────────────┤
│  0x00007FF7`00000000  ┌──────────────────────────────┐          │
│                       │     malware.exe              │          │
│                       │  PE Headers (Visible)        │          │
│                       │  .text  (RX - Executable)    │          │
│                       │  .rdata (R  - Imports/Strings│          │
│                       │  .data  (RW - Global vars)   │          │
│                       │  .reloc (R  - Relocations)   │          │
│                       └──────────────────────────────┘          │
│  0x00007FFE`00000000  ┌──────────────────────────────┐          │
│                       │     ntdll.dll                │          │
│                       │  - LdrLoadDll (HOOKED!)      │          │
│                       │  - NtAllocateVirtualMemory   │          │
│                       └──────────────────────────────┘          │
│  0x00007FFD`00000000  ┌──────────────────────────────┐          │
│                       │     kernel32.dll             │          │
│                       │  - CreateFileA (HOOKED!)     │          │
│                       │  - VirtualAlloc (HOOKED!)    │          │
│                       └──────────────────────────────┘          │
│  0x00007FFC`00000000  ┌──────────────────────────────┐          │
│                       │     kernelbase.dll           │          │
│                       └──────────────────────────────┘          │
│                       ┌──────────────────────────────┐          │
│                       │     advapi32.dll             │          │
│                       │  - RegOpenKeyEx (HOOKED!)    │          │
│                       └──────────────────────────────┘          │
│                       ...                                        │
│  0x000000000000000    [Stack]                                   │
└─────────────────────────────────────────────────────────────────┘
```

### EDR Detection Points (Traditional Loading)

```
┌──────────────────────────────────────────────────────────────┐
│             EDR HOOKS & MONITORING (Traditional)             │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  FILE SYSTEM MONITORING:                                     │
│  ✓ Disk I/O (malware.exe read from disk)                    │
│  ✓ File creation/modification events                        │
│                                                              │
│  API HOOKING (Userland):                                     │
│  ✓ LoadLibraryA/W         ← EDR hook                        │
│  ✓ CreateProcessA/W       ← EDR hook                        │
│  ✓ VirtualAlloc           ← EDR hook                        │
│  ✓ VirtualProtect         ← EDR hook                        │
│  ✓ WriteProcessMemory     ← EDR hook                        │
│                                                              │
│  KERNEL CALLBACKS:                                           │
│  ✓ PsSetCreateProcessNotifyRoutine (process creation)       │
│  ✓ PsSetLoadImageNotifyRoutine (module load)                │
│  ✓ ObRegisterCallbacks (handle operations)                  │
│                                                              │
│  MEMORY FORENSICS:                                           │
│  ✓ Suspicious RWX memory regions                            │
│  ✓ Unsigned/unbacked memory (no file on disk)               │
│  ✓ PE headers visible in memory                             │
│  ✓ Import Address Table (IAT) intact                        │
│                                                              │
│  CALL STACK ANALYSIS:                                        │
│  ✓ Normal call stack from malware.exe → kernel32 → ntdll    │
│     Call Stack Example:                                      │
│     [0] ntdll!NtCreateFile                                   │
│     [1] kernel32!CreateFileW      ← EDR can see this         │
│     [2] malware.exe+0x1234        ← Suspicious caller        │
│     [3] malware.exe+0x5678                                   │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### Artifacts Left Behind (Traditional)

| Artifact Type | Description | EDR Visibility |
|---------------|-------------|----------------|
| **Disk Signature** | Original PE file on disk | HIGH - File hash, entropy analysis |
| **Module List** | Visible in PEB's `InLoadOrderModuleList` | HIGH - Easy enumeration |
| **IAT Entries** | Import table with function names | HIGH - Shows malicious API usage |
| **PE Headers** | Full MZ/PE headers in memory | HIGH - Easy signature matching |
| **Backed Memory** | Memory mapped to disk file | HIGH - Shows file path |
| **API Call Chain** | Normal Windows API flow | MEDIUM - Hooked by EDR |
| **Call Stack** | Return addresses point to malware.exe | HIGH - Stack walking detection |

---

## DawsonLoader Custom Loading

### Overview
DawsonLoader is a **User-Defined Reflective Loader (UDRL)** that implements **position-independent code (PIC)** to load Cobalt Strike beacons entirely in memory without relying on Windows APIs or leaving traditional artifacts.

### Process Flow

```
┌─────────────────────────────────────────────────────────────────┐
│              DAWSONLOADER REFLECTIVE LOADING                     │
└─────────────────────────────────────────────────────────────────┘

    Initial Stage: Shellcode Injection (C2 delivers)
         │
         ▼
    ┌────────────────────────────────────────┐
    │   1. POSITION-INDEPENDENT EXECUTION    │
    │   - DawsonLoader shellcode (no imports)│
    │   - No standard PE headers visible     │
    │   - PIC code uses relative addressing  │
    └────────────────┬───────────────────────┘
                     │
                     ▼
    ┌────────────────────────────────────────┐
    │   2. CUSTOM API RESOLUTION             │
    │   - Walk PEB → Find ntdll.dll base     │
    │   - Parse EAT manually (no imports!)   │
    │   - Resolve NT functions by hash/name  │
    │   - NO LoadLibrary/GetProcAddress!     │
    └────────────────┬───────────────────────┘
                     │
                     ▼
    ┌────────────────────────────────────────┐
    │   3. MODULE STOMPING ALLOCATION        │
    │   - Find legitimate DLL (mshtml.dll)   │
    │   - Unmap original DLL from memory     │
    │   - Reuse memory region for beacon     │
    │   - Looks like mshtml.dll to scanners! │
    └────────────────┬───────────────────────┘
                     │
                     ▼
    ┌────────────────────────────────────────┐
    │   4. INDIRECT SYSCALLS (HellsGate)     │
    │   - Extract syscall numbers from ntdll │
    │   - Bypass userland API hooks          │
    │   - Direct syscall; instruction        │
    │   - No kernel32/kernelbase dependency  │
    └────────────────┬───────────────────────┘
                     │
                     ▼
    ┌────────────────────────────────────────┐
    │   5. ROP/JOP STACK SPOOFING            │
    │   - Discover gadgets in ntdll.dll      │
    │     (jmp rcx, ret instructions)        │
    │   - Build ROP chain on stack           │
    │   - Syscall returns to ntdll gadgets   │
    │   - Call stack looks legitimate!       │
    └────────────────┬───────────────────────┘
                     │
                     ▼
    ┌────────────────────────────────────────┐
    │   6. MANUAL PE LOADING                 │
    │   - Allocate RW memory via syscall     │
    │   - Copy beacon sections manually      │
    │   - Process relocations in-memory      │
    │   - Change to RX (no RWX stage!)       │
    └────────────────┬───────────────────────┘
                     │
                     ▼
    ┌────────────────────────────────────────┐
    │   7. IMPORT RESOLUTION (CUSTOM)        │
    │   - Parse beacon's import table        │
    │   - Resolve APIs via PEB walk          │
    │   - No LoadLibrary calls!              │
    │   - Optionally obfuscate/hash imports  │
    └────────────────┬───────────────────────┘
                     │
                     ▼
    ┌────────────────────────────────────────┐
    │   8. HEADER OBFUSCATION                │
    │   - XOR obfuscate PE headers           │
    │   - Mask section names (.text→random)  │
    │   - Destroy MZ/PE signatures           │
    │   - Memory appears as random data      │
    └────────────────┬───────────────────────┘
                     │
                     ▼
    ┌────────────────────────────────────────┐
    │   9. EXECUTE BEACON ENTRY POINT        │
    │   - Jump to ReflectiveLoader stub      │
    │   - Beacon initializes C2 connection   │
    │   - All operations via syscalls        │
    └────────────────────────────────────────┘

         Beacon Running (Evading EDR)
```

### Memory Layout (DawsonLoader)

```
┌─────────────────────────────────────────────────────────────────┐
│              PROCESS VIRTUAL MEMORY (Reflective)                 │
├─────────────────────────────────────────────────────────────────┤
│  0x00007FF7`00000000  ┌──────────────────────────────┐          │
│                       │   Legitimate Process.exe     │          │
│                       │   (e.g., explorer.exe)       │          │
│                       │   Normal PE structure        │          │
│                       └──────────────────────────────┘          │
│                                                                  │
│  0x00007FFD`12340000  ┌──────────────────────────────┐          │
│                       │   "mshtml.dll" (STOMPED!)    │ ← Fake!  │
│                       ├──────────────────────────────┤          │
│                       │  ████████████████████████    │ ← XOR'd  │
│                       │  (Obfuscated PE headers)     │   Headers│
│                       ├──────────────────────────────┤          │
│                       │  Beacon Code (appears as     │          │
│                       │  legitimate mshtml data)     │          │
│                       │  - No "MZ" signature         │          │
│                       │  - No ".text" section names  │          │
│                       │  - No visible IAT            │          │
│                       └──────────────────────────────┘          │
│                       │                              │          │
│                       │  ↑ PEB shows "mshtml.dll"    │          │
│                       │    at this address           │          │
│                       │  ↑ EDR sees legitimate DLL   │          │
│                       │  ↑ Actual beacon code hiding │          │
│                                                                  │
│  0x00007FFE`00000000  ┌──────────────────────────────┐          │
│                       │     ntdll.dll (CLEAN!)       │          │
│                       │  - No hooks bypassed         │          │
│                       │  - Syscall stubs extracted   │          │
│                       │  - ROP gadgets discovered    │          │
│                       └──────────────────────────────┘          │
│                                                                  │
│  [NO kernel32.dll loaded by beacon - not needed!]               │
│  [NO suspicious unbacked memory regions!]                       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Call Stack Comparison

**Traditional Malware Call Stack (DETECTED!):**
```
Stack Trace for Suspicious API Call (NtCreateFile):
┌────────────────────────────────────────────────────┐
│ [0] ntdll!NtCreateFile                             │
│     Return Address: kernel32!CreateFileW+0x70      │ ← Hooked!
│                                                    │
│ [1] kernel32!CreateFileW                           │
│     Return Address: malware.exe+0x1234             │ ← SUSPICIOUS!
│     Module: malware.exe (unbacked memory)          │ ← EDR ALERT!
│                                                    │
│ [2] malware.exe+0x1234 (PayloadFunction)          │
│     Return Address: malware.exe+0x5678             │ ← SUSPICIOUS!
│                                                    │
│ [3] malware.exe+0x5678 (Main)                      │
│     ⚠️  EDR FLAGS: Return addresses in unbacked    │
│        memory, no legitimate call chain           │
└────────────────────────────────────────────────────┘
```

**DawsonLoader + ROP Chain Call Stack (EVADED!):**
```
Stack Trace for Syscall via ROP Chain (NtProtectVirtualMemory):
┌────────────────────────────────────────────────────┐
│ [0] ntdll!NtProtectVirtualMemory (syscall stub)   │
│     Return Address: ntdll+0x8A3C (jmp rcx gadget) │ ← ntdll!
│                                                    │
│ [1] ntdll+0x8A3C (ROP gadget: jmp rcx)            │
│     Return Address: ntdll+0x12F4 (ret gadget)     │ ← ntdll!
│                                                    │
│ [2] ntdll+0x12F4 (ROP gadget: ret)                │
│     Return Address: ntdll+0x5F89 (pop rcx; ret)   │ ← ntdll!
│                                                    │
│ [3] ntdll+0x5F89 (ROP gadget: pop rcx; ret)       │
│     Return Address: "mshtml.dll"+0x4500           │ ← Looks legit!
│     Module: mshtml.dll (stomped, but PEB says OK) │ ← NO ALERT
│                                                    │
│ [4] "mshtml.dll"+0x4500 (Beacon code)             │
│     ✓ EDR SEES: Normal call from mshtml.dll       │
│     ✓ Call chain goes through ntdll gadgets       │
│     ✓ No suspicious unbacked memory in chain      │
│     ✓ Stack looks completely legitimate!          │
└────────────────────────────────────────────────────┘
```

### Evasion Techniques Breakdown

```
┌──────────────────────────────────────────────────────────────┐
│            DAWSONLOADER EVASION TECHNIQUES                   │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  1. REFLECTIVE DLL INJECTION                                 │
│     ┌─────────────────────────────────────────────┐         │
│     │ • No file on disk (delivered via network)   │         │
│     │ • Self-contained loader in shellcode         │         │
│     │ • Position-independent code (PIC)            │         │
│     │ ✓ EVADES: File-based scanning, disk forensics│        │
│     └─────────────────────────────────────────────┘         │
│                                                              │
│  2. MODULE STOMPING (Phantom DLL)                            │
│     ┌─────────────────────────────────────────────┐         │
│     │ • Find loaded DLL (e.g., mshtml.dll)        │         │
│     │ • NtUnmapViewOfSection (remove original)     │         │
│     │ • Reuse same memory region for beacon        │         │
│     │ • PEB still shows "mshtml.dll" entry         │         │
│     │ ✓ EVADES: Unbacked memory detection          │         │
│     │ ✓ EVADES: Memory region analysis             │         │
│     └─────────────────────────────────────────────┘         │
│                                                              │
│  3. INDIRECT SYSCALLS (HellsGate/HalosGate)                  │
│     ┌─────────────────────────────────────────────┐         │
│     │ • Parse ntdll.dll EAT for syscall stubs     │         │
│     │ • Extract SSN (syscall number) at runtime    │         │
│     │ • Execute syscall instruction directly       │         │
│     │ • Bypass kernel32/kernelbase hooks           │         │
│     │ ✓ EVADES: API hooking (userland)             │         │
│     │ ✓ EVADES: ETW (Event Tracing for Windows)    │         │
│     └─────────────────────────────────────────────┘         │
│                                                              │
│  4. ROP/JOP CALL STACK SPOOFING                              │
│     ┌─────────────────────────────────────────────┐         │
│     │ • Scan ntdll for gadgets (jmp rcx, ret)     │         │
│     │ • Build random gadget chain on stack         │         │
│     │ • Syscall returns through gadget chain       │         │
│     │ • Return addresses point to ntdll (legit!)   │         │
│     │ ✓ EVADES: Call stack inspection               │         │
│     │ ✓ EVADES: Return address validation          │         │
│     └─────────────────────────────────────────────┘         │
│                                                              │
│  5. PE HEADER OBFUSCATION                                    │
│     ┌─────────────────────────────────────────────┐         │
│     │ • XOR obfuscate "MZ" and "PE" signatures    │         │
│     │ • Randomize section names (.text → █████)   │         │
│     │ • Mask import table entries                  │         │
│     │ • Destroy DOS stub and Rich header           │         │
│     │ ✓ EVADES: Signature-based memory scanning    │         │
│     │ ✓ EVADES: YARA rules for PE structures       │         │
│     └─────────────────────────────────────────────┘         │
│                                                              │
│  6. NO RWX MEMORY PAGES                                      │
│     ┌─────────────────────────────────────────────┐         │
│     │ • Allocate as RW initially                   │         │
│     │ • Copy beacon code and process relocations   │         │
│     │ • Change to RX before execution              │         │
│     │ • Never have RWX permissions simultaneously  │         │
│     │ ✓ EVADES: RWX memory region hunting          │         │
│     └─────────────────────────────────────────────┘         │
│                                                              │
│  7. CUSTOM API RESOLUTION (No IAT)                           │
│     ┌─────────────────────────────────────────────┐         │
│     │ • Walk PEB to find loaded modules            │         │
│     │ • Parse EAT manually (no GetProcAddress)     │         │
│     │ • Resolve by hash/name at runtime            │         │
│     │ • No visible Import Address Table            │         │
│     │ ✓ EVADES: IAT analysis                        │         │
│     │ ✓ EVADES: Import-based detection rules       │         │
│     └─────────────────────────────────────────────┘         │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

---

## Side-by-Side Comparison

### Architecture Diagram

```
┌───────────────────────────────────────────────────────────────────────────┐
│                    TRADITIONAL vs DAWSONLOADER                            │
├───────────────────────────────────┬───────────────────────────────────────┤
│       TRADITIONAL LOADING         │       DAWSONLOADER (UDRL)             │
├───────────────────────────────────┼───────────────────────────────────────┤
│                                   │                                       │
│  1. DELIVERY METHOD               │  1. DELIVERY METHOD                   │
│     • File on disk (malware.exe)  │     • In-memory only (shellcode)      │
│     • Downloaded/dropped          │     • Delivered via C2 channel        │
│     • Scanned by AV               │     • No filesystem interaction       │
│                                   │                                       │
│  2. PROCESS CREATION              │  2. INJECTION TARGET                  │
│     • CreateProcess()             │     • Existing process (explorer.exe) │
│     • New process context         │     • Remote thread injection         │
│     • Monitored by EDR            │     • Or process hollowing            │
│                                   │                                       │
│  3. MODULE LOADING                │  3. MANUAL MEMORY ALLOCATION          │
│     • Windows loader (ntdll)      │     • NtAllocateVirtualMemory         │
│     • LdrLoadDll()                │     • Or module stomping              │
│     • Automatic IAT resolution    │     • Direct syscall (no hooks)       │
│                                   │                                       │
│  4. IMPORT RESOLUTION             │  4. CUSTOM API RESOLUTION             │
│     • LoadLibrary()               │     • PEB walk                        │
│     • GetProcAddress()            │     • Manual EAT parsing              │
│     • Visible IAT entries         │     • No IAT structure                │
│     • ✗ Hooked by EDR             │     • ✓ Bypasses hooks                │
│                                   │                                       │
│  5. MEMORY PROTECTION             │  5. MEMORY PROTECTION                 │
│     • VirtualAlloc()              │     • NtProtectVirtualMemory          │
│     • RWX pages common            │     • RW → RX transition              │
│     • ✗ Hooked by EDR             │     • Via ROP chain syscall           │
│     • ✗ Suspicious RWX pages      │     • ✓ No RWX stage                  │
│                                   │                                       │
│  6. EXECUTION                     │  6. EXECUTION                         │
│     • Normal entry point          │     • Position-independent code       │
│     • Call stack from .exe        │     • Call stack through ROP gadgets  │
│     • ✗ Return addrs in malware   │     • ✓ Return addrs in ntdll        │
│                                   │                                       │
│  7. FORENSIC ARTIFACTS            │  7. FORENSIC ARTIFACTS                │
│     • PE headers intact           │     • XOR obfuscated headers          │
│     • Section names visible       │     • Randomized section names        │
│     • MZ/PE signatures present    │     • Signatures destroyed            │
│     • Module list entry           │     • Stomped DLL in module list      │
│     • ✗ HIGH detection surface    │     • ✓ LOW detection surface         │
│                                   │                                       │
└───────────────────────────────────┴───────────────────────────────────────┘
```

### Detection Comparison Table

| **Detection Method** | **Traditional PE** | **DawsonLoader UDRL** |
|----------------------|--------------------|-----------------------|
| **File Hash Scanning** | DETECTED - File on disk | EVADED - No file |
| **PE Header Signature** | DETECTED - MZ/PE visible | EVADED - XOR obfuscated |
| **Import Table Analysis** | DETECTED - IAT shows APIs | EVADED - No IAT |
| **API Hooking (userland)** | DETECTED - Calls hooked APIs | EVADED - Direct syscalls |
| **RWX Memory Scan** | DETECTED - RWX pages | EVADED - RW→RX transition |
| **Unbacked Memory** | DETECTED - No disk backing | EVADED - Module stomping |
| **Call Stack Walking** | DETECTED - Returns to .exe | EVADED - ROP chain spoofing |
| **Module List Check** | DETECTED - Malware in list | EVADED - Fake DLL name |
| **ETW Telemetry** | DETECTED - API events logged | EVADED - Syscalls bypass ETW |
| **YARA Rules (memory)** | DETECTED - PE patterns match | EVADED - Obfuscated structure |

---

## Evasion Techniques Explained

### 1. Reflective DLL Injection

**Traditional DLL Loading:**
```
LoadLibrary("payload.dll")
    ↓
Reads from disk
    ↓
Windows maps PE to memory
    ↓
Resolve imports automatically
```

**Reflective Loading:**
```
Shellcode delivered over network
    ↓
Self-contained loader code
    ↓
Manual PE parsing and loading
    ↓
No disk interaction
```

**Why It Evades:**
- No file signature to scan
- No disk I/O events
- Loader is position-independent code (PIC)

---

### 2. Module Stomping (Phantom DLL Technique)

**Problem:** Unbacked memory regions are suspicious.

**Solution:** Overwrite a legitimate DLL's memory space.

```
BEFORE Module Stomping:
┌─────────────────────────────────────┐
│ mshtml.dll (Loaded by browser)      │
│ Base: 0x7FFD12340000                │
│ Size: 0x500000                      │
│ Backed: C:\Windows\System32\mshtml.dll
└─────────────────────────────────────┘

STEP 1: Unmap Original
    NtUnmapViewOfSection(mshtml_base)

STEP 2: Allocate Beacon in Same Region
    NtAllocateVirtualMemory(mshtml_base, beacon_size)

AFTER Module Stomping:
┌─────────────────────────────────────┐
│ "mshtml.dll" (FAKE - Beacon code!)  │
│ Base: 0x7FFD12340000                │ ← Same address!
│ Size: 0x500000                      │
│ Backed: None (but PEB says mshtml!) │
│ PEB Entry: mshtml.dll               │ ← Looks legitimate
└─────────────────────────────────────┘
```

**EDR's View:**
```
> Get-Process explorer | Select-Object -ExpandProperty Modules
Name            : mshtml.dll
FileName        : C:\Windows\System32\mshtml.dll ← Fake path!
BaseAddress     : 0x7FFD12340000
Size            : 5242880
```

**Why It Evades:**
- Memory appears to be backed by legitimate DLL
- Module list shows expected system DLL
- No "unbacked memory" alert

---

### 3. Indirect Syscalls (HellsGate)

**Traditional API Call (HOOKED!):**
```
Your Code:
    VirtualAlloc(size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
        ↓
    kernel32!VirtualAlloc [EDR HOOK JUMPS TO AGENT]
        ↓
    EDR Agent: Log this suspicious call!
        ↓
    kernelbase!VirtualAlloc
        ↓
    ntdll!NtAllocateVirtualMemory
        ↓
    syscall (enters kernel)
```

**DawsonLoader Indirect Syscall (BYPASSED!):**
```
Your Code:
    // Find syscall stub in ntdll
    PVOID NtAllocAddr = GetSyscallStub("NtAllocateVirtualMemory");
    WORD ssn = ExtractSSN(NtAllocAddr);  // SSN = 0x18

    // Build inline syscall
    mov r10, rcx
    mov eax, 0x18        ; SSN for NtAllocateVirtualMemory
    syscall              ; Direct to kernel!
    ret

    [EDR hooks are completely bypassed]
        ↓
    syscall (enters kernel directly)
```

**HellsGate SSN Extraction:**
```c
// ntdll!NtAllocateVirtualMemory looks like this:
// 4C 8B D1             mov r10, rcx
// B8 18 00 00 00       mov eax, 0x18      ← SSN = 0x18
// 0F 05                syscall
// C3                   ret

WORD getSyscallNumber(PVOID func_addr) {
    BYTE* bytes = (BYTE*)func_addr;

    // Check for mov eax, <SSN> instruction
    if (bytes[0] == 0x4C && bytes[1] == 0x8B &&   // mov r10, rcx
        bytes[3] == 0xB8) {                        // mov eax, imm32
        return *(WORD*)(bytes + 4);  // Return SSN
    }

    // If hooked, use HalosGate (check nearby functions)
    return halosGate_findNearby(func_addr);
}
```

---

### 4. ROP/JOP Call Stack Spoofing

**The Problem: Suspicious Call Stacks**

EDR products walk the call stack during sensitive operations (e.g., memory allocation, process creation) to validate the caller chain.

**Suspicious Call Stack (DETECTED!):**
```
[0] ntdll!NtProtectVirtualMemory
[1] beacon.dll+0x1234         ← ALERT! Unbacked memory
[2] beacon.dll+0x5678         ← ALERT! Unbacked memory
```

**The Solution: ROP Chain Return Address Obfuscation**

Build a chain of "gadgets" (small instruction sequences ending in `ret` or `jmp`) from legitimate ntdll code.

**Gadget Discovery:**
```c
// Search ntdll.dll's .text section for useful gadgets
BYTE jmp_rcx[]  = {0xFF, 0xE1};           // jmp rcx (indirect jump)
BYTE ret[]      = {0xC3};                  // ret
BYTE pop_rcx[]  = {0x59, 0xC3};           // pop rcx; ret

find_gadgets(ntdll_base, jmp_rcx, &gadget_list);
```

**ROP Chain Execution:**
```
Stack Layout During Syscall:
┌──────────────────────────────────┐
│ [RSP+0x00] → ntdll+0x8A3C        │ ← Gadget 1: jmp rcx
│ [RSP+0x08] → ntdll+0x12F4        │ ← Gadget 2: ret
│ [RSP+0x10] → ntdll+0x5F89        │ ← Gadget 3: pop rcx; ret
│ [RSP+0x18] → beacon.dll+0x4500   │ ← Actual return (hidden!)
└──────────────────────────────────┘

Execution Flow:
1. syscall instruction completes
2. Returns to ntdll+0x8A3C (jmp rcx) ← EDR sees ntdll!
3. Jumps to ntdll+0x12F4 (ret)       ← EDR sees ntdll!
4. Returns to ntdll+0x5F89 (pop rcx) ← EDR sees ntdll!
5. Finally returns to beacon code    ← Hidden by legit frames
```

**EDR's View (EVADED!):**
```
Call Stack Inspection:
[0] ntdll!NtProtectVirtualMemory
[1] ntdll+0x8A3C (legitimate code)   ← Looks normal
[2] ntdll+0x12F4 (legitimate code)   ← Looks normal
[3] mshtml.dll+0x4500 (stomped DLL)  ← Looks normal

✓ All return addresses are in legitimate modules
✓ No suspicious unbacked memory in chain
✓ EDR validation passes
```

**Assembly Implementation (src/DawsonLoader.c:1701):**
```asm
jop_syscall:
    ; Save registers
    mov [rsp - 0x8], rsi
    mov [rsp - 0x10], rdi

    ; Push gadgets onto stack (LIFO order)
    mov r11, rcx              ; r11 = gadget array
    push qword ptr [r11 + 0x10]  ; Gadget 3
    push qword ptr [r11 + 0x08]  ; Gadget 2
    ; Gadget 1 loaded into r11 for jmp

    ; Setup syscall parameters
    mov eax, r8d              ; SSN
    mov r10, [rsp + 0x28]     ; arg1
    mov rdx, [rsp + 0x30]     ; arg2
    mov r8,  [rsp + 0x38]     ; arg3
    mov r9,  [rsp + 0x40]     ; arg4

    mov rcx, r12              ; syscall address
    jmp r11                   ; Jump to first gadget → syscall
```

---

### 5. PE Header Obfuscation

**Why Obfuscate Headers?**

Memory scanners (YARA, Volatility, EDR agents) search for PE structures:
- `MZ` signature at offset 0
- `PE\0\0` signature at e_lfanew
- Section names like `.text`, `.rdata`
- Rich header (compiler signature)

**DawsonLoader Obfuscation (dist/DawsonLoader.cna:405-424):**

```c
// Original PE Headers:
4D 5A 90 00 ... (MZ signature)
...
50 45 00 00 (PE signature)
...
2E 74 65 78 74 00 00 00  (.text section name)

// After XOR with key 0xAB:
E6 F1 3B AB ... (Obfuscated MZ)
...
FB AF AB AB (Obfuscated PE)
...
85 DF CE D2 CF 84 AB AB  (Obfuscated section name)
```

**Aggressor Script XOR Function:**
```perl
sub dawson_pe_mask {
    local('$beacon_dll $xor_key');
    $beacon_dll = $1;
    $xor_key = $2;

    # XOR first 4096 bytes (headers)
    for ($i = 0; $i < 4096; $i++) {
        $byte = byteAt($beacon_dll, $i);
        $beacon_dll = replaceAt($beacon_dll, pack("C", $byte ^ $xor_key), $i);
    }

    return $beacon_dll;
}
```

**Result:**
- Memory scanners searching for `MZ` pattern fail
- YARA rules matching PE structure fail
- Signature-based detection evaded

---

## Detection Surface Analysis

### Traditional Executable - Attack Surface

```
┌────────────────────────────────────────────────────────────┐
│              DETECTION ATTACK SURFACE                      │
│                (Traditional Malware)                       │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  FILE SYSTEM:                                              │
│    ▓▓▓▓▓▓▓▓▓▓ (100% - File on disk)                       │
│                                                            │
│  API HOOKING:                                              │
│    ▓▓▓▓▓▓▓▓▓▓ (100% - All APIs hooked)                    │
│                                                            │
│  MEMORY SIGNATURES:                                        │
│    ▓▓▓▓▓▓▓▓▓▓ (100% - PE headers visible)                 │
│                                                            │
│  CALL STACK:                                               │
│    ▓▓▓▓▓▓▓▓▓▓ (100% - Suspicious frames)                  │
│                                                            │
│  MODULE LIST:                                              │
│    ▓▓▓▓▓▓▓▓▓▓ (100% - Malicious module visible)           │
│                                                            │
│  IMPORT TABLE:                                             │
│    ▓▓▓▓▓▓▓▓▓▓ (100% - Suspicious APIs listed)             │
│                                                            │
│  MEMORY PROTECTION:                                        │
│    ▓▓▓▓▓▓▓▓▓▓ (100% - RWX pages detected)                 │
│                                                            │
│  OVERALL DETECTION RISK:  ████████ 95%                     │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

### DawsonLoader - Reduced Attack Surface

```
┌────────────────────────────────────────────────────────────┐
│              DETECTION ATTACK SURFACE                      │
│                (DawsonLoader UDRL)                         │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  FILE SYSTEM:                                              │
│    ░░░░░░░░░░ (0% - No file, in-memory only)              │
│                                                            │
│  API HOOKING:                                              │
│    ░░░░░░░░░░ (0% - Syscalls bypass hooks)                │
│                                                            │
│  MEMORY SIGNATURES:                                        │
│    ▓░░░░░░░░░ (10% - Headers obfuscated)                  │
│                                                            │
│  CALL STACK:                                               │
│    ▓▓░░░░░░░░ (15% - ROP gadgets hide caller)             │
│                                                            │
│  MODULE LIST:                                              │
│    ▓▓░░░░░░░░ (20% - Stomped DLL, looks legit)            │
│                                                            │
│  IMPORT TABLE:                                             │
│    ░░░░░░░░░░ (0% - No IAT, runtime resolution)           │
│                                                            │
│  MEMORY PROTECTION:                                        │
│    ░░░░░░░░░░ (0% - RW→RX, no RWX)                        │
│                                                            │
│  OVERALL DETECTION RISK:  ▓░░░░░░░ 8-12%                   │
│                           (Requires advanced hunting)      │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

---

## Advanced EDR Bypass Diagram

```
┌────────────────────────────────────────────────────────────────────────┐
│                       EDR BYPASS WORKFLOW                              │
└────────────────────────────────────────────────────────────────────────┘

    ┌──────────────────┐
    │  Cobalt Strike   │
    │  Team Server     │
    └────────┬─────────┘
             │
             ▼ (HTTP/HTTPS)
    ┌────────────────────┐
    │  Compromised Host  │
    │  (explorer.exe)    │
    └────────┬───────────┘
             │
             ▼
    ┌─────────────────────────────────────────────────────────┐
    │         STAGE 1: Initial Beacon Delivery                │
    │  ┌───────────────────────────────────────────────────┐  │
    │  │ • Small HTTP stager received                      │  │
    │  │ • Allocate RW memory (VirtualAlloc - OK to hook)  │  │
    │  │ • Download full beacon + DawsonLoader shellcode   │  │
    │  └───────────────────────────────────────────────────┘  │
    └────────┬────────────────────────────────────────────────┘
             │
             ▼
    ┌─────────────────────────────────────────────────────────┐
    │         STAGE 2: DawsonLoader Initialization            │
    │  ┌───────────────────────────────────────────────────┐  │
    │  │ [PEB Walk - Find ntdll.dll]                       │  │
    │  │      TEB → PEB → Ldr → InLoadOrderModuleList      │  │
    │  │      ↓                                             │  │
    │  │ [Parse ntdll EAT - Resolve NT Functions]          │  │
    │  │      NtAllocateVirtualMemory → 0x7FFE0001A3B0     │  │
    │  │      NtProtectVirtualMemory  → 0x7FFE0001B8D0     │  │
    │  │      NtUnmapViewOfSection    → 0x7FFE0001C4F0     │  │
    │  │      ↓                                             │  │
    │  │ [Extract Syscall Numbers - HellsGate]             │  │
    │  │      SSN(NtAllocate...) = 0x18                    │  │
    │  │      SSN(NtProtect...)  = 0x50                    │  │
    │  │      ↓                                             │  │
    │  │ [Discover ROP Gadgets - jopcall]                  │  │
    │  │      Find: jmp rcx (0xFF 0xE1)                    │  │
    │  │      Find: ret     (0xC3)                         │  │
    │  │      Build gadget chain: [ntdll+0x8A3C, ...]     │  │
    │  └───────────────────────────────────────────────────┘  │
    └────────┬────────────────────────────────────────────────┘
             │
             ▼
    ┌─────────────────────────────────────────────────────────┐
    │         STAGE 3: Module Stomping                        │
    │  ┌───────────────────────────────────────────────────┐  │
    │  │ 1. Find loaded DLL (e.g., mshtml.dll)            │  │
    │  │    Base: 0x7FFD12340000, Size: 0x500000          │  │
    │  │    ↓                                               │  │
    │  │ 2. NtUnmapViewOfSection(mshtml_base)              │  │
    │  │    [Original mshtml.dll removed from memory]      │  │
    │  │    ↓                                               │  │
    │  │ 3. NtAllocateVirtualMemory(mshtml_base, ...)      │  │
    │  │    [Via ROP chain syscall - no hooks!]            │  │
    │  │    ↓                                               │  │
    │  │ 4. Copy beacon code to stomped region             │  │
    │  │    [PEB still shows "mshtml.dll" - fake!]         │  │
    │  └───────────────────────────────────────────────────┘  │
    └────────┬────────────────────────────────────────────────┘
             │
             ▼
    ┌─────────────────────────────────────────────────────────┐
    │         STAGE 4: Manual PE Loading                      │
    │  ┌───────────────────────────────────────────────────┐  │
    │  │ 1. Parse beacon PE headers                        │  │
    │  │    • NumberOfSections: 5                          │  │
    │  │    • EntryPoint: 0x4500                           │  │
    │  │    ↓                                               │  │
    │  │ 2. Copy sections to stomped memory                │  │
    │  │    • .text  → RVA 0x1000 (code)                   │  │
    │  │    • .rdata → RVA 0x3000 (data)                   │  │
    │  │    ↓                                               │  │
    │  │ 3. Process relocations                            │  │
    │  │    [Fix addresses for new base]                   │  │
    │  │    ↓                                               │  │
    │  │ 4. Resolve imports (custom)                       │  │
    │  │    [PEB walk, no LoadLibrary!]                    │  │
    │  │    ↓                                               │  │
    │  │ 5. NtProtectVirtualMemory(RX)                     │  │
    │  │    [Via ROP chain - change RW → RX]               │  │
    │  └───────────────────────────────────────────────────┘  │
    └────────┬────────────────────────────────────────────────┘
             │
             ▼
    ┌─────────────────────────────────────────────────────────┐
    │         STAGE 5: Header Obfuscation                     │
    │  ┌───────────────────────────────────────────────────┐  │
    │  │ XOR obfuscate first 4096 bytes:                   │  │
    │  │   Before: 4D 5A 90 00 ... (MZ signature)          │  │
    │  │   After:  E6 F1 3B AB ... (Obfuscated)            │  │
    │  │                                                    │  │
    │  │ Randomize section names:                          │  │
    │  │   .text  → .█████                                 │  │
    │  │   .rdata → .█████                                 │  │
    │  └───────────────────────────────────────────────────┘  │
    └────────┬────────────────────────────────────────────────┘
             │
             ▼
    ┌─────────────────────────────────────────────────────────┐
    │         STAGE 6: Beacon Execution                       │
    │  ┌───────────────────────────────────────────────────┐  │
    │  │ • Jump to beacon entry point                      │  │
    │  │ • All API calls via syscalls + ROP chains         │  │
    │  │ • Return addresses point to ntdll gadgets         │  │
    │  │ • Memory looks like legitimate mshtml.dll         │  │
    │  │                                                    │  │
    │  │ ✓ EDR EVASION COMPLETE                            │  │
    │  └───────────────────────────────────────────────────┘  │
    └─────────────────────────────────────────────────────────┘

             Beacon Running in Stealth Mode
```

---

## Summary

### Traditional PE Loading
- **High visibility** - Relies on OS loader and Windows APIs
- **Heavily monitored** - API hooks, ETW, kernel callbacks
- **Forensic artifacts** - Files on disk, PE headers, IAT, module lists
- **Easy to detect** - Standard EDR signatures match

### DawsonLoader UDRL
- **Low visibility** - Custom loader, manual PE processing
- **Bypasses monitoring** - Direct syscalls, no API calls
- **Minimal artifacts** - No files, obfuscated headers, fake module entries
- **Hard to detect** - Requires advanced memory forensics and behavioral analysis

### Key Takeaways
1. **Reflective loading** eliminates file-based detection
2. **Module stomping** hides unbacked memory
3. **Indirect syscalls** bypass userland hooks
4. **ROP/JOP chains** obfuscate call stacks
5. **Header obfuscation** defeats signature scanning

This combination of techniques makes DawsonLoader highly effective against modern EDR solutions that rely on traditional detection methods.

---

## References

- **PE File Format**: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
- **Windows Loader**: https://www.crowdstrike.com/blog/windows-loader-internals/
- **Reflective DLL Injection**: https://github.com/stephenfewer/ReflectiveDLLInjection
- **Module Stomping**: https://www.mdsec.co.uk/2020/09/i-live-to-move-it-windows-lateral-movement-part-2-dcom/
- **Syscall Internals**: https://j00ru.vexillium.org/syscalls/nt/64/
- **ROP Primer**: https://ropemporium.com/
- **EDR Internals**: https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-Putting-Yourself-In-The-EDRs-Shoes.pdf
