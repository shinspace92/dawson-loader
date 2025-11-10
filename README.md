# Dawson-Loader
>[!Tip] **CTE Tradition of Baking Products during TDYs**

## Todo

### Jopcall ROP/JOP Integration - Implementation Checklist

This checklist tracks the integration of jopcall's return address obfuscation via ROP/JOP chains into DawsonLoader.

#### Phase 1: Setup & Structure Definitions
- [x] **1.1** Add new structures to `src/DawsonLoader.h` after line 76
  - `MemorySection` struct for scanning executable memory
  - `GadgetChain` struct for storing ROP/JOP gadgets
  - `SyscallInfo` struct for syscall metadata
  - Function declarations for gadget discovery
  - Location: After `Section` typedef (line 76)

- [x] **1.2** Create new file `src/jopcall_integration.c`
  - Implement `search_bytes()` - pattern matching helper
  - Implement `pseudorandom()` - RDTSC-based RNG
  - Implement `pick_random_gadget()` - random gadget selection
  - Implement `get_image_memory_sections()` - PE section parser
  - Implement `search_gadget()` - gadget scanner
  - Implement `find_rop_gadgets()` - main gadget discovery function

#### Phase 2: Assembly Modifications
- [x] **2.1** Add `jop_syscall` assembly function to `src/DawsonLoader.c`
  - Location: After existing `HellDescent` function (around line 1700)
  - Purpose: Execute syscalls through ROP/JOP chain
  - Saves/restores callee-saved registers
  - Pushes gadgets to stack in LIFO order
  - Jumps to first gadget (jmp rcx) which calls syscall

#### Phase 3: Syscall Invocation Updates
- [x] **3.1** Initialize gadget chain in `DawsonLoader()` function
  - Location: Near top of `DawsonLoader()` (around line 45-50)
  - Add static `GadgetChain rop_chain` variable
  - Call `find_rop_gadgets(ntdll, &rop_chain)` once on first run

- [x] **3.2** Replace syscall at line 78-81 (DLL stomping - NtProtectVirtualMemory)
  - Current: `HellsGate()` + `HellDescent()`
  - New: `jop_syscall()` with ROP chain

- [x] **3.3** Replace syscall at line 96-100 (Heap allocator - NtProtectVirtualMemory)
  - Same pattern as 3.2

- [x] **3.4** Replace syscall at line 132-136 (VirtualAlloc - NtAllocateVirtualMemory)
  - Note: Left as HellDescent for now (6 parameters, needs extended jop_syscall)

- [x] **3.5** Replace syscall at line 157-161 (Change protection to RX - NtProtectVirtualMemory)
  - Same pattern as 3.2

#### Phase 4: Build System
- [x] **4.1** Update `Makefile`
  - Add compilation rule for `dist/jopcall_integration.o`
  - Update linking to include new object file
  - Ensure `-masm=intel` flag is set

- [x] **4.2** Test compilation
  - Run `make clean && make`
  - Verify no compilation errors
  - Check output: `dist/DawsonLoader.x64.o` should be generated
  - **Result**: SUCCESS - 24KB object file created

#### Phase 5: Testing & Validation
- [ ] **5.1** Test with Cobalt Strike
  - Import updated `DawsonLoader.cna` Aggressor script
  - Generate x64 beacon
  - Verify beacon executes without crashes

- [ ] **5.2** Verify ROP chain execution
  - Use WinDbg to inspect return addresses during syscalls
  - Confirm return addresses point to ntdll gadgets (not loader code)
  - Check that gadgets vary between syscall invocations

- [ ] **5.3** Test against EDR
  - Run against Windows Defender
  - Test with CrowdStrike/SentinelOne if available
  - Monitor for callstack-based detections

#### Phase 6: Future Enhancements
- [ ] **6.1** Add more gadget types
  - `pop rcx; ret` gadgets for register manipulation
  - `add rsp, X; ret` for stack cleanup
  - Chain length randomization (2-5 gadgets)

- [ ] **6.2** Implement gadget caching
  - Store discovered gadgets to avoid re-scanning
  - Add gadget validation (check for hooks)

- [ ] **6.3** Add fallback mechanism
  - If gadget discovery fails, fall back to direct HellDescent
  - Add logging/debugging for gadget discovery failures

- [ ] **6.4** Cross-module gadget chains
  - Scan kernel32.dll, kernelbase.dll for additional gadgets
  - Mix gadgets from multiple modules for diversity

- [ ] **6.5** Hardware breakpoint syscalls (advanced)
  - Use DR0-DR7 registers for execution redirection
  - Combine with ROP chains for multi-layer obfuscation

### Modified Files Reference

| File | Lines Modified | Purpose |
|------|----------------|---------|
| `src/DawsonLoader.h` | After line 76 | Add ROP/JOP structures and function declarations |
| `src/DawsonLoader.c` | Lines 45-50, 70-71, 86-87, 119-120, 142-143, ~1700 | Initialize gadget chain, replace syscalls, add jop_syscall asm |
| `src/jopcall_integration.c` | New file | Gadget discovery and helper functions |
| `Makefile` | Compilation/linking rules | Add new source file to build |

### Key Concepts

**What is ROP/JOP?**
- ROP (Return-Oriented Programming): Chains together existing code snippets (gadgets) that end in `ret`
- JOP (Jump-Oriented Programming): Similar but uses `jmp` instructions
- Purpose: Obfuscate return addresses to evade callstack inspection by EDR

**How jopcall Integration Works:**
1. **Gadget Discovery**: Scan ntdll.dll's executable sections for useful instruction sequences
2. **Gadget Chain Building**: Select random gadgets and arrange them in a chain
3. **Stack Manipulation**: Push gadget addresses onto stack before syscall
4. **Indirect Execution**: Jump to first gadget → syscall → gadgets execute → return to legitimate code

**Benefits:**
- Return addresses point to legitimate ntdll code (not suspicious loader addresses)
- Randomized gadget selection prevents signature-based detection
- Bypasses callstack-based EDR detections
- Maintains compatibility with existing HellsGate/HalosGate syscall number resolution

### Resources & References

- **Original jopcall**: https://github.com/NoahKirchner/jopcall
- **DawsonLoader**: https://github.com/boku7/DawsonLoader
- **ROP Primer**: https://ropemporium.com/
- **Windows Syscall Internals**: https://j00ru.vexillium.org/syscalls/nt/64/
- **Cobalt Strike UDRL Docs**: https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2-extend_user-defined-rdll.htm
