
void cleanup_allocate_entry(PALLOCATED_MEMORY_REGION memoryRegion) {
	/* Check to see if this region can be cleaned */
	if (!memoryRegion->CleanupInformation.Cleanup) {
		DLOGT("cleanup_allocate_entry: Cleanup flag set to FALSE");
	}
	else if (memoryRegion->CleanupInformation.AllocationMethod == METHOD_VIRTUALALLOC) {
		DLOG("Calling VirtualFree(%x, 0, MEM_RELEASE)\n", memoryRegion->AllocationBase);
		VirtualFree(memoryRegion->AllocationBase, 0, MEM_RELEASE);
	}
	else if (memoryRegion->CleanupInformation.AllocationMethod == METHOD_NTMAPVIEW) {
		DLOG("Calling UnmapViewOfFile(%x)\n", memoryRegion->AllocationBase);
		UnmapViewOfFile(memoryRegion->AllocationBase);
	}
	else if (memoryRegion->CleanupInformation.AllocationMethod == METHOD_HEAPALLOC) {
		if (memoryRegion->CleanupInformation.AdditionalCleanupInformation.HeapAllocInfo.DestroyHeap) {
			DLOG("Calling HeapDestroy(%x)\n", memoryRegion->CleanupInformation.AdditionalCleanupInformation.HeapAllocInfo.HeapHandle);
			HeapDestroy(memoryRegion->CleanupInformation.AdditionalCleanupInformation.HeapAllocInfo.HeapHandle);
		}
		else {
			DLOG("Calling HeapFree(%p, 0, %p)\n", memoryRegion->CleanupInformation.AdditionalCleanupInformation.HeapAllocInfo.HeapHandle, memoryRegion->AllocationBase);
			HeapFree(memoryRegion->CleanupInformation.AdditionalCleanupInformation.HeapAllocInfo.HeapHandle, 0, memoryRegion->AllocationBase);
		}
	}
	else if (memoryRegion->CleanupInformation.AllocationMethod == METHOD_MODULESTOMP) {
		DLOG("Calling FreeLibrary(%x)\n", memoryRegion->CleanupInformation.AdditionalCleanupInformation.ModuleStompInfo.ModuleHandle);
		FreeLibrary(memoryRegion->CleanupInformation.AdditionalCleanupInformation.ModuleStompInfo.ModuleHandle);
	}
	else {
		DLOG("cleanup_allocate_entry: Cleanup flag set to TRUE, however unsupported AllocationMethod: %d", memoryRegion->CleanupInformation.AllocationMethod);
	}
}

void cleanup_allocate_memory(PSLEEPMASK_INFO sleepMaskInfo) {
	int i = 0;
	int totalEntries = sizeof(sleepMaskInfo->beacon_info.allocatedMemory.AllocatedMemoryRegions) / sizeof(ALLOCATED_MEMORY_REGION);
	PALLOCATED_MEMORY_REGION memoryRegion = &sleepMaskInfo->beacon_info.allocatedMemory.AllocatedMemoryRegions[0];

	/*	Loop through the regions to find memory to cleanup	*/
	for (i = 0; i < totalEntries; ++i, ++memoryRegion) {
		if (memoryRegion->Purpose == PURPOSE_EMPTY) {
			DLOG("cleanup_allocate_memory: memory region %d is empty\n", i);
			continue;
		}
		else if (memoryRegion->Purpose == PURPOSE_SLEEPMASK_MEMORY) {
			/* Requires a timer, which will not be supported by the CS sleepmask */
			DLOG("cleanup_allocate_memory: memory region %d is the sleepmask at AllocationBase %p.  Cleanup is not supported as it requires a timer.\n", i, memoryRegion->AllocationBase);
		}
		else {
			DLOG("cleanup_allocate_memory: memory region %d is for purpose %d at AllocationBase %p\n", i, memoryRegion->Purpose, memoryRegion->AllocationBase);
			cleanup_allocate_entry(memoryRegion);
		}
	}
}
