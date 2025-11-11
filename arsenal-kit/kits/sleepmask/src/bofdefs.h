#pragma once

#include "winsock2.h"
#include <windows.h>

// Kernel32 function definitions
WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE handle);
WINBASEAPI BOOL WINAPI KERNEL32$ConnectNamedPipe(HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateTimerQueue(VOID);
WINBASEAPI BOOL WINAPI KERNEL32$CreateTimerQueueTimer(PHANDLE phNewTimer, HANDLE TimerQueue, WAITORTIMERCALLBACK Callback, PVOID Parameter, DWORD DueTime, DWORD Period, ULONG Flags);
WINBASEAPI BOOL WINAPI KERNEL32$DeleteTimerQueue(HANDLE TimerQueue);
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess(VOID);
WINBASEAPI DWORD WINAPI KERNEL32$GetCurrentThreadId(VOID);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleW(LPCWSTR lpLibFileName);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);
WINBASEAPI BOOL WINAPI KERNEL32$GetThreadContext(HANDLE hThread, LPCONTEXT lpContext);
WINBASEAPI void * WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI BOOL WINAPI KERNEL32$HeapDestroy(HANDLE hHeap);
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryW(LPCWSTR lpLibFileName);
WINBASEAPI LPWSTR WINAPI KERNEL32$lstrcpyW(LPWSTR lpString1, LPCWSTR lpString2);
WINBASEAPI HANDLE WINAPI KERNEL32$OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);
WINBASEAPI VOID WINAPI KERNEL32$OutputDebugStringA(LPCSTR lpOutputString);
WINBASEAPI BOOL WINAPI KERNEL32$PeekNamedPipe(HANDLE  hNamedPipe, LPVOID  lpBuffer, DWORD   nBufferSize, LPDWORD lpBytesRead, LPDWORD lpTotalBytesAvail, LPDWORD lpBytesLeftThisMessage);
NTSYSAPI VOID KERNEL32$RtlCaptureContext(PCONTEXT ContextRecord);
WINBASEAPI BOOL WINAPI KERNEL32$SetEvent(HANDLE hEvent);
WINBASEAPI BOOL WINAPI KERNEL32$SetThreadContext(HANDLE hThread, const CONTEXT *lpContext);
WINBASEAPI void WINAPI KERNEL32$Sleep(DWORD dwMilliseconds);
WINBASEAPI BOOL WINAPI KERNEL32$UnmapViewOfFile(LPCVOID lpBaseAddress);
WINBASEAPI BOOL WINAPI KERNEL32$VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
WINBASEAPI BOOL WINAPI KERNEL32$VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
WINBASEAPI DWORD WINAPI KERNEL32$WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);

#ifdef _WIN64
NTSYSAPI PRUNTIME_FUNCTION WINAPI KERNEL32$RtlLookupFunctionEntry(DWORD64 ControlPc, PDWORD64 ImageBase, PUNWIND_HISTORY_TABLE HistoryTable);
#endif

// WS2_32 function definitions
WINSOCK_API_LINKAGE SOCKET WSAAPI WS2_32$accept(SOCKET s, struct sockaddr* addr, int* addrlen);
WINSOCK_API_LINKAGE int WSAAPI WS2_32$recv(SOCKET s, void* buf, int len, int flags);

// NTDLL function definitions
NTSYSAPI NTSTATUS NTAPI NTDLL$NtContinue(PCONTEXT ThreadContext, BOOLEAN RaiseAlert );

// Advapi32 function definitions
typedef struct
{
    DWORD   Length;
    DWORD   MaximumLength;
    PVOID   Buffer;
} USTRING;

WINBASEAPI NTSTATUS WINAPI ADVAPI32$SystemFunction032(USTRING *data, const USTRING *key);


// MSVCRT function definitions
WINBASEAPI int       __cdecl MSVCRT$memcmp(const void *_Buf1,const void *_Buf2,size_t _Size);
WINBASEAPI int       __cdecl MSVCRT$rand();
WINBASEAPI int       __cdecl MSVCRT$sprintf_s(char *_DstBuf, size_t _DstSize, const char *_Format, ...);
WINBASEAPI int       __cdecl MSVCRT$vsprintf_s(char *_DstBuf, size_t _DstSize, const char *_Format, va_list _ArgList);

// Kernel32 function definitions
#define CloseHandle               KERNEL32$CloseHandle
#define ConnectNamedPipe          KERNEL32$ConnectNamedPipe
#define CreateEventA              KERNEL32$CreateEventA
#define CreateTimerQueue          KERNEL32$CreateTimerQueue
#define CreateTimerQueueTimer     KERNEL32$CreateTimerQueueTimer
#define DeleteTimerQueue          KERNEL32$DeleteTimerQueue
#define GetCurrentProcess         KERNEL32$GetCurrentProcess
#define GetCurrentThreadId        KERNEL32$GetCurrentThreadId
#define GetLastError              KERNEL32$GetLastError
#define GetModuleHandleW          KERNEL32$GetModuleHandleW
#define GetProcessHeap            KERNEL32$GetProcessHeap
#define GetThreadContext          KERNEL32$GetThreadContext
#define HeapAlloc                 KERNEL32$HeapAlloc
#define HeapDestroy               KERNEL32$HeapDestroy
#define HeapFree                  KERNEL32$HeapFree
#define LoadLibraryW              KERNEL32$LoadLibraryW
#define lstrcpyW                  KERNEL32$lstrcpyW
#define OpenThread                KERNEL32$OpenThread
#define OutputDebugStringA        KERNEL32$OutputDebugStringA
#define PeekNamedPipe             KERNEL32$PeekNamedPipe
#define RtlCaptureContext         KERNEL32$RtlCaptureContext
#define SetEvent                  KERNEL32$SetEvent
#define SetThreadContext          KERNEL32$SetThreadContext
#define Sleep                     KERNEL32$Sleep
#define UnmapViewOfFile           KERNEL32$UnmapViewOfFile
#define VirtualFree               KERNEL32$VirtualFree
#define VirtualProtect            KERNEL32$VirtualProtect
#define WaitForSingleObject       KERNEL32$WaitForSingleObject

#ifdef _WIN64
#define RtlLookupFunctionEntry    KERNEL32$RtlLookupFunctionEntry
#endif

// WS2_32 function definitions
#define accept                    WS2_32$accept
#define recv                      WS2_32$recv

// NTDLL function definitions
#define NtContinue                NTDLL$NtContinue

// Advapi32 function definitions
#define SystemFunction032         ADVAPI32$SystemFunction032

// MSVCRT function definitions
#define memcmp                    MSVCRT$memcmp
#define rand                      MSVCRT$rand
#define sprintf_s                 MSVCRT$sprintf_s
#define vsprintf_s                MSVCRT$vsprintf_s
