#ifndef _BEACON_GATE_H_
#define _BEACON_GATE_H_
#include <windows.h>

/* Beacon gate defines. */
#define MAX_BEACON_GATE_ARGUMENTS 10
#define beaconGate(i)	((BEACON_GATE_##i)functionCall->functionPtr)
#define arg(i) (ULONG_PTR)functionCall->args[i]

/* Enum to specify what win api is being called. */
typedef enum _WinApi {
    INTERNETOPENA,
    INTERNETCONNECTA,
    VIRTUALALLOC,
    VIRTUALALLOCEX,
    VIRTUALPROTECT,
    VIRTUALPROTECTEX,
    VIRTUALFREE,
    GETTHREADCONTEXT,
    SETTHREADCONTEXT,
    RESUMETHREAD,
    CREATETHREAD,
    CREATEREMOTETHREAD,
    OPENPROCESS,
    OPENTHREAD,
    CLOSEHANDLE,
    CREATEFILEMAPPINGA,
    MAPVIEWOFFILE,
    UNMAPVIEWOFFILE,
    VIRTUALQUERY,
    DUPLICATEHANDLE,
    READPROCESSMEMORY,
    WRITEPROCESSMEMORY,
    EXITTHREAD,
} WinApi;

/**
 * FUNCTION_CALL struct which encapsulates atomic function call.
 *
 * functionPtr - target function to call
 * function - Enum representing target WinApi
 * numOfArgs - number of arguments
 * args - array of ULONG_PTRs containing the passed arguments (e.g. rcx, rdx, ...)
 * bMask - BOOL indicating whether Beacon should be masked during the call
 * ULONG_PTR - retValue of the atomic function call
 */
typedef struct {
    PVOID functionPtr;
    WinApi function;
    int numOfArgs;
    ULONG_PTR args[MAX_BEACON_GATE_ARGUMENTS];
    BOOL bMask;
    ULONG_PTR retValue;
} FUNCTION_CALL, * PFUNCTION_CALL;

/* Currently support max 10 arguments. */
/* NB For x86 we only support std call convention as this is what Windows uses for most Win32 APIs. */
/* This is inspired by railgun (for ref: https://github.com/rapid7/meterpreter/blob/master/source/extensions/stdapi/server/railgun/railgun.h#L53) */
typedef ULONG_PTR(__stdcall* BEACON_GATE_00)(VOID);
typedef ULONG_PTR(__stdcall* BEACON_GATE_01)(ULONG_PTR);
typedef ULONG_PTR(__stdcall* BEACON_GATE_02)(ULONG_PTR, ULONG_PTR);
typedef ULONG_PTR(__stdcall* BEACON_GATE_03)(ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef ULONG_PTR(__stdcall* BEACON_GATE_04)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef ULONG_PTR(__stdcall* BEACON_GATE_05)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef ULONG_PTR(__stdcall* BEACON_GATE_06)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef ULONG_PTR(__stdcall* BEACON_GATE_07)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef ULONG_PTR(__stdcall* BEACON_GATE_08)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef ULONG_PTR(__stdcall* BEACON_GATE_09)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef ULONG_PTR(__stdcall* BEACON_GATE_10)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);

#endif
