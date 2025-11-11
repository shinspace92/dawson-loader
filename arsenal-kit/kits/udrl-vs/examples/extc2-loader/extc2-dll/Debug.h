#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

// Controls logging for the release build
#define ENABLE_LOGGING 0
#define DEBUG_EXTERNAL_C2_ONLY 0

#if _DEBUG
#define DLOG(fmt) printf(fmt)
#define DLOGF(fmt, ...) printf(fmt, __VA_ARGS__)
#elif defined(NDEBUG) && ENABLE_LOGGING
#define DLOG(fmt) OutputDebugStringA(fmt)
#define DLOGF(fmt, ...) PrintToDebugLog(fmt, __VA_ARGS__)
#else
#define DLOG(fmt);
#define DLOGF(fmt, ...);
#endif

void PrintToDebugLog(const char* fmt, ...);
