#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#include "Debug.h"

#if defined(NDEBUG) && ENABLE_LOGGING
/*
* Print a message to the Debug log
*
* @param fmt The format string to print
* @param ... A variable number of arguments
*/
void PrintToDebugLog(const char* fmt, ...) {
    char buff[512];
    va_list va;
    va_start(va, fmt);
    vsprintf_s(buff, 512, fmt, va);
    va_end(va);
    OutputDebugStringA(buff);
}
#endif
