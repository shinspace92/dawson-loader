#pragma once

#include <stdlib.h>

#define NO_DATA_AVAILABLE -1
#define EXTC2PIPE_READ_ERROR -2
#define EXTC2SOCKET_READ_ERROR -2
#define BUFFER_MAX_SIZE 1024 * 1024

#pragma comment(lib, "ws2_32.lib")

typedef struct _EXTC2_SYNC_INFO {
    HANDLE ExtC2Init;
    HANDLE ExtC2StopEvent;
    HANDLE ExtC2SleepEvent;
    HANDLE ExtC2ContinueEvent;
} EXTC2_SYNC_INFO, * PEXTC2_SYNC_INFO;

#define CLOSE_HANDLE(x) if(x != INVALID_HANDLE_VALUE) CloseHandle(x);
#define CLOSE_SOCKET(x) if(x != INVALID_SOCKET) closesocket(x);
#define FREE_BUFFER(x) if(x != NULL) free(x);

void go(PEXTC2_SYNC_INFO extC2Info);
