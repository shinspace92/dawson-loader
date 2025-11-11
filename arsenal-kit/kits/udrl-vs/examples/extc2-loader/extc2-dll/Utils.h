#pragma once
#include <windows.h>

SOCKET InitExternalC2();
HANDLE ConnectToBeaconPipe();
int ReadFrameFromBeaconPipe(HANDLE pipeHandle, char* buffer);
BOOL WriteFrameToBeaconPipe(HANDLE pipeHandle, const char* buffer, DWORD length);
int ReceiveFrameFromExtC2Server(SOCKET socket, char* buffer);
BOOL SendFrameToExtC2Server(SOCKET socket, const char* buffer, int length);
