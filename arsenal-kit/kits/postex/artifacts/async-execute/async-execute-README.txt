Async-execute
-------------

# About

    - Async-execute is an attempt to address an issue in CS whereby long-running BOFs that are executed using inline-execute block Beacon until they complete.
    - The cna script and associated postex dlls implement an asynchronous system.
    - Multiple BOFs can be run one after another, or just once, and Beacon can continue to be used for other tasks. 

# How it works

    - Executing the `async-execute` script will load your specified BOF and set up a postex job that will receive some config settings and your BOF as the payload.
    - Beacon will inject the supplied postex dll either into a process of your choosing, or it will fork/run if no pid is provided. 
    - The postex dll will either run once and execute the BOF provided or run in background mode where it will persist in memory until its associated job is manually terminated.
    - After running the BOF once, or if manually terminated, the postex dll will free itself from memory and exit.
    - By default, all output will go to the Beacon console. This can be controlled by opening the All Jobs window (View->All Jobs) and right-clicking on the BOF job and
      selecting Hide/Show Output. If Output is hidden, it will then only be visible if you interact with the job. 

# Malleable C2 settings

    - Several malleable c2 profile settings influence how things operate.
      - process-inject.bof_allocator
        - This setting tells the postex dll how to allocate memory for the BOF (MapViewOfFile, HeapAlloc, or VirtualAlloc)
      - process-inject.execute
        - Influences how the postex dll is injected
      - post-ex.pipename
        - The pipe name that will be used for both the postex dll communication with Beacon and BOF communication with Beacon. If not specified, this defaults to postex_####.
          It is highly recommended to create a custom pipename and ensure that it contains at least 3 #'s in the name to facilitate sufficient randomness. This option cannot 
          be a single string value without hashes because of the fact that it is used both for the postex pipename and the BOF pipename. 
      - post-ex.thread_hint
        - Sets the thread start address for all threads created by the postex dll. Defaults to "ntdll.dll!RtlUserThreadStart+0x21" if not provided. 

# Script options

    - The script accepts command line options. There are some required options and some optional ones.
      --arch - Required. Specifies the postex dll and BOF architecture. Can be either x64 or x86.
      --bof - Required. The path to the BOF you wish to execute.
      --pid - Optional. If not specified, defaults to fork/run via a value of -1. If specified, the pid of the process to inject the postex dll into.
      --syscall - Optional. If not specified, defaults to indirect. Can be either indirect or private_ntdll. Indirect uses indirect syscalls, private_ntdll maps a private copy
        of ntdll and uses that for syscalls. The postex dll will utilize this for specific api calls and expose it for certain Beacon apis available in beacon.h.
      --mode - Optional. If not specified, defaults to once. Once mode executes one BOF and exits. Background mode executes the provided BOF and then continually processes 
        additional BOFs in an asyncronous manner until its job is manually terminated.
      --fmt - Optional. Allows you to use a format specifier for any arguments you need to pass to your BOF. If the BOF uses arguments, this is required. The arguments will be
        supplied using the --argX option and the format specifier will be applied to each argument in the order you give them. For example, let's say you need to pass two unicode
        strings to the BOF. You would use --fmt ZZ --arg0 "This is the first string" --arg1 "This is the second string". 
      --argX - Optional. A numbered argument to be used with the format specifier to pass arguments to the BOF. The first argument is always --arg0 and the first value in your
        format specifier is applied to it. For each letter in the format specifier, add an associated --argX value. 

# Caveats
  
    - Due to how the team server handles scripts per-user, state cannot be maintained between users. If one user is running the async-execute script, state is maintained only
      for that user. If the other user runs the execute-async script, a new postex dll will be injected for that user.
    - Manually terminating the postex dll job while there are BOFs running will result in the postex dll attempting to terminate each BOF. This can cause undefined behavior,
      depending on what code the BOF was executing. It's generally best to wait to terminate the postex job until all BOFs have completed. 

# BOFs and beacon.h considerations

    - Because the BOFs are executing outside of Beacon by a standalone postex dll, not all of the APIs provided in beacon.h are exposed. In fact, any Beacon API used from beacon.h
      will go through the postex dll rather than Beacon. Effort has been made to maintain 1:1 alignment with how Beacon would treat the api call, but some functions cannot be 
      exposed currently. 
      
    - The following is a list of beacon.h functions that will continue to work normally:

        - LoadLibraryA - Will ultimately call kernel32!LoadLibraryA
        - FreeLibrary - Will ultimately call kernel32!FreeLibrary
        - GetProcAddress - Will ultimately call kernel32!GetProcAddress
        - GetModuleHandleA - Will ultimately call kernel32!GetModuleHandleA
        - BeaconDataParse
        - BeaconDataPtr
        - BeaconDataInt
        - BeaconDataShort
        - BeaconDataLength
        - BeaconDataExtract
        - BeaconFormatAlloc
        - BeaconFormatReset
        - BeaconFormatPrintf
        - BeaconFormatAppend
        - BeaconFormatFree
        - BeaconFormatToString
        - BeaconFormatInt
        - BeaconOutput
        - BeaconPrintf 
        - BeaconErrorD 
        - BeaconErrorDD
        - BeaconErrorNA
        - BeaconIsAdmin
        - toWideChar

    - The following beacon apis will inherit the syscall method specified in options and will call the native api

        - BeaconVirtualAlloc
        - BeaconVirtualAllocEx
        - BeaconVirtualProtect
        - BeaconVirtualProtectEx
        - BeaconVirtualFree
        - BeaconGetThreadContext
        - BeaconSetThreadContext
        - BeaconResumeThread
        - BeaconOpenProcess
        - BeaconOpenThread
        - BeaconCloseHandle
        - BeaconUnmapViewOfFile
        - BeaconVirtualQuery
        - BeaconDuplicateHandle
        - BeaconReadProcessMemory
        - BeaconWriteProcessMemory

    - The following beacon apis are currently unsupported and should not be called from BOFs. They will either simply return or return false. This may change in the future. 

        - BeaconUseToken
        - BeaconRevertToken
        - BeaconGetSpawnTo
        - BeaconCleanupProcess
        - BeaconInjectProcess
        - BeaconSpawnTemporaryProcess
        - BeaconInjectTemporaryProcess
        - BeaconInformation
        - BeaconAddValue
        - BeaconGetValue
        - BeaconRemoveValue
        - BeaconDataStoreGetItem
        - BeaconDataStoreProtectItem
        - BeaconDataStoreUnprotectItem
        - BeaconDataStoreMaxEntries
        - BeaconGetCustomUserData
        - BeaconGetSyscallInformation
        - BeaconDisableBeaconGate
        - BeaconEnableBeaconGate
