# SleepMask 

This package contains example sleep_mask source code to support
the ability to mask and unmask Beacon in memory.

Only the Cobalt Strike version that was released with this arsenal kit is
supported.  This package maybe compatible with previous versions, however that
is not guaranteed. It is recommended to download the corresponding Arsenal Kit
that was released with the version of Cobalt Strike that you are using.

The files in the src directory contain the function to support the two
sleep mask types for a specific type of Beacon.

Type       |     Supports
-----------|----------------------------------------
default    |     HTTP, HTTPS and DNS Beacons
pivot      |     SMB and TCP Beacons

# How it Works

Cobalt Strike when generating a Beacon will call the BEACON_SLEEP_MASK
hook to allow the user to override the default sleep mask code.

The BEACON_SLEEP_MASK hook passes in the type and architecture that is
being generated.  This information is used to open the appropriate 
object file containing your sleep_mask code.  The sleep_mask code will
be extracted and updated in Beacon instead of the default.

Each release may introduce new operations that are performed in the sleep mask
which required reworking the data structures and functions in the sleep mask
code.  These could be breaking changes and will require you to modify any of
your existing sleep mask implementations. Use the examples in the sleepmask/src
directory as a reference as this source has been updated to work with the
latest Cobalt Strike release.

The parameters that are passed into the sleep mask function have been changed.
The first parameter is pointer to the SLEEPMASK_INFO data structure and the
second parameter is a pointer to the FUNCTION_CALL data structure.  See the
header files in the sleepmask/src directory for additional information. The
SLEEPMASK_INFO data structure contains information for obfuscating beacon
in memory such as Beacon's PE sections and Heap Memory.  The FUNCTION_CALL
data structure contains information for proxying WinAPI functions through the
sleep mask, which is referred to as Beacon Gate.  The default behavior when
proxying a supported WinAPI function will mask beacon, execute the Windows API
call, unmask beacon, and the result will be available to Beacon.  You can
customize the behavior to do whatever you require, for example implement your
own system call implementation.

The sleep mask continues to execute as a Beacon Object File (BOF) in its own
memory region.  This memory region is allocated using VirtualAlloc by default.
You can now provide your own memory region through a User Defined Reflective
Loader (UDRL) allowing the use of other memory allocation techniques.  For an
example see the udrl-vs/examples/bud-loader.

This release also introduces the ability to clean up memory on ExitThread when
configured in the BeaconGate and module stomping is not configured.  In this
case the sleep mask function will release the memory for Beacon and other
ALLOCATED_MEMORY entries prior to calling ExitThread.  If an ALLOCATED_MEMORY
entry is set to the purpose of PURPOSE_SLEEPMASK_MEMORY, then the entry will
not be released as you are currently executing in this memory region.  For
this entry you will need to implement your own technique to release the memory
for example using a timer.

There is a code size requirement that cannot exceed 32768 bytes (32 KB) bytes.
If this occurs the default sleep_mask code will be used.

Use of beacon API functions are available, however only before the code
sections are masked and after the code sections are unmasked.

Use of external functions are supported using the dynamic function
resolution syntax as LIBRARY$Function.

Additional files are also included within the src directory to support
additional sleep mask capabilities.  These capabilities are disabled
by default and can be enabled by updating the define tags found in
src/sleepmask.c.

One of the sleep mask capabilities is to provide code to implement the use of a
system call for NtProtectVirtualMemory instead of using VirtualProtect. The
SysWhispers3 public repository was used to generate the code for the system call
with additional modification to work with the sleep mask kit.

The system call method that is referenced as 'jumper' in the SysWhispers3
project will be referred to as 'indirect' in the sleep mask kit to be consistent
with the Cobalt Strike terminology.  This affects the file names, build scripts
and documentation, however does not affect the code in the generated files.

The new system call method 'beacon' which implements the 'indirect' method
was added to the sleep mask kit with the 4.10 release.  This implementation
will retrieve the system call information that was either resolved by beacon
or supplied via a UDRL.  This removes the SysWhispers3 implementation for
resolving of the NtProtectVirtualMemory function address and sysnum.  The
custom assembly has been modified as the calls to set the function address
and sysnum have been simplified.

File                           |  Description
-------------------------------|-------------------------------------
beacon.h                       |  Defines the internal beacon APIs that are available
beacon_gate.c                  |  Defines the beacon gate functions for proxying supported WinAPI calls
beacon_gate.h                  |  Defines the beacon gate data structures
bofdefs.h                      |  Defines the dynamic function resolution prototypes for Windows APIs
cfg.c                          |  Defines Control Flow Guard (CFG) bypass (x64 only)
common_logger.h                |  Common debug logging MACROS and function
common_mask.c                  |  Common masking functions
evasive_sleep.c                |  Obfuscate the sleep mask code using CreateTimerQueueTimer (x64 only)
evasive_sleep_stack_spoof.c    |  Same as evasive_sleep.c with stack spoofing (x64 only)
mask_text_section.c            |  Mask the text section of beacon prior to sleeping.
memory_cleanup.c               |  Defines the memory cleanup functions for cleanup of memory on ExitThread
sleepmask.c                    |  Defines the sleep mask functions for the default sleep mask type
sleepmask.h                    |  Defines the common sleep mask data structures
sleepmask_pivot.c              |  Defines the sleep mask functions for the pivot sleep mask type
syscall.h                      |  Defines the header file for use with the system calls source
syscalls_beacon.c              |  Implements the system call using the beacon method
syscalls_embedded.c            |  Implements the system call using the embedded method
syscalls_indirect.c            |  Implements the system call using the indirect method
syscalls_indirect_randomized.c |  Implements the system call using the indirect_randomized method

Warnings:
- The Control Flow Guard (CFG) bypass is disabled by default with the evasive_sleep capability.
- The CFG bypass is needed for process injection into processes protected by CFG.
- The artifactkit_stack_spoof setting of true will not work with the evasive_sleep capability.
- The provided spoofed stack in evasive_sleep_stack_spoof.c was determined by values from a specific  
  version of Windows 10.  See Evasive Sleep Stack Spoof Information section.
- The DLOG and DLOGT macros do not work in the 'syscalls' files and will cause a crash.

# Evasive Sleep Information

The sleep mask kit provides code for additional evasion techniques that you will need to
enable as it is disabled by default and only supported on x64 systems.  There are two
implementations which are found in evasive_sleep.c and evasive_sleep_stack_spoof.c.
Both implementations will change the memory protection of the sleep mask BOF between
RW and RX, obfuscate the memory for the sleep mask BOF, and sleep for the specified time.
The evasive_sleep_stack_spoof.c file adds the ability to spoof the stack, however this
capability needs to target specific Windows versions in order to look valid.

In order to enable these techniques set the EVASIVE_SLEEP define to 1 in the sleepmask.c
file. Then search for EVASIVE_SLEEP define again to uncomment the implementation to
use, the default is evasive_sleep.c.

The evasive_sleep_stack_spoof implementation will require additional investigation
and testing for a targeted Windows versions as the spoofed stack may look valid
for one version but not for another version.  The reason is offsets within the
targeted dlls may change between versions more so between major versions.  For example
a stack that is targeted for Windows 10 may not look the same on Windows 11.

In order to make the spoofed stack look valid on a target, you will need to investigate
the valid call stacks on a comparable Windows version to determine the values needed
in the evasive_sleep_stack_spoof code.

To help with determining this information the code for a utility process is being provided.
The source code for the utility is located in the arsenal-kit/utils/getFunctionOffset
directory.  The build instructions can be found in the source file.  This utility needs
to be executed on the comparable Windows version.

How to choose your call stack to spoof.
Steps:
 - Use process hacker or similar utility on a representative
   Windows target system to find a stack you want to spoof.
 - Use the module, function and offset information as input
   to the getFunctionOffset utility located in arsenal-kit/utils.
 - The getFunctionOffset utility outputs information including
   the code to use in the set_callstack() function.

Note: Should look for a stack with NtWaitForSingleObject at the top.
      Then use the information for the remaining stack frames.
Note: The module extension is optional.

Example using the getFunctionOffset helper utility to generate the code:
 - getFunctionOffset.exe ntdll.dll TpReleasePool 0x402
 - getFunctionOffset.exe kernel32.dll BaseThreadInitThunk 0x14
 - getFunctionOffset.exe ntdll RtlUserThreadStart 0x21


# Modifications

You're encouraged to make modifications to the code, compiler versions, or
compiler options if the sleep mask is being used to identify your Beacons.

In the source code there are items that cannot be modified because beacon
uses these items to populate the data structures to call the sleep_mask
function.  If these are changed beacon will fail.

Do not redistribute this source code. It is not open source. It is
provided as a benefit to licensed Cobalt Strike users.

# Usage
```
./build.sh <sleep_method> <syscalls> <output directory>

Sleep Method     - Choose which function to use for sleeping
                      Valid options are: Sleep, WaitForSingleObject
Syscalls         - set the system calls method"
                      Valid values [none embedded indirect indirect_randomized beacon]"
Output Directory - Destination directory to save the output

```

Example:
```
./build.sh WaitForSingleObject indirect /tmp/dist
```

You will need the following:

- Minimal GNU for Windows Cross-Compiler - apt-get install mingw-w64

# Load into Cobalt Strike

To use the sleep mask object file, load the sleepmask.cna into Cobalt Strike.

Open the Scripts manager, Cobalt Strike -> Scripts

Load `<output directory>/sleepmask/sleepmask.cna`

# License

This code is subject to the end user license agreement for Cobalt Strike. The
complete license agreement is at:

https://www.cobaltstrike.com/license
