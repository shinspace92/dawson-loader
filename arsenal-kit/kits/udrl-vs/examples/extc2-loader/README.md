# ExtC2 Loader Example

This is an adapted loader that loads Beacon and an External C2 DLL at the same time. 
More information on this loader can be found in the following blog post.

https://cobaltstrike.com/blog/revisiting-the-udrl-part-3-beacon-user-data

This is a PoC loader and should only be used in conjunction with External C2 payloads. 
This is because it will be applied universally via BEACON_RDLL_GENERATE. Therefore, if 
you export an HTTP/DNS Beacon it will be bundled with an External C2 dll which will 
fail and remain in memory. Also, it is not compatible with the `inject`, `spawn`, `spawnas`, 
`spawnu`, `elevate` commands as the parent Beacon will link to the child before the External 
C2 DLL.

**Note:** This loader creates a very large payload file. It is therefore important 
to increase the "stage size" when generating artifacts via the Arsenal kit.

## Sleepmask-VS

The extc2-loader can work in combination with Sleepmask-VS to ensure that both Beacon and the External 
C2 DLL are masked at runtime.

https://github.com/Cobalt-Strike/sleepmask-vs

To use these two features together:

* Update the `example.profile` to include `stage.sleep_mask "true";`.
* Compile Sleepmask-VS.
* Load `sleepmask.cna` in the Script Manager.

## Quick Start Guide

To get started, use the instructions provided below.

### Release Build

To use the Release build:
* Start the teamserver with the `example.profile` in the project directory.
* Compile the `Release` build of both the `extc2-dll` and the `extc2-loader`.
* Load `./bin/extc2-loader/prepend-udrl.cna` into Cobalt Strike.
* Export a Beacon payload using the `extc2-pipe-listener` listener.
  * Modify "stage size" if using Cobalt Strike's default shellcode runners/the artifact kit.
* Ensure that the extc2-loader/extc2-dll have network visibility of the External C2 listener (`<team server IP>:2222`).

**Note:** Make sure to use the 32-bit version of Python when testing the x86 builds!

### Debug 

#### ExtC2-Loader

To start Debugging:

* Compile the extc2-dll in `Release` mode. 
* Start the teamserver with the `example.profile` in the project directory.
* Load `./bin/extc2-loader/debug-udrl.cna` into Cobalt Strike.
* Export a RAW Beacon payload from the teamserver using the `extc2-pipe-listener` (our Debug DLL).
* Add the payload file to the project - `py.exe .\udrl.py xxd <path\to\beacon_x64.bin> .\library\DebugDLL.x64.h`.
* Ensure that the extc2-loader/extc2-dll have network visibility of the External C2 listener (`<team server IP>:2222`).
* Start the Visual Studio Debugger (make sure to right-click extc2-loader in the
Solution Explorer->Set As Startup Project).

#### ExtC2-Dll

In Debug mode, the extc2-dll compiles to an executable (`.exe`) which makes it possible to debug it independently
of Cobalt Strike/Beacon.

To start debugging the External C2 component only (without Beacon):

* Start the teamserver with the `example.profile` in the project directory.
* Create an External C2 listener.
* Update `InitExternalC2()` in `Utils.cpp` to include the External C2 server's IP/Port.
* Ensure that the extc2-dll has network visibility of the above mentioned External C2 listener (`<team server IP>:2222`)
* Set `DEBUG_EXTERNAL_C2_ONLY` to 1 in `Debug.h`
* Start the Visual Studio Debugger (make sure to right-click extc2-dll in the
Solution Explorer->Set As Startup Project).

## Additional Considerations

As part of the quick start guide, we provided `example.profile` to get you up
and running. This is a simple profile based upon a public example to avoid
any issues.

You will undoubtedly want to use your own profiles and make modifications to
Beacon. It is therefore important to note that only the communication elements
of a given C2 profile (HTTP/HTTPs/DNS etc) will be applied to a Beacon 
exported via one of the BEACON_RDLL_GENERATE* hooks. You are expected to apply 
PE modifications to a Beacon exported via one of the BEACON_RDLL_GENERATE* 
hooks using Aggressor Functions. 

For example, to mask a given section of Beacon:

```
$payload = pe_mask_section($beacon, ".text", <XORkey>);
```

In addition, to apply the contents of the transform blocks and setup any strings
specified in the C2 profile:

```
$payload = setup_reflective_loader($beacon, $ldr);
$payload = setup_strings($payload);
$payload = setup_transformations($payload, $arch);
```
The above is demonstrated in the obfuscation-loader example.

## Modifications

You're encouraged to make modifications to this code and use them in your
engagements. Do not redistribute this source code. It is not open source. It
is provided as a benefit to licensed Cobalt Strike users.

## License

This code is subject to the end user license agreement for Cobalt Strike. The
complete license agreement is at:

https://www.cobaltstrike.com/license

This code is subject to the license for the Reflective loader project by
Stephen Fewer. The complete license is at:

https://github.com/stephenfewer/ReflectiveDLLInjection/blob/master/LICENSE.txt
