# GitHub Copilot Instructions for Proxychains-Windows

## Project Context

This is **proxychains-windows**, a Windows port of proxychains-ng that provides SOCKS5 proxy chaining functionality through DLL injection and API hooking. The project enables transparent proxying of Windows applications by intercepting network-related Win32 API calls.

## Architecture Overview

### Core Components

1. **Main Executable (proxychains.exe)**
   - Location: `src/exe/`
   - Purpose: Launches target process, manages IPC, coordinates DLL injection
   - Key files: `main.c`, `args_and_config.c`

2. **Hook DLL (proxychains_hook_x64.dll / proxychains_hook_x86.dll)**
   - Location: `src/dll/`
   - Purpose: Injected into target process to hook network APIs
   - Key files: `hookdll_main.c`, `hook_connect_win32.c`, `hook_createprocess_win32.c`

3. **Configuration System**
   - Location: `src/`, `include/`
   - Files: `stdlib_config_reader.c`, `defines_generic.h`
   - Handles proxy configuration, rules, hosts file

4. **Remote Injection Code**
   - Location: `src/remote_function.c`
   - Compiled into binary blobs for both x86 and x64
   - Executed in target process to load hook DLL

### Technology Stack

- **Language**: C (Win32 API)
- **Build System**: Visual Studio 2019+ (MSBuild)
- **Key Libraries**: 
  - MinHook (API hooking)
  - uthash (hash tables)
  - Win32 API (CreateProcess, Named Pipes, etc.)

## Coding Guidelines

### Code Style

1. **Naming Conventions**
   - Functions: `PascalCase` for public, `snake_case` for internal
   - Variables: `camelCase` or `snake_case` (be consistent within file)
   - Macros: `UPPER_SNAKE_CASE`
   - Structures: `PXCH_` prefix, e.g., `PXCH_PROXY_DATA`

2. **Architecture-Specific Code**
   ```c
   #if defined(_M_X64) || defined(__x86_64__)
       // x64 code
   #else
       // x86 code
   #endif
   ```

3. **Logging**
   - Use `IPCLOG*` macros for IPC-based logging
   - Use `LOG*` macros for direct console logging
   - Levels: `LOGV` (verbose), `LOGD` (debug), `LOGI` (info), `LOGW` (warn), `LOGE` (error)

4. **Error Handling**
   - Check all Win32 API return values
   - Use `GetLastError()` and `FormatErrorToStr()` for error messages
   - Use `goto` for error cleanup (common in Win32 C code)

### Platform Considerations

1. **Cross-Architecture Support**
   - Always implement both x86 and x64 versions of injection code
   - Use `bIsX86` flag to select appropriate DLL/function pointers
   - Test on both 32-bit and 64-bit target processes

2. **Windows Version Compatibility**
   - Support Windows 7+ (target SDK: v141_xp)
   - Use `GetNativeSystemInfo()` instead of `GetSystemInfo()`
   - Avoid APIs not available in Windows 7

3. **Cygwin/MSYS2 Support**
   - Code has both `__CYGWIN__` and `!__CYGWIN__` paths
   - Be careful with path separators and line endings
   - Test on both native Win32 and Cygwin builds

## Key Concepts

### DLL Injection Process

1. Main exe creates target process suspended
2. Allocates memory in target process
3. Writes remote function + hook DLL path to target
4. Modifies entry point or creates remote thread
5. Target loads hook DLL and initializes hooks
6. Target resumes execution with hooks active

### Fake IP DNS Resolution

1. Intercept `GetAddrInfoW` calls
2. Generate fake IP from hostname hash
3. Store hostname<->fake IP mapping in main exe
4. When connecting to fake IP, resolve via proxy
5. Send real hostname to SOCKS5 proxy for DNS

### IPC Architecture

- Named pipe between main exe and child processes
- Bidirectional communication for:
  - DNS queries (fake IP resolution)
  - Logging messages
  - Process lifecycle events

## Implementation Patterns

### Adding a New Hook

```c
// 1. Declare function pointer type
typedef int (WINAPI *FpNewFunction)(PARAMS);

// 2. Declare original function pointer
FpNewFunction orig_fpNewFunction;

// 3. Define proxy function
PROXY_FUNC(NewFunction) {
    g_bCurrentlyInWinapiCall = TRUE;
    
    // Pre-processing
    // ...
    
    // Call original or proxy logic
    result = orig_fpNewFunction(params);
    
    // Post-processing
    // ...
    
    g_bCurrentlyInWinapiCall = FALSE;
    return result;
}

// 4. Create and enable hook in InitHook
CREATE_HOOK(NewFunction);
```

### Adding Configuration Option

```c
// 1. Add field to PROXYCHAINS_CONFIG in defines_generic.h
typedef struct _PROXYCHAINS_CONFIG {
    // ...
    PXCH_UINT32 dwNewOption;
} PROXYCHAINS_CONFIG;

// 2. Parse in stdlib_config_reader.c
if (WSTR_EQUAL(sOption, sOptionNameEnd, L"new_option")) {
    // Parse and set pPxchConfig->dwNewOption
}

// 3. Add to proxychains.conf
# New option description
#new_option = value

// 4. Use in hook DLLs
if (g_pPxchConfig->dwNewOption) {
    // Feature logic
}
```

### Working with TODO List Features

When implementing features from TODO.md:

1. **Dynamic Chain Support**
   - Modify `Ws2_32_LoopThroughProxyChain` in `hook_connect_win32.c`
   - Add proxy state tracking (UP/DOWN)
   - Skip failed proxies, continue chain

2. **HTTP/HTTPS Proxy Support**
   - Add new proxy type: `PXCH_PROXY_TYPE_HTTP`
   - Implement HTTP CONNECT method
   - New connect/handshake functions in `hook_connect_win32.c`

3. **UDP Associate for DNS**
   - Implement SOCKS5 UDP associate command
   - Create UDP socket management
   - Forward DNS queries through UDP tunnel

## Testing Guidelines

1. **Manual Testing**
   - Test with curl (both x86 and x64 versions)
   - Test with browser (Chrome, Firefox)
   - Test with SSH clients
   - Verify with "what is my IP" services

2. **Architecture Testing**
   - Run x64 exe with x64 target
   - Run x64 exe with x86 target
   - Verify correct DLL injection

3. **Configuration Testing**
   - Test all config options
   - Test with invalid configs
   - Test with multiple proxies

## Common Pitfalls

1. **DLL Path Issues**
   - Always use absolute paths for DLL injection
   - Handle both x86 and x64 DLL paths
   - Check DLL exists before injection

2. **Process Architecture Mismatch**
   - Cannot inject x86 DLL into x64 process
   - Cannot inject x64 DLL into x86 process
   - Use `IsWow64Process()` to detect

3. **IPC Synchronization**
   - Named pipes can block if not handled properly
   - Use overlapped I/O
   - Handle pipe disconnection gracefully

4. **Memory Management**
   - Free all `VirtualAllocEx` allocations
   - Close all process/thread handles
   - Use `HeapAlloc/HeapFree` consistently

## Security Considerations

1. **DLL Injection Risks**
   - Some antivirus may flag as malware
   - Windows Defender SmartScreen may block
   - Use code signing for distribution

2. **Privilege Escalation**
   - Cannot inject into higher-privilege processes
   - Run as administrator if needed
   - Handle access denied gracefully

3. **Input Validation**
   - Validate all config file inputs
   - Check buffer sizes
   - Sanitize proxy hostnames

## Documentation Requirements

When adding features:

1. Update `README.md` if user-facing
2. Update `TODO.md` to mark as complete
3. Update `CHANGELOG.md` with changes
4. Add examples to `TESTING.md` if needed
5. Update `proxychains.conf` with new options

## Build System

### Visual Studio Projects

- Solution file: `proxychains.exe.sln`
- Configurations: Debug|Release, x86|x64
- Output: `win32_output/` directory
- Remote function build: Uses pre-built binaries or builds from source

### CI/CD

- GitHub Actions: `.github/workflows/msvc.yml`
- Builds both architectures
- Creates unified release package
- Uploads artifacts

## Quick Reference

### Important Macros
- `PXCH_DO_NOT_INCLUDE_STRSAFE_NOW` - Control when strsafe.h is included
- `PROXY_FUNC(name)` - Declare hook function
- `CREATE_HOOK(name)` - Create and register hook
- `IPCLOG*` - IPC-based logging
- `IsX64()` - Compile-time architecture check

### Key Structures
- `PROXYCHAINS_CONFIG` - Configuration data
- `PXCH_INJECT_REMOTE_DATA` - Data passed to remote function
- `PXCH_PROXY_DATA` - Proxy definition
- `PXCH_RULE` - Routing rule
- `PXCH_HOST_PORT` - Host and port combination

### Key Functions
- `InjectTargetProcess()` - Main injection logic
- `RemoteCopyExecute()` - Write and execute remote code
- `Ws2_32_LoopThroughProxyChain()` - Connect through proxy chain
- `Socks5_Connect()` / `Socks5_Handshake()` - SOCKS5 protocol

## Getting Help

- Check `doc/DEVNOTES.md` for developer notes
- Review existing hooks for patterns
- Search for similar functionality in proxychains-ng (Linux version)
- Use Visual Studio debugger with debug builds

## Summary

This is a complex low-level Windows project requiring:
- Deep understanding of Win32 API
- DLL injection techniques
- Network programming (sockets, protocols)
- Multi-architecture support
- Careful memory and resource management

Always test thoroughly on both x86 and x64 targets. Use logging extensively. Handle errors gracefully. Document non-obvious code.
