# Copilot Instructions for Proxychains-Windows

## Project Overview

**proxychains-windows** is a Windows port of proxychains-ng that enables transparent SOCKS5 proxy chaining through DLL injection and Win32 API hooking.

### Key Information
- **Language**: C (Win32 API)
- **Architecture**: x86 and x64 (multi-architecture support)
- **Build System**: Visual Studio 2019+ (MSBuild)
- **Key Libraries**: MinHook (API hooking), uthash (hash tables)

## Repository Structure

```
src/
├── exe/                    # Main executable
│   ├── main.c             # IPC server, process management
│   └── args_and_config.c  # Configuration parsing
├── dll/                    # Hook DLL (injected)
│   ├── hookdll_main.c     # DLL entry, injection logic
│   ├── hook_connect_win32.c    # Network API hooks
│   └── hook_createprocess_win32.c
└── remote_function.c       # Remote process execution

include/                    # Header files
TODO.md                     # Feature backlog (50+ items)
proxychains.conf           # Configuration template
```

## Building the Project

### Prerequisites
- Visual Studio 2019+ with C++ workload
- Windows SDK
- Git submodules (minhook, uthash)

### Build Commands
```cmd
# Update submodules (ALWAYS RUN FIRST)
git submodule update --init --recursive

# Build x64
devenv.com proxychains.exe.sln /build "Release|x64"

# Build x86  
devenv.com proxychains.exe.sln /build "Release|x86"
```

### Output Files
- `win32_output/proxychains_win32_x64.exe` - Main x64 executable
- `win32_output/proxychains_hook_x64.dll` - x64 hook DLL
- `win32_output/proxychains_hook_x86.dll` - x86 hook DLL

## Testing

```cmd
# Test x64 target
proxychains_win32_x64.exe curl.exe https://ifconfig.me

# Test x86 target (WOW64)
proxychains_win32_x64.exe "C:\Program Files (x86)\app.exe"
```

The x64 executable auto-detects target architecture and injects appropriate DLL.

## Coding Standards

### Architecture-Specific Code
```c
#if defined(_M_X64) || defined(__x86_64__)
    // x64-specific code
#else
    // x86-specific code
#endif
```

### Naming
- Functions: `PascalCase` (public), `snake_case` (internal)
- Variables: `camelCase` or `snake_case`
- Macros: `UPPER_SNAKE_CASE`
- Structures: `PXCH_` prefix

### Error Handling
```c
if (!Result) {
    dwLastError = GetLastError();
    LOGE(L"Failed: %ls", FormatErrorToStr(dwLastError));
    goto error;
}
error:
    if (hHandle) CloseHandle(hHandle);
    return dwLastError;
```

### Logging
Use IPC logging macros:
- `IPCLOGV` - Verbose
- `IPCLOGD` - Debug
- `IPCLOGI` - Info
- `IPCLOGW` - Warning
- `IPCLOGE` - Error

## Common Patterns

### Adding a Hook
```c
// 1. Declare function pointer
typedef int (WINAPI *FpConnect)(SOCKET, ...);
FpConnect orig_fpConnect;

// 2. Define proxy
PROXY_FUNC(connect) {
    g_bCurrentlyInWinapiCall = TRUE;
    result = Socks5_Connect(...);
    g_bCurrentlyInWinapiCall = FALSE;
    return result;
}

// 3. Register
CREATE_HOOK(connect);
```

### Adding Config Option
```c
// 1. In defines_generic.h
typedef struct _PROXYCHAINS_CONFIG {
    PXCH_UINT32 dwNewOption;
} PROXYCHAINS_CONFIG;

// 2. In stdlib_config_reader.c
if (WSTR_EQUAL(sOption, sOptionNameEnd, L"new_option")) {
    pPxchConfig->dwNewOption = value;
}

// 3. In proxychains.conf
#new_option = 0

// 4. Use
if (g_pPxchConfig->dwNewOption) { ... }
```

## Security Rules

1. Validate all inputs (config, hostnames, ports)
2. Use `StringCchCopy`, never `strcpy`
3. Free all resources in error paths
4. Verify DLL architecture matches target
5. No hardcoded credentials

## Documentation

When making changes:
1. Update TODO.md (mark complete: `- [x]`)
2. Update CHANGELOG.md
3. Update README.md (if user-facing)
4. Update TESTING.md (add test scenarios)
5. Update proxychains.conf (new options)

## Constraints

- Cannot inject x86 DLL → x64 process
- Cannot inject x64 DLL → x86 process
- Cannot hook statically-linked executables
- Must support Windows 7-11
- Must work with Cygwin and Win32 builds
