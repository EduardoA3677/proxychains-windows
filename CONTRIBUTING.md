# Contributing to Proxychains-Windows

Thank you for your interest in contributing to proxychains-windows! This document provides guidelines and information for contributors.

## Getting Started

### Prerequisites

- **Windows 10/11 x64** (required for development and testing)
- **Visual Studio 2019 or later** with C++ desktop development workload
- **Windows SDK** (installed with Visual Studio)
- **Git** with submodule support

### Setting Up the Development Environment

1. Clone the repository:
   ```cmd
   git clone https://github.com/EduardoA3677/proxychains-windows.git
   cd proxychains-windows
   ```

2. Initialize submodules:
   ```cmd
   git submodule update --init --recursive
   ```

3. Open `proxychains.exe.sln` in Visual Studio.

4. Build both architectures:
   - Select `Release|x64` → Build Solution
   - Select `Release|x86` → Build Solution

### Output Files

After building:
- `win32_output/proxychains_win32_x64.exe` — Main x64 executable
- `win32_output/proxychains_hook_x64.dll` — x64 hook DLL
- `win32_output/proxychains_hook_x86.dll` — x86 hook DLL

## Architecture Overview

### Components

```
┌─────────────────┐     ┌──────────────────────────┐
│  proxychains.exe │────▶│  Target Process           │
│  (Launcher)      │     │  ┌──────────────────────┐ │
│                  │     │  │ proxychains_hook.dll  │ │
│  - Config parser │     │  │ (Injected DLL)        │ │
│  - IPC server    │     │  │                       │ │
│  - Process mgmt  │     │  │ - Hooks connect()     │ │
│                  │     │  │ - Hooks WSAConnect()   │ │
│                  │◀───▶│  │ - Hooks DNS functions  │ │
│  (Named Pipes)   │     │  │ - SOCKS5/4/HTTP proxy │ │
│                  │     │  │ - Fake DNS resolution  │ │
└─────────────────┘     │  └──────────────────────┘ │
                        └──────────────────────────┘
```

### Connection Flow (Proxy Chain)

```
Application                Hook DLL                  Proxy Chain              Target
    │                         │                          │                      │
    ├── connect(target) ─────▶│                          │                      │
    │                         ├── TunnelThroughChain ───▶│                      │
    │                         │   (chain mode logic)     │                      │
    │                         │                          │                      │
    │                         │   ┌── GenericTunnelTo ──▶│ Proxy 1              │
    │                         │   │   (connect+handshake)├──TCP──▶│             │
    │                         │   │                      │        │             │
    │                         │   ├── GenericTunnelTo ──▶│ Proxy 2│             │
    │                         │   │                      ├──TCP───┼──▶│         │
    │                         │   │                      │        │   │         │
    │                         │   └── GenericConnectTo ─▶│        │   │         │
    │                         │       (final target)     ├──TCP───┼───┼──▶│     │
    │                         │                          │        │   │   │     │
    │◀── return(success) ─────│                          │        │   │   │     │
    │                         │                          │        │   │   │     │
    ├── send(data) ──────────▶│──────────────────────────┼────────┼───┼──▶│     │
    │◀── recv(data) ──────────│◀─────────────────────────┼────────┼───┼───│     │
```

### DNS Resolution Flow

```
Application                Hook DLL                  IPC Server (exe)
    │                         │                          │
    ├── getaddrinfo() ──────▶│                          │
    │                         ├── Generate Fake IP ─────▶│ (store hostname→IP mapping)
    │◀── return(fake IP) ─────│                          │
    │                         │                          │
    ├── connect(fake IP) ───▶│                          │
    │                         ├── Lookup hostname ──────▶│ (resolve fake IP→hostname)
    │                         │◀── return hostname ──────│
    │                         │                          │
    │                         ├── SOCKS5 CONNECT with hostname (remote DNS)
    │                         │                          │
```

### Cross-Architecture Injection

```
proxychains.exe (x64)
    │
    ├── CreateProcess(target.exe)
    │
    ├── IsWow64Process(target)?
    │   │
    │   ├── YES (x86 target) ──▶ Inject proxychains_hook_x86.dll
    │   │                         (via modified entry point)
    │   │
    │   └── NO (x64 target) ───▶ Inject proxychains_hook_x64.dll
    │                             (via modified entry point)
    │
    └── ResumeThread(target)
```

### Key Source Files

| File | Purpose |
|------|---------|
| `src/exe/main.c` | Entry point, IPC server, process management |
| `src/exe/args_and_config.c` | Command-line parsing, configuration file loading |
| `src/dll/hookdll_main.c` | DLL entry point, hook DLL injection logic |
| `src/dll/hook_connect_win32.c` | Network API hooks (connect, WSAConnect, etc.) |
| `src/dll/hook_createprocess_win32.c` | CreateProcess hooks for child process injection |
| `src/dll/hook_installer.c` | MinHook setup and hook registration |
| `src/remote_function.c` | Code executed in target process context |
| `include/defines_generic.h` | Data structures and constants |

### Data Flow

1. **Launcher** (`proxychains.exe`) reads configuration and starts the target process with the hook DLL injected.
2. **Hook DLL** intercepts Winsock `connect()` calls and redirects them through the configured proxy chain.
3. **IPC** (Named Pipes) is used for communication between the launcher and injected DLLs for DNS resolution and logging.

## Coding Standards

### Naming Conventions

```c
// Public functions: PascalCase
PXCH_DLL_API int Ws2_32_Socks5Connect(...);

// Internal functions: PascalCase or snake_case
static int TunnelThroughProxyChain(...);

// Macros: UPPER_SNAKE_CASE
#define PXCH_PROXY_TYPE_SOCKS5  0x00000001

// Structures: PXCH_ prefix
typedef struct _PXCH_PROXY_DATA { ... } PXCH_PROXY_DATA;
```

### Error Handling

Always use the `goto` cleanup pattern:
```c
if (!result) {
    dwLastError = GetLastError();
    LOGE(L"Operation failed: %ls", FormatErrorToStr(dwLastError));
    goto error;
}

// ... more code ...

error:
    if (hHandle) CloseHandle(hHandle);
    return dwLastError;
```

### Logging

Use IPC logging macros in hook DLL code:
```c
FUNCIPCLOGV(L"Verbose: detail");    // Verbose (600)
FUNCIPCLOGD(L"Debug: %d", val);     // Debug (500)
FUNCIPCLOGI(L"Info: connected");     // Info (400)
FUNCIPCLOGW(L"Warning: retry");      // Warning (300)
FUNCIPCLOGE(L"Error: failed");       // Error (200)
```

Use standard logging in executable code:
```c
LOGV(L"Verbose");
LOGD(L"Debug");
LOGI(L"Info");
LOGW(L"Warning");
LOGE(L"Error");
```

### Architecture-Specific Code

```c
#if defined(_M_X64) || defined(__x86_64__)
    // x64-specific code
#else
    // x86-specific code
#endif
```

### Buffer Safety

Always use safe string functions:
```c
// Good
StringCchCopyW(dest, _countof(dest), src);
StringCchPrintfA(buf, _countof(buf), "%s:%d", host, port);

// Bad - never use these
strcpy(dest, src);   // Buffer overflow risk
sprintf(buf, ...);   // Buffer overflow risk
```

## Adding Features

### Adding a New Proxy Type

1. Define the proxy type in `include/defines_generic.h`:
   ```c
   #define PXCH_PROXY_TYPE_NEWTYPE  0x00000004
   ```

2. Add data structure in `include/defines_generic.h`:
   ```c
   typedef struct _PXCH_PROXY_NEWTYPE_DATA {
       PXCH_UINT32 dwTag;
       char Ws2_32_ConnectFunctionName[PXCH_MAX_DLL_FUNC_NAME_BUFSIZE];
       char Ws2_32_HandshakeFunctionName[PXCH_MAX_DLL_FUNC_NAME_BUFSIZE];
       PXCH_HOST_PORT HostPort;
       int iAddrLen;
       // Additional fields...
   } PXCH_PROXY_NEWTYPE_DATA;
   ```

3. Add to the union in `PXCH_PROXY_DATA`.

4. Implement Connect and Handshake functions in `src/dll/hook_connect_win32.c`.

5. Add config parsing in `src/exe/args_and_config.c`.

### Adding a New Chain Mode

1. Define the chain type in `include/defines_generic.h`:
   ```c
   #define PXCH_CHAIN_TYPE_NEWMODE  0x00000005
   ```

2. Add config parsing in `src/exe/args_and_config.c`.

3. Add chain logic in `TunnelThroughProxyChain()` in `src/dll/hook_connect_win32.c`.

### Adding a Configuration Option

1. Add field to `PROXYCHAINS_CONFIG` in `include/defines_generic.h`.
2. Set default in `LoadConfiguration()` in `src/exe/args_and_config.c`.
3. Parse option in config file loop in `src/exe/args_and_config.c`.
4. Document in `proxychains.conf`.

## Testing

See [TESTING.md](TESTING.md) for comprehensive testing guide.

### Quick Test

```cmd
# Test with curl through a SOCKS5 proxy
proxychains_win32_x64.exe curl.exe https://ifconfig.me

# Test cross-architecture (x86 target from x64 exe)
proxychains_win32_x64.exe "C:\Windows\SysWOW64\curl.exe" https://ifconfig.me
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch from `master`
3. Make your changes following the coding standards
4. Update documentation (README.md, TODO.md, CHANGELOG.md, TESTING.md)
5. Submit a pull request with a clear description

### PR Checklist

- [ ] Code follows existing style and naming conventions
- [ ] Both x86 and x64 architectures are handled
- [ ] Error handling follows the `goto` cleanup pattern
- [ ] Logging added for significant operations
- [ ] No memory or handle leaks
- [ ] `proxychains.conf` updated for new options
- [ ] `TODO.md` updated (mark completed items)
- [ ] `CHANGELOG.md` updated with changes
- [ ] `TESTING.md` updated with test scenarios

## License

This project is licensed under the GNU General Public License version 2. See [COPYING](COPYING) for details.
