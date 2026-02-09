# Contributing to Proxychains-Windows

Thank you for your interest in contributing to proxychains-windows! This guide will help you get started.

## Table of Contents

- [Development Setup](#development-setup)
- [Code Structure](#code-structure)
- [Coding Standards](#coding-standards)
- [Building and Testing](#building-and-testing)
- [Submitting Changes](#submitting-changes)
- [Feature Requests](#feature-requests)

## Development Setup

### Prerequisites

- **Visual Studio 2019 or later** with C++ workload
- **Windows SDK** (comes with Visual Studio)
- **Git** with submodule support

### Getting Started

1. Clone the repository with submodules:
```cmd
git clone --recursive https://github.com/EduardoA3677/proxychains-windows.git
cd proxychains-windows
```

2. If you already cloned without `--recursive`:
```cmd
git submodule update --init --recursive
```

3. Open `proxychains.exe.sln` in Visual Studio

4. Build the solution:
   - Select `Release` configuration
   - Build for `x64` and/or `x86` platforms

## Code Structure

### Directory Layout

```
proxychains-windows/
├── src/
│   ├── exe/              # Main executable (launcher, IPC server)
│   │   ├── main.c        # IPC server, process management
│   │   └── args_and_config.c  # Configuration parsing
│   ├── dll/              # Hook DLL (injected into target process)
│   │   ├── hookdll_main.c     # DLL entry, hook initialization
│   │   ├── hook_connect_win32.c  # Network API hooks
│   │   └── hook_createprocess_win32.c  # Process creation hooks
│   └── remote_function.c # Code executed in remote process
├── include/              # Header files
│   ├── defines_generic.h # Configuration structures
│   ├── log_win32.h      # Logging macros
│   └── ...
├── win32_output/        # Build output directory
└── proxychains.conf     # Configuration template
```

### Key Components

#### 1. Main Executable (`src/exe/`)
- Parses configuration file
- Creates IPC server (named pipe)
- Injects hook DLL into target process
- Manages child processes

#### 2. Hook DLL (`src/dll/`)
- Injected into target process
- Hooks Winsock functions (connect, GetAddrInfo, etc.)
- Intercepts DNS queries
- Forwards connections through proxy chain

#### 3. Configuration (`src/exe/args_and_config.c`)
- Parses `proxychains.conf`
- Validates proxy list
- Handles environment variable expansion
- Loads hosts file

## Coding Standards

### Naming Conventions

```c
// Functions
PascalCase              // Public functions: CreateProxyChain()
snake_case              // Internal functions: parse_config_line()

// Variables
camelCase               // Local variables: proxyCount, hostName
snake_case              // Also acceptable: proxy_count, host_name

// Macros
UPPER_SNAKE_CASE        // All macros: PXCH_MAX_PROXIES

// Structures
PXCH_PREFIX             // All structures: PXCH_PROXY_DATA
```

### Error Handling

Always use the `goto error` pattern for cleanup:

```c
DWORD MyFunction() {
    HANDLE hFile = NULL;
    DWORD dwLastError = NO_ERROR;
    
    hFile = CreateFile(...);
    if (hFile == INVALID_HANDLE_VALUE) {
        dwLastError = GetLastError();
        LOGE(L"Failed to open file: %ls", FormatErrorToStr(dwLastError));
        goto error;
    }
    
    // Do work...
    
error:
    if (hFile && hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
    }
    return dwLastError;
}
```

### Logging

Use IPC logging macros throughout:

```c
IPCLOGV(L"Verbose details");     // Verbose (600)
IPCLOGD(L"Debug info: %d", x);   // Debug (500)
IPCLOGI(L"Information");         // Info (400)
IPCLOGW(L"Warning");             // Warning (300)
IPCLOGE(L"Error occurred");      // Error (200)
IPCLOGC(L"Critical failure");    // Critical (100)
```

### Architecture Support

Always handle both x86 and x64:

```c
#if defined(_M_X64) || defined(__x86_64__)
    // x64-specific code
    StringCchCopyW(szDllPath, MAX_PATH, g_pPxchConfig->szHookDllPathX64);
#else
    // x86-specific code
    StringCchCopyW(szDllPath, MAX_PATH, g_pPxchConfig->szHookDllPathX86);
#endif
```

### Memory Safety

- **Always** use safe string functions: `StringCchCopy`, `StringCchCopyN`, `StringCchPrintf`
- **Never** use unsafe functions: `strcpy`, `sprintf`, `strcat`
- **Always** check return values from Win32 API calls
- **Always** free allocated memory and close handles

```c
// Good
if (FAILED(StringCchCopyW(dest, destSize, src))) {
    goto error;
}

// Bad - don't do this
wcscpy(dest, src);  // Buffer overflow risk!
```

## Building and Testing

### Building

#### Visual Studio GUI
1. Open `proxychains.exe.sln`
2. Select configuration: `Release` or `Debug`
3. Select platform: `x64` or `x86`
4. Build → Build Solution (Ctrl+Shift+B)

#### Command Line (MSBuild)
```cmd
# Build x64 Release
msbuild proxychains.exe.sln /p:Configuration=Release /p:Platform=x64

# Build x86 Release
msbuild proxychains.exe.sln /p:Configuration=Release /p:Platform=x86

# Build both
msbuild proxychains.exe.sln /p:Configuration=Release /p:Platform=x64
msbuild proxychains.exe.sln /p:Configuration=Release /p:Platform=x86
```

### Output Files

After building, executables are in `win32_output/`:
- `proxychains_win32_x64.exe` - x64 main executable
- `proxychains_hook_x64.dll` - x64 hook DLL
- `proxychains_hook_x86.dll` - x86 hook DLL

### Testing

#### Manual Testing

1. **Basic connectivity test:**
```cmd
proxychains_win32_x64.exe curl https://ifconfig.me
```

2. **Chain mode test:**
```cmd
# Edit proxychains.conf to use dynamic_chain or round_robin_chain
proxychains_win32_x64.exe curl https://ifconfig.me
```

3. **Architecture test:**
```cmd
# x64 target
proxychains_win32_x64.exe notepad.exe

# x86 target (on x64 Windows)
proxychains_win32_x64.exe "C:\Program Files (x86)\SomeApp.exe"
```

4. **Multiple proxies:**
```conf
# In proxychains.conf
[ProxyList]
socks5 proxy1.example.com 1080
socks5 proxy2.example.com 1080
http proxy3.example.com 8080
```

#### Test Scenarios

See [TESTING.md](TESTING.md) for comprehensive test scenarios covering:
- Chain modes (strict, dynamic, random, round-robin)
- Proxy types (SOCKS5, SOCKS4/4a, HTTP/HTTPS)
- Authentication
- IPv4/IPv6
- Error handling

## Submitting Changes

### Before Submitting

1. **Test your changes** on both x64 and x86 (if applicable)
2. **Update documentation:**
   - Add/update comments in code
   - Update `CHANGELOG.md` with your changes
   - Update `TODO.md` (mark completed items)
   - Update `TESTING.md` with new test scenarios
   - Update `proxychains.conf` if adding configuration options
3. **Follow coding standards** (see above)
4. **Check for memory leaks** and resource leaks
5. **Ensure backward compatibility** (don't break existing configs)

### Pull Request Process

1. **Fork** the repository
2. **Create a feature branch:**
```cmd
git checkout -b feature/my-new-feature
```

3. **Make your changes** following coding standards

4. **Commit with clear messages:**
```cmd
git commit -m "Add support for SOCKS5 UDP associate"
```

5. **Push to your fork:**
```cmd
git push origin feature/my-new-feature
```

6. **Create Pull Request** on GitHub with:
   - Clear description of changes
   - Motivation/problem being solved
   - Test results
   - Breaking changes (if any)

### Commit Message Format

```
Short summary (50 chars or less)

Longer description if needed. Explain what and why, not how.
The how is evident from the code.

- Bullet points for multiple changes
- Reference issues: Fixes #123
```

Examples:
```
Add SOCKS4a proxy support

Implements SOCKS4a protocol for proxies that support hostname
resolution. Maintains backward compatibility with SOCKS4.

- Add PXCH_PROXY_TYPE_SOCKS4 constant
- Implement Ws2_32_Socks4Connect() function
- Update configuration parser
- Add documentation and tests
```

## Feature Requests

### Before Requesting

1. **Check existing issues** to avoid duplicates
2. **Check TODO.md** - it might already be planned
3. **Consider feasibility** - some features may not be possible due to Windows limitations

### High Priority Features

These are more likely to be accepted:
- Improved error handling
- Better logging and debugging
- Performance improvements (if significant)
- Bug fixes
- Documentation improvements
- Security improvements

### Lower Priority Features

These need strong justification:
- GUI applications (CLI focus)
- Advanced features with limited use cases
- Features requiring major architectural changes

### Submitting Feature Requests

1. Open an issue on GitHub
2. Use clear, descriptive title
3. Provide:
   - **Use case:** Why is this needed?
   - **Expected behavior:** What should it do?
   - **Alternatives considered:** What else could solve this?
   - **Additional context:** Screenshots, examples, etc.

## Architecture Notes

### DLL Injection Process

1. Main exe parses config and validates proxy list
2. Main exe creates target process in suspended state
3. Main exe allocates memory in target process
4. Main exe writes configuration and hook DLL path to target
5. Main exe modifies target entry point to load hook DLL
6. Main exe resumes target process
7. Hook DLL initializes and hooks Winsock functions
8. Target process runs with hooked network functions

### Hook Mechanism

Uses [MinHook](https://github.com/TsudaKageyu/minhook) library:
```c
// 1. Create hook
MH_CreateHook(orig_function, my_proxy_function, &original_ptr);

// 2. Enable hook
MH_EnableHook(orig_function);

// 3. In proxy function
int WINAPI my_proxy_function(SOCKET s, ...) {
    // Intercept and redirect through proxy
    // ...
    // Call original if needed
    return original_ptr(s, ...);
}
```

### IPC Communication

- Uses Windows Named Pipes
- Bidirectional communication between main exe and hooked processes
- Used for logging and process bookkeeping

## Common Issues

### Building

**Issue:** "Cannot find minhook.lib"
- **Solution:** Run `git submodule update --init --recursive`

**Issue:** "Platform toolset not found"
- **Solution:** Install Visual Studio 2019 or later with C++ workload

### Runtime

**Issue:** "Failed to inject DLL"
- **Solution:** Check that DLL architecture matches target (x86 vs x64)

**Issue:** "Access denied"
- **Solution:** Run as Administrator for some system processes

**Issue:** "Proxy connection timeout"
- **Solution:** Check proxy is reachable, increase timeout in config

## Getting Help

- **GitHub Issues:** Report bugs, ask questions
- **Discussions:** General discussion, ideas
- **Documentation:** Check README.md, TESTING.md, TODO.md

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn
- Keep discussions on-topic

## License

By contributing, you agree that your contributions will be licensed under the GPL-2.0-or-later license (same as the project).

---

Thank you for contributing to proxychains-windows! 🎉
