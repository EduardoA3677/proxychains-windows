# Custom Instructions for GitHub Copilot

This repository uses GitHub Copilot Coding Agent to assist with development tasks from the TODO.md backlog.

## Project Overview

**proxychains-windows** is a Windows port of proxychains-ng that provides SOCKS5 proxy chaining through DLL injection and Win32 API hooking.

### Key Technologies
- **Language**: C (Win32 API)
- **Architecture**: Multi-arch (x86/x64 cross-compilation)
- **Build**: Visual Studio 2019+ (MSBuild)
- **Libraries**: MinHook (API hooking), uthash (hash tables)

## Repository Structure

```
src/
├── exe/                    # Main executable
│   ├── main.c             # IPC server, process management
│   └── args_and_config.c  # Config parsing
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
# Update submodules
git submodule update --init --recursive

# Build x64
devenv proxychains.exe.sln /build "Release|x64"

# Build x86
devenv proxychains.exe.sln /build "Release|x86"
```

### Output
- `win32_output/proxychains_win32_x64.exe` - Main executable
- `win32_output/proxychains_hook_x64.dll` - x64 hook DLL
- `win32_output/proxychains_hook_x86.dll` - x86 hook DLL

## Testing

Run the test suite before submitting changes:
```cmd
# Test with curl
proxychains_win32_x64.exe curl https://ifconfig.me

# Test architecture detection
proxychains_win32_x64.exe <32-bit-app>  # Should use x86 DLL
proxychains_win32_x64.exe <64-bit-app>  # Should use x64 DLL
```

See TESTING.md for comprehensive test scenarios.

## Coding Standards

### Naming Conventions
- Functions: `PascalCase` (public), `snake_case` (internal)
- Variables: `camelCase` or `snake_case`
- Macros: `UPPER_SNAKE_CASE`
- Structures: `PXCH_` prefix (e.g., `PXCH_PROXY_DATA`)

### Architecture-Specific Code
```c
#if defined(_M_X64) || defined(__x86_64__)
    // x64 implementation
#else
    // x86 implementation
#endif
```

### Error Handling
```c
if (!Result) {
    dwLastError = GetLastError();
    LOGE(L"Operation failed: %ls", FormatErrorToStr(dwLastError));
    goto error;
}
error:
    // Cleanup resources
    return dwLastError;
```

### Logging
Use IPC-based logging macros:
- `IPCLOGV` - Verbose
- `IPCLOGD` - Debug
- `IPCLOGI` - Info
- `IPCLOGW` - Warning
- `IPCLOGE` - Error

## Implementation Guidelines

### When Adding Features

1. **Check TODO.md** - Review requirements and priority
2. **Search existing code** - Look for similar implementations
3. **Plan architecture** - Consider x86/x64 implications
4. **Implement changes** - Follow coding style
5. **Add error handling** - Handle all failure cases
6. **Add logging** - Use IPCLOG* macros
7. **Update documentation** - TODO.md, CHANGELOG.md, README.md

### Common Patterns

#### Adding a Hook
```c
// 1. Declare function pointer type
typedef int (WINAPI *FpNewFunction)(PARAMS);

// 2. Declare original function pointer
FpNewFunction orig_fpNewFunction;

// 3. Define proxy function
PROXY_FUNC(NewFunction) {
    g_bCurrentlyInWinapiCall = TRUE;
    // Hook logic
    result = orig_fpNewFunction(params);
    g_bCurrentlyInWinapiCall = FALSE;
    return result;
}

// 4. Register hook
CREATE_HOOK(NewFunction);
```

#### Adding Configuration Option
```c
// 1. Add to PROXYCHAINS_CONFIG in include/defines_generic.h
typedef struct _PROXYCHAINS_CONFIG {
    // ...
    PXCH_UINT32 dwNewOption;
} PROXYCHAINS_CONFIG;

// 2. Parse in src/stdlib_config_reader.c
if (WSTR_EQUAL(sOption, sOptionNameEnd, L"new_option")) {
    // Parse value
    pPxchConfig->dwNewOption = value;
}

// 3. Document in proxychains.conf
# New option description
#new_option = value

// 4. Use in code
if (g_pPxchConfig->dwNewOption) {
    // Feature logic
}
```

## Code Review Checklist

Before submitting, verify:
- [ ] Both x86 and x64 architectures handled
- [ ] All error cases have proper handling
- [ ] Logging added for debugging
- [ ] Resources properly freed (memory, handles)
- [ ] Config parsing added if needed
- [ ] TODO.md updated (mark as complete)
- [ ] CHANGELOG.md updated
- [ ] TESTING.md updated if needed
- [ ] Code follows style guidelines
- [ ] No memory leaks or handle leaks

## Working with TODO.md

The TODO.md file tracks all pending features:
- **High Priority**: Critical features (dynamic chain, UDP DNS)
- **Medium Priority**: Important improvements (HTTP proxy, IPv6)
- **Low Priority**: Nice-to-have (GUI, optimizations)

When implementing a feature:
1. Read feature description in TODO.md
2. Check difficulty estimate and dependencies
3. Implement following guidelines above
4. Mark as complete: Change `- [ ]` to `- [x]`
5. Update CHANGELOG.md with changes

## Security Considerations

### Critical Rules
1. **Validate all inputs** - Config files, proxy hostnames, ports
2. **Check buffer sizes** - Prevent overflows
3. **Handle privileges** - Don't assume admin rights
4. **Clean up resources** - Prevent leaks
5. **Check architecture** - Ensure DLL matches target process

### Common Vulnerabilities to Avoid
- Buffer overflows in string operations
- Memory leaks from VirtualAllocEx
- Handle leaks from CreateProcess
- Path traversal in DLL loading
- Injection into higher-privilege processes

## Documentation Requirements

### When Adding Features
- Update `TODO.md` - Mark feature complete
- Update `CHANGELOG.md` - Describe changes
- Update `README.md` - If user-facing
- Update `TESTING.md` - Add test scenarios
- Update `proxychains.conf` - Document new options

### Commit Messages
Format: `<type>: <description>`

Types:
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation only
- `refactor:` - Code refactoring
- `test:` - Adding tests
- `chore:` - Maintenance

Example: `feat: implement dynamic chain support for skipping dead proxies`

## Limitations and Constraints

### Cannot Do
- Inject x86 DLL into x64 process (Windows limitation)
- Inject x64 DLL into x86 process
- Hook statically-linked executables
- Bypass anti-debugging/anti-hooking protections
- Force push to repository (security)

### Must Consider
- Cygwin vs Win32 differences
- Windows 7 compatibility (XP toolset)
- Multiple Windows versions (7/10/11)
- Antivirus false positives
- Branch protection rules

## Priority for Copilot Coding Agent

Focus on these high-impact features from TODO.md:
1. **Dynamic chain support** - Skip dead proxies
2. **HTTP/HTTPS proxy** - Expand beyond SOCKS5
3. **UDP associate for DNS** - Better DNS privacy
4. **Round-robin mode** - Load balancing
5. **Testing infrastructure** - Unit tests

## Getting Help

- Review `.github/agents/proxychains-developer.md` for detailed guidelines
- Check `TODO.md` for feature requirements
- See `TESTING.md` for validation procedures
- Consult `doc/DEVNOTES.md` for developer notes

## Summary

This is a **low-level Windows systems programming project** requiring expertise in:
- Win32 API and DLL injection
- Multi-architecture (x86/x64) development
- Network programming and protocols
- Memory management and resource handling
- Security-conscious coding

**Always test on both architectures before submitting changes.**
