# Changelog

All notable changes to proxychains-windows will be documented in this file.

## [Unreleased] - Dynamic Chain, Random Chain, and Cross-Architecture Support

### Added
- **Dynamic Chain Support**: New `dynamic_chain` mode that skips dead/unreachable proxies and continues with alive ones. At least one proxy must be online for the chain to work.
- **Random Chain Support**: New `random_chain` mode that randomly selects proxies from the list. Configurable `chain_len` parameter controls how many proxies are used per connection.
- **Random Seed Configuration**: New `random_seed` option for reproducible random chain proxy selection. When set, random proxy selection uses the specified seed instead of time-based seeding.
- **Round-Robin Chain Support**: New `round_robin_chain` mode that cycles through proxies sequentially with thread-safe rotation using `InterlockedIncrement`. Configurable `chain_len` parameter.
- **Chain Type Configuration**: Four chain modes now supported: `strict_chain` (default, all proxies must be online), `dynamic_chain` (skip dead proxies), `random_chain` (random proxy selection), and `round_robin_chain` (sequential rotation).
- **SOCKS4/SOCKS4a Proxy Support**: New `socks4` proxy type supporting both SOCKS4 (IPv4 only) and SOCKS4a (hostname resolution on proxy server). Optional userid for ident-based authentication.
- **HTTP CONNECT Proxy Support**: New `http` proxy type using HTTP CONNECT method for tunneling. Supports Basic authentication with username/password.
- **Proxy Health Checking**: Per-proxy failure counters using thread-safe `InterlockedIncrement`. Dynamic chain auto-skips proxies with ≥3 consecutive failures. All chain modes now track success/failure metrics.
- **Automatic Proxy Failover**: Dynamic chain mode automatically skips dead proxies and resets health counters when all proxies fail, allowing retry on next connection.
- **Environment Variable Expansion**: File paths in configuration (such as `custom_hosts_file_path` and `-f` flag) now support `%VARIABLE%` environment variable expansion.
- **Improved Timeout Diagnostics**: Proxy connection and handshake timeout error messages now include the timeout value and target address for better troubleshooting.
- **Unified Binary Support**: x64 build now automatically detects and injects into both x64 and x86 (32-bit) processes
- **Automatic Architecture Detection**: Uses `IsWow64Process()` to determine target process architecture
- **Smart DLL Selection**: Automatically selects correct hook DLL (x86 or x64) based on target process
- **Improved Error Messages**: Better diagnostics showing exact paths of missing DLLs
- **Windows 11 Compatibility**: Full support and testing for Windows 11
- **API Hook Documentation**: New API_HOOKS.md with complete documentation of all hooked functions, proxy protocols, chain modes, and health checking behavior.
- **Enhanced Documentation**:
  - New "Key Features and Improvements" section in README
  - Updated Install section with unified binary instructions
  - New TESTING.md guide for testing cross-architecture support
  - New CONTRIBUTING.md with developer guidelines, architecture overview, and coding standards
  - Inline documentation added to key functions in hook_connect_win32.c
- **CI/CD Improvements**: GitHub Actions workflow now builds both x86 and x64 versions
- **Process Name Filtering**: New `process_only` (whitelist) and `process_except` (blacklist) config directives to control which child processes get injected. Case-insensitive matching on executable filename. Maximum 8 filter entries.
- **Persistent Round-Robin State**: Round-robin chain mode counter is now stored in named shared memory (`Local\proxychains_rr_<pid>`) for consistent rotation across child processes.
- **WinHTTP/WinINet API Hooks**: Hook `WinHttpOpen` and `WinHttpSetOption` (winhttp.dll) and `InternetOpenA/W` and `InternetSetOptionA/W` (wininet.dll) to force proxy settings on applications using high-level HTTP APIs (PowerShell Invoke-WebRequest, .NET HttpClient, browsers, Windows Update, etc.).

### Changed
- **DLL Path Handling**: Hook DLL paths are now dynamically selected at injection time based on target architecture
- **Architecture Validation**: x64 builds now verify both x86 and x64 DLLs are present
- **Warning System**: Missing x86 DLL in x64 build now generates warning instead of error (allows x64-only operation)
- **Module Name Selection**: Hook DLL module name correctly set based on target process architecture
- **Build Process**: Updated to ensure both architectures are built in CI

### Improved
- **Error Diagnostics**: Error messages now show which DLL is missing and expected paths
- **Logging**: Added architecture detection logging showing which DLL is being used
- **Documentation**: Removed outdated warnings about requiring matching architecture executables
- **User Experience**: Single executable can now handle all scenarios (no need for separate x86/x64 versions)

### Fixed
- **Case-insensitive DNS**: Domain name resolution in hosts file lookup and fake IP mapping now uses case-insensitive comparison (`StrCmpIW` instead of `StrCmpW`), matching RFC behavior
- **IPv6 link-local CIDR**: Fixed fe80::/8 to correct fe80::/10 prefix length per RFC 4291
- **IPv6 loopback rule**: Added ::1/128 to default exclusion rules

### Technical Details

#### Core Changes
- Modified `InjectTargetProcess()` in `hookdll_main.c` to dynamically override DLL paths
- Updated DLL validation logic in `args_and_config.c` for cross-architecture support
- Hook DLL module name selection now based on target architecture, not build architecture

#### Compatibility
- Maintains backward compatibility with existing configurations
- Works on Windows 11, Windows 10, Windows 7 x64
- Supports both Cygwin and native Win32 builds

### How to Use

1. **Build or Download**: 
   - Build both x64 and x86 configurations in Visual Studio
   - Or download pre-built binaries from releases

2. **Install**:
   - Copy x64 `proxychains.exe` to a directory in your PATH
   - Copy both `proxychains_hook_x64.dll` and `proxychains_hook_x86.dll` to the same directory

3. **Use**:
   - Simply run `proxychains.exe <application>` regardless of target application architecture
   - The tool will automatically detect and inject the correct DLL

### Migration from Previous Versions

If you were using separate `proxychains_x86.exe` and `proxychains_x64.exe`:
- Replace both with single `proxychains.exe` (x64 build)
- Ensure both hook DLLs are present
- No configuration changes needed

### Known Limitations

- x86 build cannot inject into x64 processes (Windows limitation)
- x64 build requires both DLLs for full functionality (x86 DLL missing = warning, x64-only mode)
- Some anti-debugging/anti-hooking applications may not work

### Testing

See [TESTING.md](TESTING.md) for comprehensive testing guide.

### Contributors

- Architecture detection and unified binary implementation
- Windows 11 compatibility testing and fixes
- Documentation improvements
- Error handling enhancements

---

## Previous Versions

For changelog of previous versions, see the git commit history or release notes.
