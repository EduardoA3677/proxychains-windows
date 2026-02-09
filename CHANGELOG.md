# Changelog

All notable changes to proxychains-windows will be documented in this file.

## [Unreleased] - Persistent Round-Robin State

### Added
- **Persistent Round-Robin State**: Round-robin mode now remembers position across restarts
  - New configuration options: `persistent_round_robin` and `round_robin_state_file`
  - Automatically saves current proxy index to state file
  - Loads state on startup for true load balancing
  - File-based state storage with automatic creation
  - Default state file can be customized via config

### Implementation Details
- Added `dwEnablePersistentRoundRobin` and `szRoundRobinStateFile` to `PROXYCHAINS_CONFIG`
- `SaveRoundRobinState()` writes current index to file after each rotation
- `LoadRoundRobinState()` reads state on configuration load
- State file format: simple text file with index number
- Handles missing file gracefully (starts from 0)
- File locking prevents corruption from concurrent access

### Configuration
```conf
# Enable persistent round-robin state
persistent_round_robin
round_robin_state_file = C:\Users\YourName\.proxychains\roundrobin.state
```

## [Unreleased] - Bug Fixes and Improvements

### Fixed
- **Case-Insensitive DNS Resolution**: Hostname comparison in hosts file now case-insensitive
  - DNS protocol is case-insensitive per RFC
  - Changed `StrCmpW` to `StrCmpIW` in hostname resolution
  - Fixes issues with mixed-case domain names

### Added
- **Environment Variable Expansion Support**: Utility function for expanding environment variables
  - Supports both %VAR% (Windows) and ${VAR} (Unix) syntax
  - Can be used in configuration parsing
  - Foundation for future config enhancements

## [Unreleased] - SOCKS4/SOCKS4a Proxy Support

### Added
- **SOCKS4 Proxy Support**: Full support for SOCKS4 protocol
- **SOCKS4a Proxy Support**: SOCKS4a with hostname resolution capability
- **SOCKS4 User ID**: Optional user ID field for SOCKS4/4a proxies
- **Configuration Options**:
  - `socks4` proxy type in configuration
  - `socks4a` proxy type in configuration (with hostname support)
  - User ID support for SOCKS4/4a proxies (optional)

### Implementation Details
- Added `PXCH_PROXY_TYPE_SOCKS4` constant
- Added `PXCH_PROXY_SOCKS4_DATA` structure for SOCKS4 proxy configuration
- Implemented `Ws2_32_Socks4Connect()` function for SOCKS4/4a protocol
- Implemented `Ws2_32_Socks4Handshake()` function (no-op for SOCKS4)
- Added SOCKS4/4a proxy parsing in configuration reader
- SOCKS4a automatically used when hostname is provided
- IPv4 addresses and hostnames supported (IPv6 not supported by SOCKS4 protocol)

### Technical Details
- SOCKS4 protocol: VER(1) CMD(1) PORT(2) IP(4) USERID(variable) NULL(1)
- SOCKS4a extension: Uses IP 0.0.0.x to signal hostname follows
- Response parsing: VER(1) REP(1) PORT(2) IP(4)
- Success code: 0x5A (request granted)

### Compatibility
- Works with all chain modes (strict, dynamic, random, round-robin)
- Can be mixed with SOCKS5, HTTP, and HTTPS in the same chain
- Maintains backward compatibility with existing configurations

## [Unreleased] - HTTP/HTTPS Proxy Support

### Added
- **HTTP Proxy Support**: Full support for HTTP proxies using CONNECT method
- **HTTPS Proxy Support**: Support for HTTPS proxies (same as HTTP with SSL)
- **HTTP Basic Authentication**: Username/password authentication for HTTP/HTTPS proxies
- **Configuration Options**:
  - `http` proxy type in configuration
  - `https` proxy type in configuration
  - Username/password support for HTTP/HTTPS proxies

### Implementation Details
- Added `PXCH_PROXY_TYPE_HTTP` constant
- Added `PXCH_PROXY_HTTP_DATA` structure for HTTP proxy configuration
- Implemented `Ws2_32_HttpConnect()` function for HTTP CONNECT method
- Implemented `Ws2_32_HttpHandshake()` function (no-op for HTTP)
- Added HTTP proxy parsing in configuration reader
- Supports IPv4, IPv6, and hostname targets through HTTP proxy

### Compatibility
- Works with all chain modes (strict, dynamic, random, round-robin)
- Can be mixed with SOCKS5 proxies in the same chain
- Maintains backward compatibility with existing configurations

## [Unreleased] - Multiple Chain Modes Support

### Added
- **Dynamic Chain Mode**: Skip dead proxies and continue with alive ones
- **Random Chain Mode**: Select random proxies from the list for each connection
- **Round-Robin Chain Mode**: Rotate through proxies in a round-robin fashion
- **Chain Length Configuration**: `chain_len` option to specify number of proxies in random/round-robin modes
- **Enhanced Logging**: Chain mode operations now logged with detailed information
- **Configuration Options**:
  - `dynamic_chain` - Enable dynamic chain mode with automatic failover
  - `random_chain` - Enable random proxy selection
  - `round_robin_chain` - Enable round-robin proxy rotation
  - `chain_len` - Configure chain length for random/round-robin modes (default: 1)

### Changed
- **Proxy Chain Logic**: Refactored proxy connection loop into `Ws2_32_LoopThroughProxyChain()` function
- **Configuration Defaults**: Chain mode defaults to strict chain for backward compatibility
- **Error Handling**: Dynamic mode continues on proxy failures instead of aborting

### Improved
- **Reliability**: Dynamic chain mode provides better fault tolerance
- **Load Balancing**: Round-robin mode distributes load across proxies
- **Testing**: Random mode useful for testing and avoiding detection
- **Documentation**: Updated proxychains.conf with detailed chain mode descriptions

### Technical Details

#### Core Changes
- Added chain mode constants in `defines_generic.h`: 
  - `PXCH_CHAIN_MODE_STRICT` (default)
  - `PXCH_CHAIN_MODE_DYNAMIC`
  - `PXCH_CHAIN_MODE_RANDOM`
  - `PXCH_CHAIN_MODE_ROUND_ROBIN`
- Extended `PROXYCHAINS_CONFIG` structure with chain mode fields
- Implemented chain mode selection logic in `hook_connect_win32.c`
- Added configuration parsing in `args_and_config.c`
- Initialized random seed for random chain mode

#### Compatibility
- Maintains full backward compatibility with existing configurations
- Default behavior unchanged (strict chain mode)
- Works with all existing proxy configurations

## [Unreleased] - Cross-Architecture Support and Windows 11 Improvements

### Added
- **Unified Binary Support**: x64 build now automatically detects and injects into both x64 and x86 (32-bit) processes
- **Automatic Architecture Detection**: Uses `IsWow64Process()` to determine target process architecture
- **Smart DLL Selection**: Automatically selects correct hook DLL (x86 or x64) based on target process
- **Improved Error Messages**: Better diagnostics showing exact paths of missing DLLs
- **Windows 11 Compatibility**: Full support and testing for Windows 11
- **Enhanced Documentation**: 
  - New "Key Features and Improvements" section in README
  - Updated Install section with unified binary instructions
  - New TESTING.md guide for testing cross-architecture support
- **CI/CD Improvements**: GitHub Actions workflow now builds both x86 and x64 versions

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
