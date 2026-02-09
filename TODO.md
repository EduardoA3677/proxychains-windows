# TODO List - Proxychains-Windows Features & Improvements

## High Priority Features

### Dynamic Chain Support
- [x] Implement dynamic chain mode (skip dead proxies)
- [x] Add proxy health checking mechanism
- [x] Implement automatic proxy failover
- [x] Add timeout-based proxy detection
- **Status**: Dynamic chain mode with health tracking: per-proxy failure counters, auto-skip dead proxies after 3 consecutive failures, automatic counter reset when all proxies fail
- **Difficulty**: Medium
- **Impact**: High - Better reliability when proxies fail

### Round Robin Chain Support
- [x] Implement round-robin proxy selection
- [x] Add chain length configuration support
- [x] Thread-safe proxy rotation
- [x] Persistent state for proxy rotation across processes
- **Status**: Round-robin chain mode with named shared memory (Local\proxychains_rr_<pid>) for cross-process persistent counter
- **Difficulty**: Medium
- **Impact**: Medium - Load balancing across proxies

### Random Chain Support
- [x] Implement random proxy selection
- [x] Configurable chain length
- [x] Random seed configuration
- **Status**: Random chain mode implemented with configurable chain_len and optional random_seed
- **Difficulty**: Low
- **Impact**: Low - Useful for testing

### UDP Associate Support
- [x] Implement SOCKS5 UDP associate for DNS
- [x] UDP packet forwarding through proxy
- [x] DNS queries via UDP associate
- **Status**: Implemented. SOCKS5 UDP ASSOCIATE (command 0x03) sends DNS queries through the proxy's UDP relay, preventing DNS leaks. Enable with `proxy_dns_udp_associate` config option. Supports authentication, custom DNS server via `dns_server` option, and IPv4/IPv6 (A/AAAA) queries.
- **Difficulty**: High
- **Impact**: High - Prevent DNS leaks better

### Hook WinHTTP/WinINet APIs
- [x] Hook WinHttpOpen to force proxy settings on WinHTTP sessions
- [x] Hook WinHttpSetOption to intercept proxy configuration changes
- [x] Hook InternetOpenA/W to force proxy settings on WinINet sessions
- [x] Hook InternetSetOptionA/W to intercept proxy configuration changes
- [x] Child data backup/restore for all WinHTTP/WinINet hook function pointers
- **Status**: Implemented. Hooks intercept WinHTTP (winhttp.dll) and WinINet (wininet.dll) session creation to inject the configured proxy. Applications using these APIs (PowerShell Invoke-WebRequest, browsers, .NET HttpClient, etc.) are now transparently proxied.
- **Difficulty**: Medium
- **Impact**: High - Many Windows applications use WinHTTP/WinINet instead of raw Winsock

## Medium Priority Features

### Configuration Improvements
- [x] Support for HTTP/HTTPS proxy (HTTP CONNECT method)
- [x] Support for SOCKS4/SOCKS4a proxies
- [ ] Multiple configuration file profiles
- [x] Environment variable expansion in config
- [ ] Reload configuration without restart
- **Status**: SOCKS5, SOCKS4/SOCKS4a, and HTTP CONNECT proxies supported; environment variables expanded in file paths
- **Difficulty**: Medium
- **Impact**: Medium - More flexibility

### Enhanced DNS Resolution
- [x] Implement proxy_dns_daemon feature from proxychains-ng
- [x] Better DNS cache management
- [x] Custom DNS server configuration
- [ ] DNS-over-HTTPS support
- [x] IPv6 DNS resolution improvements
- **Status**: DNS cache with configurable TTL (`dns_cache_ttl`), custom DNS server (`dns_server`), SOCKS5 UDP ASSOCIATE for leak-free DNS. DNS cache is thread-safe with CRITICAL_SECTION, supports both IPv4 and IPv6 results, auto-evicts expired entries. UDP Associate resolves both A and AAAA records through the proxy.
- **Difficulty**: High
- **Impact**: High - Better privacy and performance

### IPv6 Improvements
- [x] Full IPv6 proxy chain support
- [x] IPv6 local network rules
- [x] Better IPv6 fake IP range management
- [x] Dual-stack (IPv4/IPv6) handling
- **Status**: Full IPv6 proxy chain support: SOCKS5 connect handles IPv6 addresses (ATYP 0x04), DirectConnect falls back to any available address family for dual-stack compatibility, DNS cache stores both IPv4 and IPv6 results, GetAddrInfoW cache lookup supports AF_INET6 queries.
- **Difficulty**: Medium
- **Impact**: Medium - Future-proofing

### Logging and Debugging
- [ ] Structured logging (JSON output option)
- [x] Per-process log files
- [ ] Log rotation
- [x] Performance metrics logging
- [ ] Visual Studio debug output improvements
- **Status**: Per-proxy success/failure counters tracked via InterlockedIncrement for health monitoring. Per-process log file via `log_file` config directive.
- **Difficulty**: Low
- **Impact**: Medium - Better troubleshooting

## Low Priority Features

### GUI Application
- [ ] Basic GUI for configuration
- [ ] Proxy list management UI
- [ ] Real-time connection monitoring
- [ ] System tray icon
- [ ] Profile management
- **Status**: Not implemented (command-line only)
- **Difficulty**: High
- **Impact**: Low - CLI works well, but GUI would help non-technical users

### Performance Optimizations
- [ ] Connection pooling for proxy connections
- [ ] Async I/O improvements
- [ ] Memory usage optimization
- [ ] Startup time reduction
- [ ] DLL injection speed improvements
- **Status**: Basic implementation exists
- **Difficulty**: Medium
- **Impact**: Low - Current performance is acceptable

### Testing Infrastructure
- [ ] Unit tests for core functionality
- [ ] Integration tests with real proxies
- [ ] Automated testing in CI/CD
- [ ] Mock proxy server for testing
- [ ] Performance benchmarks
- **Status**: No automated tests
- **Difficulty**: Medium
- **Impact**: Medium - Better code quality

### Security Enhancements
- [ ] Code signing for binaries
- [x] ASLR and DEP enforcement verification
- [ ] Security audit of DLL injection code
- [ ] Sandboxing options
- [ ] Certificate pinning for HTTPS proxies
- **Status**: ASLR (RandomizedBaseAddress) and DEP (DataExecutionPrevention) explicitly enabled in Release builds for both exe and DLL
- **Difficulty**: High
- **Impact**: Medium - Enhanced security

## Bug Fixes & Improvements

### Known Issues
- [x] Domain name resolution should be case-insensitive
- [ ] Handle "fork-and-exit" child processes properly
- [x] Powershell wget compatibility issues
- [ ] Better ConEmu compatibility (currently incompatible)
- [ ] Handle Cygwin encoding issues completely
- **Status**: Case-insensitive DNS fixed. PowerShell wget/Invoke-WebRequest fixed via WinHTTP/WinINet API hooks (PowerShell uses WinHTTP internally). Others documented in README To-do section.
- **Difficulty**: Various
- **Impact**: Various

### Code Quality
- [x] Refactor large functions into smaller ones
- [x] Improve error handling consistency
- [x] Add more inline documentation
- [x] Reduce code duplication
- [ ] Better separation of concerns (Win32 vs Cygwin code)
- **Status**: TunnelThroughProxyChain extracted from 3 hook functions. Health tracking consolidated into shared counters. Error handling now consistent with InterlockedIncrement-based failure tracking across all chain modes.
- **Difficulty**: Medium
- **Impact**: Medium - Maintainability

### Documentation
- [x] Developer documentation
- [x] API documentation for hooks
- [x] Architecture diagrams
- [ ] Video tutorials
- [x] Troubleshooting guide expansion
- **Status**: CONTRIBUTING.md with architecture diagrams (connection flow, DNS resolution, cross-arch injection). API_HOOKS.md documents all hooked functions and proxy protocols. Troubleshooting expanded in TESTING.md.
- **Difficulty**: Low
- **Impact**: Medium - Easier contribution

## Platform Support

### Additional Windows Versions
- [ ] Windows Server 2022 testing
- [ ] Windows 11 ARM64 support
- [ ] Windows on ARM testing
- [ ] Older Windows versions (Vista, XP) maintenance
- **Status**: Tested on Win 7/10/11 x64
- **Difficulty**: Low-Medium
- **Impact**: Low - Niche platforms

### Cross-Platform Improvements
- [ ] WSL2 integration
- [ ] Wine compatibility for Linux users
- [ ] ReactOS compatibility testing
- **Status**: Not tested
- **Difficulty**: Medium
- **Impact**: Low - Niche use cases

## Feature Requests from Community

### User-Requested Features
- [x] Support for authentication with proxy servers (username/password)
- [x] Whitelist/blacklist based on process name
- [ ] Global system-wide proxying option
- [ ] Browser extension integration
- [ ] VPN-like system proxy configuration
- **Status**: Proxy authentication implemented for SOCKS5/SOCKS4/HTTP. Process filtering via process_only (whitelist) and process_except (blacklist) config directives.
- **Difficulty**: Various
- **Impact**: Various - Based on user demand

## Research & Exploration

### Advanced Features
- [ ] Investigate Tor integration
- [ ] Research alternative DLL injection methods
- [ ] Explore kernel-mode filtering options
- [ ] Study Windows Filtering Platform (WFP) integration
- [ ] Research zero-configuration proxy detection
- **Status**: Not started
- **Difficulty**: High
- **Impact**: Unknown - Research phase

## Priority Legend
- **High**: Critical for core functionality or high user demand
- **Medium**: Important but not blocking
- **Low**: Nice to have, convenience features

## Difficulty Legend
- **Low**: 1-2 days of work
- **Medium**: 3-7 days of work
- **High**: 1-4 weeks of work

## Next Actions

### Immediate (Next Sprint)
1. ~~Implement dynamic chain support (skip dead proxies)~~ ✅ Done
2. ~~Add HTTP/HTTPS proxy support~~ ✅ Done
3. Create unit testing framework
4. ~~Improve documentation~~ ✅ Done (CONTRIBUTING.md, API_HOOKS.md created)

### Short Term (1-2 months)
1. ~~Implement round-robin and random chain modes~~ ✅ Done
2. ~~UDP associate for DNS~~ ✅ Done
3. ~~Enhanced logging system~~ ✅ Done (health tracking metrics, per-process log files)
4. Security audit
5. ~~Proxy health checking and failover~~ ✅ Done

### Long Term (3-6 months)
1. GUI application
2. Performance optimizations
3. ~~Advanced proxy authentication~~ ✅ Done (SOCKS5/SOCKS4/HTTP auth)
4. ~~Full IPv6 support~~ ✅ Done (IPv6 proxy chains, dual-stack, DNS cache)

## Contributing

If you want to contribute to any of these features:
1. Check the issue tracker for related discussions
2. Comment on the feature you want to work on
3. Fork the repository
4. Create a feature branch
5. Submit a pull request

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.
