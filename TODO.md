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
- [ ] Persistent state for proxy rotation across processes
- **Status**: Round-robin chain mode implemented with thread-safe InterlockedIncrement counter
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
- [ ] Implement SOCKS5 UDP associate for DNS
- [ ] UDP packet forwarding through proxy
- [ ] DNS queries via UDP associate
- **Status**: Not implemented (marked as "NOT SUPPORTED" in config)
- **Difficulty**: High
- **Impact**: High - Prevent DNS leaks better

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
- [ ] Implement proxy_dns_daemon feature from proxychains-ng
- [ ] Better DNS cache management
- [ ] Custom DNS server configuration
- [ ] DNS-over-HTTPS support
- [ ] IPv6 DNS resolution improvements
- **Status**: Basic fake IP DNS implemented
- **Difficulty**: High
- **Impact**: High - Better privacy and performance

### IPv6 Improvements
- [ ] Full IPv6 proxy chain support
- [ ] IPv6 local network rules
- [ ] Better IPv6 fake IP range management
- [ ] Dual-stack (IPv4/IPv6) handling
- **Status**: Partial IPv6 support exists
- **Difficulty**: Medium
- **Impact**: Medium - Future-proofing

### Logging and Debugging
- [ ] Structured logging (JSON output option)
- [ ] Per-process log files
- [ ] Log rotation
- [x] Performance metrics logging
- [ ] Visual Studio debug output improvements
- **Status**: Per-proxy success/failure counters tracked via InterlockedIncrement for health monitoring
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
- [ ] Powershell wget compatibility issues
- [ ] Better ConEmu compatibility (currently incompatible)
- [ ] Handle Cygwin encoding issues completely
- **Status**: Case-insensitive DNS fixed; others documented in README To-do section
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
- [ ] Whitelist/blacklist based on process name
- [ ] Global system-wide proxying option
- [ ] Browser extension integration
- [ ] VPN-like system proxy configuration
- **Status**: Proxy authentication implemented for SOCKS5 (username/password), SOCKS4 (userid), and HTTP (Basic auth)
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
2. UDP associate for DNS
3. ~~Enhanced logging system~~ ✅ Done (health tracking metrics)
4. Security audit
5. ~~Proxy health checking and failover~~ ✅ Done

### Long Term (3-6 months)
1. GUI application
2. Performance optimizations
3. ~~Advanced proxy authentication~~ ✅ Done (SOCKS5/SOCKS4/HTTP auth)
4. Full IPv6 support

## Contributing

If you want to contribute to any of these features:
1. Check the issue tracker for related discussions
2. Comment on the feature you want to work on
3. Fork the repository
4. Create a feature branch
5. Submit a pull request

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.
