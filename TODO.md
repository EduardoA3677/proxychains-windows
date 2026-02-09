# TODO List - Proxychains-Windows Features & Improvements

## High Priority Features

### Dynamic Chain Support
- [x] Implement dynamic chain mode (skip dead proxies)
- [x] Add proxy health checking mechanism
- [x] Implement automatic proxy failover
- [x] Add timeout-based proxy detection
- **Status**: Implemented
- **Difficulty**: Medium
- **Impact**: High - Better reliability when proxies fail

### Round Robin Chain Support
- [x] Implement round-robin proxy selection
- [x] Add chain length configuration support
- [x] Thread-safe proxy rotation
- [x] Persistent state for proxy rotation across processes
- **Status**: Fully Implemented
- **Difficulty**: Medium
- **Impact**: Medium - Load balancing across proxies

### Random Chain Support
- [x] Implement random proxy selection
- [x] Configurable chain length
- [x] Random seed configuration
- **Status**: Implemented
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
- [x] Support for HTTP/HTTPS proxy (SOCKS5 also supported)
- [x] Support for SOCKS4/SOCKS4a proxies
- [x] Environment variable expansion in config
- [ ] Multiple configuration file profiles
- [ ] Reload configuration without restart
- **Status**: HTTP/HTTPS, SOCKS4/SOCKS4a, and environment variable expansion implemented
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
- [x] Per-process log files
- [ ] Structured logging (JSON output option)
- [ ] Log rotation
- [ ] Performance metrics logging
- [ ] Visual Studio debug output improvements
- **Status**: Per-process log files implemented
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
- [ ] ASLR and DEP enforcement verification
- [ ] Security audit of DLL injection code
- [ ] Sandboxing options
- [ ] Certificate pinning for HTTPS proxies
- **Status**: Basic security only
- **Difficulty**: High
- **Impact**: Medium - Enhanced security

## Bug Fixes & Improvements

### Known Issues
- [x] Domain name resolution should be case-insensitive
- [ ] Handle "fork-and-exit" child processes properly
- [ ] Powershell wget compatibility issues
- [ ] Better ConEmu compatibility (currently incompatible)
- [ ] Handle Cygwin encoding issues completely
- **Status**: Domain name case-insensitive fix implemented
- **Difficulty**: Various
- **Impact**: Various

### Code Quality
- [ ] Refactor large functions into smaller ones
- [ ] Improve error handling consistency
- [ ] Add more inline documentation
- [ ] Reduce code duplication
- [ ] Better separation of concerns (Win32 vs Cygwin code)
- **Status**: Basic code structure exists
- **Difficulty**: Medium
- **Impact**: Medium - Maintainability

### Documentation
- [x] Developer documentation (CONTRIBUTING.md created)
- [x] README with authentication examples
- [ ] API documentation for hooks
- [ ] Architecture diagrams
- [ ] Video tutorials
- [ ] Troubleshooting guide expansion
- **Status**: CONTRIBUTING.md and enhanced README completed
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
- **Status**: Proxy authentication fully implemented for all proxy types
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

### Completed ✅
1. ✅ Dynamic chain support (skip dead proxies)
2. ✅ HTTP/HTTPS and SOCKS4/SOCKS4a proxy support
3. ✅ Round-robin and random chain modes
4. ✅ Persistent round-robin state
5. ✅ Environment variable expansion in config
6. ✅ Per-process log file configuration
7. ✅ Developer documentation (CONTRIBUTING.md)
8. ✅ Authentication documentation and examples

### Realistic Next Steps (Community Contributions Welcome)
1. Testing framework with mock proxy server
2. Better error messages and validation
3. Process name filtering (whitelist/blacklist)
4. Configuration reload without restart
5. Log rotation and structured logging

### Advanced Features (Require Significant Effort)
1. UDP Associate for DNS (2-4 weeks, complex SOCKS5 UDP protocol)
2. GUI application (4-8 weeks, separate skillset)
3. Full IPv6 improvements (2-3 weeks, complex networking)
4. DNS daemon (2-3 weeks, requires separate process)

### Not Feasible / Out of Scope
1. Kernel-mode filtering (requires driver development)
2. VPN-like system-wide proxy (requires system integration)
3. Browser extension integration (different technology stack)
4. Alternative DLL injection methods (current method works well)

## Contributing

**Want to contribute? We'd love your help!**

See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Development setup guide
- Code structure and architecture
- Coding standards and conventions
- Building and testing procedures
- Pull request process

If you want to contribute to any of the remaining features:
1. Check [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines
2. Check the issue tracker for related discussions
3. Comment on the feature you want to work on
4. Fork the repository and create a feature branch
5. Submit a pull request with tests and documentation

**High-priority contributions:**
- Testing infrastructure with mock proxies
- Better error messages and validation
- Process filtering (whitelist/blacklist)
- Performance improvements
- Bug fixes and security improvements
