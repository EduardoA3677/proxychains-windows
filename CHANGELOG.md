# Changelog

All notable changes to proxychains-windows will be documented in this file.

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
