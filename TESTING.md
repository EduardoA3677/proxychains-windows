# Testing Guide for Unified Binary

This guide explains how to test the new unified x86/x64 binary features in proxychains-windows.

## Prerequisites

1. Windows 11, Windows 10, or Windows 7 (64-bit)
2. Visual C++ Redistributable for Visual Studio 2015 or later
3. A SOCKS5 proxy server for testing

## Building the Unified Binary

### Using Visual Studio

1. Open `proxychains.exe.sln` in Visual Studio
2. Build both configurations:
   - Select `Release|x64` and build solution
   - Select `Release|x86` and build solution
3. The binaries will be in `win32_output/` directory

### Expected Output Files

After building both configurations, you should have:
- `proxychains.exe` (x64) - main executable
- `proxychains_hook_x64.dll` - hook DLL for 64-bit processes
- `proxychains_hook_x86.dll` - hook DLL for 32-bit processes
- `MinHook.x64.dll` and `MinHook.x86.dll` (if using dynamic MinHook)

## Testing Cross-Architecture Support

### Test 1: Verify Automatic Detection with x64 Process

1. Place the x64 `proxychains.exe` and both DLLs in a directory
2. Configure `proxychains.conf` with a working proxy
3. Test with a 64-bit application:
   ```cmd
   proxychains.exe "C:\Windows\System32\curl.exe" https://ifconfig.me
   ```
4. Check the log output - it should show:
   ```
   Target arch: x64, using DLL: [path]\proxychains_hook_x64.dll
   ```

### Test 2: Verify Automatic Detection with x86 Process

1. Using the same x64 `proxychains.exe`
2. Test with a 32-bit application:
   ```cmd
   proxychains.exe "C:\Windows\SysWOW64\curl.exe" https://ifconfig.me
   ```
3. Check the log output - it should show:
   ```
   Target arch: x86, using DLL: [path]\proxychains_hook_x86.dll
   ```

### Test 3: Verify Error Messages

1. Remove `proxychains_hook_x86.dll` temporarily
2. Run the x64 executable:
   ```cmd
   proxychains.exe notepad.exe
   ```
3. You should see a warning (not an error) for missing x86 DLL
4. The program should still work for x64 processes

### Test 4: Test with Common Applications

Test with various applications to ensure compatibility:

**64-bit Applications:**
- PowerShell: `proxychains.exe powershell.exe`
- Git (64-bit): `proxychains.exe git clone <repo>`
- SSH (64-bit): `proxychains.exe ssh user@host`

**32-bit Applications:**
- Notepad (on 64-bit Windows): Often runs as 64-bit, but depends on system
- Older applications installed in `Program Files (x86)`
- 32-bit versions of browsers or tools

### Test 5: Verify Nested Process Injection

Test that child processes also get proxied:
```cmd
proxychains.exe cmd.exe
# Inside the proxied cmd:
curl https://ifconfig.me
```

Both the parent (cmd.exe) and child (curl.exe) should be proxied.

## Windows 11 Specific Testing

### Test on Windows 11

1. Verify the application runs without compatibility mode
2. Check that it works with Windows 11's enhanced security features
3. Test with Windows 11 native applications like Windows Terminal

### Test with Windows Defender

1. Ensure Windows Defender doesn't flag the DLL injection
2. If flagged, add exceptions for the proxychains directory
3. Verify the application works after adding exceptions

## Troubleshooting

### Issue: DLL Not Found

**Symptoms:** Error message about missing DLL
**Solution:** 
- Check that both `proxychains_hook_x64.dll` and `proxychains_hook_x86.dll` are in the same directory as `proxychains.exe`
- Check the error message for the exact expected path
- Ensure DLL names match exactly (case-sensitive on some file systems)

### Issue: Target Process Not Proxied

**Symptoms:** Application starts but doesn't use proxy
**Solution:**
- Check that the application is dynamically linked (not statically linked)
- Verify proxy configuration in `proxychains.conf`
- Check log level is set high enough to see debug messages
- Some applications may require elevated privileges

### Issue: Application Crashes

**Symptoms:** Target application crashes immediately
**Solution:**
- Try with a simpler application first (like curl)
- Check if application uses anti-debugging or anti-hooking techniques
- Verify the correct architecture DLL is being injected
- Check if application is compatible with DLL injection

## Logging and Debugging

Enable debug logging for troubleshooting:

1. Edit `proxychains.conf`:
   ```
   # Uncomment to see more details
   #quiet_mode
   ```

2. Set log level in config or via command line:
   ```cmd
   proxychains.exe -q <application>  # quiet
   proxychains.exe -v <application>  # verbose
   ```

3. Check Windows Event Viewer for application errors

## Expected Results

A successful test should show:
1. Automatic architecture detection working correctly
2. Correct DLL being injected for each process type
3. Network traffic going through the configured proxy
4. No errors or warnings in the logs (except for expected warnings)
5. Child processes also being proxied automatically

## Reporting Issues

If you encounter issues, please report with:
1. Windows version (including build number)
2. Application being proxied (and its architecture)
3. Full error message or log output
4. Steps to reproduce
5. Contents of `proxychains.conf` (with sensitive info removed)

## Testing Chain Modes

### Test 1: Dynamic Chain Mode

Test that dynamic chain skips dead proxies:

1. Edit `proxychains.conf`:
   ```
   #strict_chain
   dynamic_chain
   
   [ProxyList]
   socks5 127.0.0.1 9999  # Dead proxy
   socks5 localhost 1080  # Working proxy
   ```

2. Run a test application:
   ```cmd
   proxychains.exe curl https://ifconfig.me
   ```

3. Expected result: Connection succeeds, logs show proxy 1 failed and proxy 2 succeeded

### Test 2: Random Chain Mode

Test that random chain selects random proxies:

1. Edit `proxychains.conf`:
   ```
   #strict_chain
   random_chain
   chain_len = 2
   
   [ProxyList]
   socks5 proxy1.example.com 1080
   socks5 proxy2.example.com 1080
   socks5 proxy3.example.com 1080
   ```

2. Run multiple connections:
   ```cmd
   proxychains.exe curl https://ifconfig.me
   proxychains.exe curl https://ifconfig.me
   proxychains.exe curl https://ifconfig.me
   ```

3. Expected result: Each connection uses 2 randomly selected proxies, different combinations observed

### Test 3: Round-Robin Chain Mode

Test that round-robin rotates through proxies:

1. Edit `proxychains.conf`:
   ```
   #strict_chain
   round_robin_chain
   chain_len = 1
   
   [ProxyList]
   socks5 proxy1.example.com 1080
   socks5 proxy2.example.com 1080
   socks5 proxy3.example.com 1080
   ```

2. Run multiple connections:
   ```cmd
   proxychains.exe curl https://ifconfig.me
   proxychains.exe curl https://ifconfig.me
   proxychains.exe curl https://ifconfig.me
   ```

3. Expected result: First connection uses proxy1, second uses proxy2, third uses proxy3, then loops back

### Test 4: Strict Chain Mode (Default)

Test that strict chain requires all proxies to work:

1. Edit `proxychains.conf`:
   ```
   strict_chain
   
   [ProxyList]
   socks5 127.0.0.1 9999  # Dead proxy
   socks5 localhost 1080  # Working proxy
   ```

2. Run a test application:
   ```cmd
   proxychains.exe curl https://ifconfig.me
   ```

3. Expected result: Connection fails because first proxy is dead

### Test 5: Chain Length Configuration

Test different chain lengths:

1. Edit `proxychains.conf`:
   ```
   random_chain
   chain_len = 3
   
   [ProxyList]
   # Add 5+ proxies here
   ```

2. Check logs to verify exactly 3 proxies are used per connection
