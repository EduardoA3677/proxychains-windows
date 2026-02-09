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

## Testing Chain Modes

### Test 6: Strict Chain Mode (Default)

1. Configure `proxychains.conf` with `strict_chain` and multiple proxies
2. All proxies must be online for the chain to work
3. Test:
   ```cmd
   proxychains.exe curl.exe https://ifconfig.me
   ```
4. If any proxy is down, the connection should fail

### Test 7: Dynamic Chain Mode

1. Configure `proxychains.conf`:
   ```
   dynamic_chain
   ```
2. Add multiple proxies in `[ProxyList]`, with at least one intentionally dead
3. Test:
   ```cmd
   proxychains.exe curl.exe https://ifconfig.me
   ```
4. Check logs - dead proxies should show a warning and be skipped
5. Connection should succeed through the alive proxy/proxies
6. If ALL proxies are dead, the connection should fail

### Test 8: Random Chain Mode

1. Configure `proxychains.conf`:
   ```
   random_chain
   chain_len = 1
   ```
2. Add multiple working proxies in `[ProxyList]`
3. Test multiple times:
   ```cmd
   proxychains.exe curl.exe https://ifconfig.me
   proxychains.exe curl.exe https://ifconfig.me
   ```
4. Check logs - different proxies should be selected each time
5. Verify `chain_len` controls how many proxies are used per connection

### Test 9: Round-Robin Chain Mode

1. Configure `proxychains.conf`:
   ```
   round_robin_chain
   chain_len = 1
   ```
2. Add multiple working proxies in `[ProxyList]`
3. Test multiple times:
   ```cmd
   proxychains.exe curl.exe https://ifconfig.me
   proxychains.exe curl.exe https://ifconfig.me
   proxychains.exe curl.exe https://ifconfig.me
   ```
4. Check logs - proxies should be selected sequentially (0, 1, 2, 0, 1, 2, ...)

### Test 10: SOCKS4 Proxy

1. Configure `proxychains.conf` with a SOCKS4 proxy:
   ```
   [ProxyList]
   socks4 proxy-server 1080
   ```
2. Test:
   ```cmd
   proxychains.exe curl.exe https://ifconfig.me
   ```
3. SOCKS4 only supports IPv4 connections; IPv6 targets will fail with an appropriate error

### Test 11: HTTP CONNECT Proxy

1. Configure `proxychains.conf` with an HTTP proxy:
   ```
   [ProxyList]
   http proxy-server 8080
   ```
2. For authenticated proxy:
   ```
   [ProxyList]
   http proxy-server 8080 username password
   ```
3. Test:
   ```cmd
   proxychains.exe curl.exe https://ifconfig.me
   ```

### Test 12: Case-Insensitive DNS

1. Add entries to custom hosts file with mixed case:
   ```
   127.0.0.1 MyHost.Example.COM
   ```
2. Test that resolving `myhost.example.com` (lowercase) matches the entry
3. Verify the connection is handled correctly

### Test 13: Random Seed Configuration

1. Configure `proxychains.conf`:
   ```
   random_chain
   chain_len = 1
   random_seed = 42
   ```
2. Add multiple working proxies in `[ProxyList]`
3. Test multiple times:
   ```cmd
   proxychains.exe curl.exe https://ifconfig.me
   proxychains.exe curl.exe https://ifconfig.me
   ```
4. With the same seed, the proxy selection order should be deterministic
5. Remove the `random_seed` line and verify behavior returns to time-based randomness

### Test 14: Environment Variable Expansion

1. Set an environment variable with a hosts file path:
   ```cmd
   set CUSTOM_HOSTS=%USERPROFILE%\my_hosts
   ```
2. Configure `proxychains.conf`:
   ```
   custom_hosts_file_path %USERPROFILE%\my_hosts
   ```
3. Create the hosts file at the expanded path
4. Verify the hosts file is loaded correctly
5. Also test with the `-f` flag:
   ```cmd
   proxychains.exe -f %APPDATA%\proxychains.conf curl.exe https://ifconfig.me
   ```

### Test 15: Timeout Diagnostics

1. Configure `proxychains.conf` with a non-existent proxy:
   ```
   [ProxyList]
   socks5 192.0.2.1 1080
   ```
2. Set a short timeout:
   ```
   tcp_connect_time_out 2000
   ```
3. Test:
   ```cmd
   proxychains.exe curl.exe https://ifconfig.me
   ```
4. Verify the error message shows the timeout value and target address

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

### Issue: Proxy Connection Timeout

**Symptoms:** Long delays or `WSAETIMEDOUT` errors
**Solution:**
- Check proxy server is running and reachable
- Increase timeouts in config: `tcp_connect_time_out 10000` and `tcp_read_time_out 15000`
- Check firewall is not blocking the proxy port
- Try connecting directly to the proxy server with a SOCKS client
- In dynamic chain mode, check logs for "proxy marked dead" messages - the proxy may have been auto-skipped after 3 failures

### Issue: DNS Leak

**Symptoms:** DNS queries bypass the proxy
**Solution:**
- Ensure `proxy_dns` is enabled in `proxychains.conf`
- Use `DOMAIN-KEYWORD` or `DOMAIN-SUFFIX` rules for specific domains
- Check that the application uses `getaddrinfo()` or `gethostbyname()` (statically linked resolvers are not hooked)
- For UDP-based DNS: proxychains currently only intercepts TCP DNS queries

### Issue: Child Processes Not Proxied

**Symptoms:** Main application proxied but spawned processes are not
**Solution:**
- This is expected for "fork-and-exit" patterns where the parent exits immediately
- If `delete_fake_ip_after_child_exits` is set to 1, fake IP entries may be cleaned up too early
- Check logs for `CreateProcessW` hook messages to verify injection into child processes

### Issue: PowerShell wget Compatibility

**Symptoms:** `Invoke-WebRequest` or `wget` alias fails through proxy
**Solution:**
- PowerShell's `Invoke-WebRequest` uses .NET HTTP stack which may not go through Winsock hooks
- Use `curl.exe` instead: `proxychains.exe curl.exe https://example.com`
- Or use PowerShell's `[System.Net.WebClient]` with explicit proxy settings

## Logging and Debugging

Enable debug logging for troubleshooting:

1. Edit `proxychains.conf`:
   ```
   # Set verbose logging
   log_level 600
   ```

2. Set log level in config or via command line:
   ```cmd
   proxychains.exe -q <application>  # quiet (errors only)
   proxychains.exe -v <application>  # verbose (maximum detail)
   ```

3. Check Windows Event Viewer for application errors

4. Log level reference:
   - `600` - VERBOSE: All messages including per-byte I/O details
   - `500` - DEBUG: Connection routing, proxy selection, health tracking
   - `400` - INFO: Proxy connections, chain mode selection
   - `300` - WARNING: Proxy failures, timeouts, health-based skips
   - `200` - ERROR: Chain failures, configuration errors
   - `100` - CRITICAL: Fatal errors only

## Expected Results

A successful test should show:
1. Automatic architecture detection working correctly
2. Correct DLL being injected for each process type
3. Network traffic going through the configured proxy
4. No errors or warnings in the logs (except for expected warnings)
5. Child processes also being proxied automatically

## Testing Proxy Health Checking

### Test 16: Dynamic Chain with Health Tracking

1. Configure `proxychains.conf`:
   ```
   dynamic_chain
   ```
2. Add 3 proxies: one alive, one dead (non-existent), one alive
3. Make multiple connection attempts
4. Check logs: dead proxy should show increasing failure count, then be auto-skipped
5. Expected: `Dynamic chain: proxy 1 marked dead (3 consecutive failures), skipping`

### Test 17: Health Counter Reset

1. Configure `proxychains.conf` with `dynamic_chain`
2. Use all dead proxies
3. First attempt: all proxies tried and fail, counters reset
4. Second attempt: all proxies retried (counters were reset)
5. Expected: `Dynamic chain: all proxies failed! Resetting health counters.`

### Test 18: Strict Chain with Failure Tracking

1. Configure `proxychains.conf` with `strict_chain`
2. First proxy is alive, second is dead
3. Make connection attempt
4. Check logs: failure count should increment for dead proxy
5. Expected: `Strict chain: proxy 1 failed (failure count: 1)`

## Testing Process Name Filtering

### Test 19: Process Whitelist (process_only)

1. Configure `proxychains.conf`:
   ```
   process_only = curl.exe
   ```
2. Run:
   ```cmd
   proxychains.exe cmd.exe /c "curl https://ifconfig.me && ping localhost"
   ```
3. Expected: curl.exe gets injected (proxied), ping.exe does NOT get injected
4. Check logs: `Process filter: ping.exe not in whitelist, skipping injection`

### Test 20: Process Blacklist (process_except)

1. Configure `proxychains.conf`:
   ```
   process_except = notepad.exe
   process_except = calc.exe
   ```
2. Run:
   ```cmd
   proxychains.exe cmd.exe /c "curl https://ifconfig.me && notepad"
   ```
3. Expected: curl.exe gets injected (proxied), notepad.exe does NOT get injected
4. Check logs: `Process filter: notepad.exe matched blacklist entry, skipping injection`

### Test 21: Persistent Round-Robin State

1. Configure `proxychains.conf`:
   ```
   round_robin_chain
   chain_len = 1
   ```
2. Add 3 proxies
3. Run multiple commands in succession:
   ```cmd
   proxychains.exe curl https://ifconfig.me
   proxychains.exe curl https://ifconfig.me
   proxychains.exe curl https://ifconfig.me
   ```
4. Expected: Each command uses a different proxy (rotation persists across processes via shared memory)

## Reporting Issues

If you encounter issues, please report with:
1. Windows version (including build number)
2. Application being proxied (and its architecture)
3. Full error message or log output
4. Steps to reproduce
5. Contents of `proxychains.conf` (with sensitive info removed)
