# API Documentation for Hooks

This document describes the hooked Win32 API functions and proxy protocol implementations in proxychains-windows.

## Hooked Winsock Functions

### Connection Hooks

| Function | DLL | Purpose |
|----------|-----|---------|
| `connect()` | Ws2_32.dll | Intercepts TCP connections, routes through proxy chain |
| `WSAConnect()` | Ws2_32.dll | Intercepts extended TCP connections, routes through proxy chain |
| `ConnectEx()` | Mswsock.dll | Intercepts overlapped TCP connections, routes through proxy chain |

### DNS Resolution Hooks

| Function | DLL | Purpose |
|----------|-----|---------|
| `gethostbyname()` | Ws2_32.dll | Intercepts DNS resolution, returns fake IPs for remote DNS |
| `gethostbyaddr()` | Ws2_32.dll | Intercepts reverse DNS lookups |
| `getaddrinfo()` | Ws2_32.dll | Intercepts modern DNS resolution |
| `GetAddrInfoW()` | Ws2_32.dll | Intercepts wide-string DNS resolution |
| `GetAddrInfoExA()` | Ws2_32.dll | Intercepts extended DNS resolution (ANSI) |
| `GetAddrInfoExW()` | Ws2_32.dll | Intercepts extended DNS resolution (Wide) |
| `freeaddrinfo()` | Ws2_32.dll | Intercepts address info cleanup |
| `FreeAddrInfoW()` | Ws2_32.dll | Intercepts wide address info cleanup |
| `FreeAddrInfoExA_()` | Ws2_32.dll | Intercepts extended address info cleanup (ANSI) |
| `FreeAddrInfoExW()` | Ws2_32.dll | Intercepts extended address info cleanup (Wide) |
| `getnameinfo()` | Ws2_32.dll | Intercepts name resolution from address |
| `GetNameInfoW()` | Ws2_32.dll | Intercepts wide name resolution from address |

### Process Creation Hooks

| Function | DLL | Purpose |
|----------|-----|---------|
| `CreateProcessW()` | Kernel32.dll | Intercepts process creation to inject hook DLL into child processes |

## Proxy Protocol Implementations

### SOCKS5 (`socks5`)

- **Connect Function**: `Ws2_32_Socks5Connect()`
- **Handshake Function**: `Ws2_32_Socks5Handshake()`
- **Supported Address Types**: IPv4, IPv6, Hostname
- **Authentication**: Username/password (RFC 1929)
- **Protocol**: RFC 1928

**Connection Flow**:
1. Handshake: Send auth method selection → Receive server method choice
2. Authentication (if required): Send username/password → Receive auth result
3. Connect: Send CONNECT request with target address → Receive connect response

### SOCKS4/SOCKS4a (`socks4`)

- **Connect Function**: `Ws2_32_Socks4Connect()`
- **Handshake Function**: `Ws2_32_Socks4Handshake()` (no-op)
- **Supported Address Types**: IPv4, Hostname (SOCKS4a)
- **Authentication**: Userid (ident-based)

**Connection Flow**:
1. Send CONNECT request with VN=4, CD=1, DSTPORT, DSTIP, USERID, NULL
2. For SOCKS4a hostnames: set DSTIP to 0.0.0.x, append hostname after userid
3. Receive 8-byte response, check CD=0x5A for success

### HTTP CONNECT (`http`)

- **Connect Function**: `Ws2_32_HttpConnect()`
- **Handshake Function**: `Ws2_32_HttpHandshake()` (no-op)
- **Supported Address Types**: IPv4, IPv6, Hostname
- **Authentication**: Basic (username:password base64-encoded)

**Connection Flow**:
1. Send `CONNECT host:port HTTP/1.1\r\nHost: host:port\r\n`
2. If auth: Add `Proxy-Authorization: Basic <base64>\r\n`
3. Send `\r\n` (end of headers)
4. Receive response, check for `HTTP/1.x 200`
5. Drain remaining headers until `\r\n\r\n`

## Chain Modes

### Strict Chain (`strict_chain`)
All proxies in order. Any failure aborts the entire chain.
Health tracking: failure counters incremented on failure, reset on success.

### Dynamic Chain (`dynamic_chain`)
All proxies in order, dead ones are skipped. At least one must succeed.
Health tracking: proxies with ≥3 consecutive failures are auto-skipped.
When all proxies fail, counters are reset for retry.

### Random Chain (`random_chain`)
Randomly selects `chain_len` unique proxies from the list.
Supports `random_seed` for reproducible selection.

### Round-Robin Chain (`round_robin_chain`)
Cycles through proxies using a thread-safe `InterlockedIncrement` counter.
Uses `chain_len` proxies starting from current rotation position.

## Health Checking

Per-proxy health tracking is implemented using thread-safe counters:

```c
// In hook_connect_win32.c
static volatile LONG g_proxyFailureCount[PXCH_MAX_PROXY_NUM];  // Consecutive failures
static volatile LONG g_proxySuccessCount[PXCH_MAX_PROXY_NUM];  // Total successes
```

**Behavior**:
- On proxy failure: `InterlockedIncrement(&g_proxyFailureCount[index])`
- On proxy success: `InterlockedExchange(&g_proxyFailureCount[index], 0)` (reset)
- In dynamic mode: proxies with `g_proxyFailureCount[i] >= 3` are skipped
- When all proxies are dead: all failure counters are reset to allow retry

## Internal Helper Functions

| Function | Purpose |
|----------|---------|
| `Ws2_32_BlockConnect()` | Connect with timeout using select() for non-blocking sockets |
| `Ws2_32_LoopSend()` | Send all bytes, retrying until complete or error |
| `Ws2_32_LoopRecv()` | Receive exact byte count, with timeout via select() |
| `Ws2_32_OriginalConnect()` | Direct call to original connect() without blocking |
| `Ws2_32_DirectConnect()` | Connect directly (used when chain is empty) |
| `Ws2_32_GenericConnectTo()` | Connect through current chain to a target host |
| `Ws2_32_GenericTunnelTo()` | Tunnel to a specific proxy (connect + handshake) |
| `TunnelThroughProxyChain()` | Route connection through chain based on mode |

## Configuration Structure

The `PROXYCHAINS_CONFIG` structure (defined in `defines_generic.h`) is shared between the launcher executable and injected DLL via memory-mapped files. Key fields:

| Field | Type | Description |
|-------|------|-------------|
| `dwChainType` | UINT32 | Chain mode (STRICT/DYNAMIC/RANDOM/ROUND_ROBIN) |
| `dwChainLen` | UINT32 | Number of proxies per connection (random/round-robin) |
| `dwRandomSeed` | UINT32 | Fixed seed for random chain mode |
| `dwRandomSeedSet` | UINT32 | Whether random_seed was explicitly set |
| `dwProxyConnectionTimeoutMillisecond` | UINT32 | TCP connect timeout (default: 3000ms) |
| `dwProxyHandshakeTimeoutMillisecond` | UINT32 | Handshake read timeout (default: 5000ms) |
| `dwProxyNum` | UINT32 | Number of proxies in ProxyList |
| `dwRuleNum` | UINT32 | Number of routing rules |
