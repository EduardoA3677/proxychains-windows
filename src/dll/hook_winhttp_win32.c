// SPDX-License-Identifier: GPL-2.0-or-later
/* hook_winhttp_win32.c
 * Copyright (C) 2020 Feng Shun.
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License version 2 as 
 *   published by the Free Software Foundation, either version 3 of the
 *   License, or (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License version 2 for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   version 2 along with this program. If not, see
 *   <http://www.gnu.org/licenses/>.
 */

// Hook WinHTTP and WinINet APIs to force proxy settings.
// Applications using these high-level HTTP APIs (PowerShell, browsers, etc.)
// will transparently use the configured SOCKS5/HTTP proxy.

#define PXCH_DO_NOT_INCLUDE_STD_HEADERS_NOW
#define PXCH_DO_NOT_INCLUDE_STRSAFE_NOW
#include "includes_win32.h"
#include <winsock2.h>
#include <strsafe.h>
#include "hookdll_util_win32.h"
#include "log_generic.h"
#include <MinHook.h>

#include "hookdll_win32.h"

#ifndef __CYGWIN__

// ============================================================================
// WinHTTP types and constants (from winhttp.h)
// We define them locally to avoid header dependency issues
// ============================================================================

#define PXCH_WINHTTP_ACCESS_TYPE_DEFAULT_PROXY    0
#define PXCH_WINHTTP_ACCESS_TYPE_NO_PROXY         1
#define PXCH_WINHTTP_ACCESS_TYPE_NAMED_PROXY      3
#define PXCH_WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY   4

#define PXCH_WINHTTP_OPTION_PROXY                 38

#define PXCH_WINHTTP_NO_PROXY_NAME                NULL
#define PXCH_WINHTTP_NO_PROXY_BYPASS              NULL

typedef struct {
	DWORD  dwAccessType;
	LPWSTR lpszProxy;
	LPWSTR lpszProxyBypass;
} PXCH_WINHTTP_PROXY_INFO;

// ============================================================================
// WinINet types and constants (from wininet.h)
// ============================================================================

#define PXCH_INTERNET_OPEN_TYPE_DIRECT          0
#define PXCH_INTERNET_OPEN_TYPE_PROXY           3
#define PXCH_INTERNET_OPEN_TYPE_PRECONFIG       0

#define PXCH_INTERNET_OPTION_PROXY              38

typedef struct {
	DWORD dwAccessType;
	LPSTR lpszProxy;
	LPSTR lpszProxyBypass;
} PXCH_INTERNET_PROXY_INFO_A;

typedef struct {
	DWORD  dwAccessType;
	LPWSTR lpszProxy;
	LPWSTR lpszProxyBypass;
} PXCH_INTERNET_PROXY_INFO_W;


// ============================================================================
// Helper: Build proxy string from config
// ============================================================================

// Build a proxy URL string like "socks5://host:port" or "http://host:port"
// from the first proxy in the configured proxy list.
static BOOL BuildProxyStringW(wchar_t* szProxy, DWORD cchProxy)
{
	const PXCH_PROXY_DATA* pProxy;
	const wchar_t* szScheme;
	PXCH_UINT16 wPort;
	char szHostA[PXCH_MAX_HOSTNAME_BUFSIZE];
	wchar_t szHostW[PXCH_MAX_HOSTNAME_BUFSIZE];

	if (!g_pPxchConfig || g_pPxchConfig->dwProxyNum == 0) return FALSE;

	pProxy = &PXCH_CONFIG_PROXY_ARR(g_pPxchConfig)[0];

	if (ProxyIsType(SOCKS5, *pProxy)) {
		szScheme = L"socks5";
	} else if (ProxyIsType(SOCKS4, *pProxy)) {
		szScheme = L"socks4";
	} else if (ProxyIsType(HTTP, *pProxy)) {
		szScheme = L"http";
	} else {
		return FALSE;
	}

	// Extract host and port from the proxy's HostPort
	if (HostIsType(HOSTNAME, pProxy->CommonHeader.HostPort)) {
		StringCchCopyW(szHostW, _countof(szHostW), pProxy->CommonHeader.HostPort.HostnamePort.szValue);
	} else if (HostIsType(IPV4, pProxy->CommonHeader.HostPort)) {
		const struct sockaddr_in* pSin = (const struct sockaddr_in*)&pProxy->CommonHeader.HostPort.IpPort.Sockaddr;
		const unsigned char* b = (const unsigned char*)&pSin->sin_addr;
		StringCchPrintfW(szHostW, _countof(szHostW), L"%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
	} else {
		return FALSE;
	}

	wPort = _byteswap_ushort(pProxy->CommonHeader.HostPort.CommonHeader.wPort);

	StringCchPrintfW(szProxy, cchProxy, L"%ls=%ls:%u", szScheme, szHostW, (unsigned int)wPort);
	return TRUE;
}

static BOOL BuildProxyStringA(char* szProxy, DWORD cchProxy)
{
	wchar_t szProxyW[512];
	if (!BuildProxyStringW(szProxyW, _countof(szProxyW))) return FALSE;

	// Convert wide to narrow
	WideCharToMultiByte(CP_ACP, 0, szProxyW, -1, szProxy, (int)cchProxy, NULL, NULL);
	return TRUE;
}


// ============================================================================
// WinHTTP Hooks
// ============================================================================

// WinHttpOpen: Intercept to force named proxy access type
PROXY_FUNC2(WinHttp, Open)
{
	void* hSession;
	wchar_t szProxy[512];
	BOOL bHasProxy;

	bHasProxy = BuildProxyStringW(szProxy, _countof(szProxy));

	if (bHasProxy && dwAccessType != PXCH_WINHTTP_ACCESS_TYPE_NAMED_PROXY) {
		FUNCIPCLOGD(L"WinHttpOpen: Overriding access type to NAMED_PROXY with proxy %ls", szProxy);
		dwAccessType = PXCH_WINHTTP_ACCESS_TYPE_NAMED_PROXY;
		pszProxyName = szProxy;
		pszProxyBypass = L"<local>";
	}

	hSession = orig_fpWinHttp_Open(pszAgentW, dwAccessType, pszProxyName, pszProxyBypass, dwFlags);

	if (hSession) {
		FUNCIPCLOGD(L"WinHttpOpen: Session %p created (access_type=%lu)", hSession, dwAccessType);
	}

	return hSession;
}

// WinHttpSetOption: Intercept proxy option changes to enforce our proxy
PROXY_FUNC2(WinHttp, SetOption)
{
	if (dwOption == PXCH_WINHTTP_OPTION_PROXY && lpBuffer && dwBufferLength >= sizeof(PXCH_WINHTTP_PROXY_INFO)) {
		wchar_t szProxy[512];
		if (BuildProxyStringW(szProxy, _countof(szProxy))) {
			PXCH_WINHTTP_PROXY_INFO* pProxyInfo = (PXCH_WINHTTP_PROXY_INFO*)lpBuffer;
			FUNCIPCLOGD(L"WinHttpSetOption: Overriding WINHTTP_OPTION_PROXY to %ls", szProxy);
			pProxyInfo->dwAccessType = PXCH_WINHTTP_ACCESS_TYPE_NAMED_PROXY;
			pProxyInfo->lpszProxy = szProxy;
			pProxyInfo->lpszProxyBypass = L"<local>";
		}
	}

	return orig_fpWinHttp_SetOption(hInternet, dwOption, lpBuffer, dwBufferLength);
}


// ============================================================================
// WinINet Hooks
// ============================================================================

// InternetOpenA: Intercept to force proxy access type
PROXY_FUNC2(WinINet, InternetOpenA)
{
	void* hInternet;
	char szProxy[512];
	BOOL bHasProxy;

	bHasProxy = BuildProxyStringA(szProxy, _countof(szProxy));

	if (bHasProxy && dwAccessType != PXCH_INTERNET_OPEN_TYPE_PROXY) {
		FUNCIPCLOGD(L"InternetOpenA: Overriding access type to PROXY with proxy " WPRS, szProxy);
		dwAccessType = PXCH_INTERNET_OPEN_TYPE_PROXY;
		lpszProxy = szProxy;
		lpszProxyBypass = "<local>";
	}

	hInternet = orig_fpWinINet_InternetOpenA(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);

	if (hInternet) {
		FUNCIPCLOGD(L"InternetOpenA: Session %p created (access_type=%lu)", hInternet, dwAccessType);
	}

	return hInternet;
}

// InternetOpenW: Intercept to force proxy access type
PROXY_FUNC2(WinINet, InternetOpenW)
{
	void* hInternet;
	wchar_t szProxy[512];
	BOOL bHasProxy;

	bHasProxy = BuildProxyStringW(szProxy, _countof(szProxy));

	if (bHasProxy && dwAccessType != PXCH_INTERNET_OPEN_TYPE_PROXY) {
		FUNCIPCLOGD(L"InternetOpenW: Overriding access type to PROXY with proxy %ls", szProxy);
		dwAccessType = PXCH_INTERNET_OPEN_TYPE_PROXY;
		lpszProxy = szProxy;
		lpszProxyBypass = L"<local>";
	}

	hInternet = orig_fpWinINet_InternetOpenW(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);

	if (hInternet) {
		FUNCIPCLOGD(L"InternetOpenW: Session %p created (access_type=%lu)", hInternet, dwAccessType);
	}

	return hInternet;
}

// InternetSetOptionA: Intercept proxy option changes
PROXY_FUNC2(WinINet, InternetSetOptionA)
{
	if (dwOption == PXCH_INTERNET_OPTION_PROXY && lpBuffer && dwBufferLength >= sizeof(PXCH_INTERNET_PROXY_INFO_A)) {
		char szProxy[512];
		if (BuildProxyStringA(szProxy, _countof(szProxy))) {
			PXCH_INTERNET_PROXY_INFO_A* pProxyInfo = (PXCH_INTERNET_PROXY_INFO_A*)lpBuffer;
			FUNCIPCLOGD(L"InternetSetOptionA: Overriding INTERNET_OPTION_PROXY to " WPRS, szProxy);
			pProxyInfo->dwAccessType = PXCH_INTERNET_OPEN_TYPE_PROXY;
			pProxyInfo->lpszProxy = szProxy;
			pProxyInfo->lpszProxyBypass = "<local>";
		}
	}

	return orig_fpWinINet_InternetSetOptionA(hInternet, dwOption, lpBuffer, dwBufferLength);
}

// InternetSetOptionW: Intercept proxy option changes
PROXY_FUNC2(WinINet, InternetSetOptionW)
{
	if (dwOption == PXCH_INTERNET_OPTION_PROXY && lpBuffer && dwBufferLength >= sizeof(PXCH_INTERNET_PROXY_INFO_W)) {
		wchar_t szProxy[512];
		if (BuildProxyStringW(szProxy, _countof(szProxy))) {
			PXCH_INTERNET_PROXY_INFO_W* pProxyInfo = (PXCH_INTERNET_PROXY_INFO_W*)lpBuffer;
			FUNCIPCLOGD(L"InternetSetOptionW: Overriding INTERNET_OPTION_PROXY to %ls", szProxy);
			pProxyInfo->dwAccessType = PXCH_INTERNET_OPEN_TYPE_PROXY;
			pProxyInfo->lpszProxy = szProxy;
			pProxyInfo->lpszProxyBypass = L"<local>";
		}
	}

	return orig_fpWinINet_InternetSetOptionW(hInternet, dwOption, lpBuffer, dwBufferLength);
}

#endif // __CYGWIN__
