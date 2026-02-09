// SPDX-License-Identifier: GPL-2.0-or-later
/* hook_createprocess_win32.c
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
#include "hookdll_util_win32.h"
#include "log_win32.h"
#include <psapi.h>
#include <Shlwapi.h>

#include "hookdll_win32.h"

#ifndef __CYGWIN__
#define wcscasecmp _wcsicmp
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "Shlwapi.lib")
#endif

// Check if a process should be injected based on process_only/process_except config.
// Returns TRUE if injection should proceed, FALSE if it should be skipped.
static BOOL ShouldInjectProcess(LPCWSTR lpApplicationName, LPWSTR lpCommandLine)
{
	PXCH_UINT32 i;
	const wchar_t* pExeName = NULL;

	if (!g_pPxchConfig || g_pPxchConfig->dwProcessFilterMode == PXCH_PROCESS_FILTER_NONE) {
		return TRUE;
	}

	// Extract the executable name from the application name or command line
	if (lpApplicationName) {
		pExeName = PathFindFileNameW(lpApplicationName);
	} else if (lpCommandLine) {
		// Skip leading whitespace and quotes
		const wchar_t* p = lpCommandLine;
		while (*p == L' ' || *p == L'\t') p++;
		if (*p == L'"') {
			p++;
			pExeName = PathFindFileNameW(p);
		} else {
			pExeName = PathFindFileNameW(p);
		}
	}

	if (!pExeName || *pExeName == L'\0') {
		return TRUE;
	}

	for (i = 0; i < g_pPxchConfig->dwProcessFilterCount; i++) {
		if (wcscasecmp(pExeName, g_pPxchConfig->szProcessFilterNames[i]) == 0) {
			if (g_pPxchConfig->dwProcessFilterMode == PXCH_PROCESS_FILTER_WHITELIST) {
				IPCLOGD(L"Process filter: %ls matched whitelist entry %ls, will inject", pExeName, g_pPxchConfig->szProcessFilterNames[i]);
				return TRUE;
			} else {
				IPCLOGD(L"Process filter: %ls matched blacklist entry %ls, skipping injection", pExeName, g_pPxchConfig->szProcessFilterNames[i]);
				return FALSE;
			}
		}
	}

	// No match found
	if (g_pPxchConfig->dwProcessFilterMode == PXCH_PROCESS_FILTER_WHITELIST) {
		IPCLOGD(L"Process filter: %ls not in whitelist, skipping injection", pExeName);
		return FALSE;
	}

	return TRUE;
}

PROXY_FUNC(CreateProcessA)
{
BOOL bRet;
	DWORD dwLastError;
	DWORD dwReturn = 0;
	PROCESS_INFORMATION ProcessInformation;

	g_bCurrentlyInWinapiCall = TRUE;

	// For cygwin: cygwin fork() will duplicate the data in child process, including pointer g_*.
	RestoreChildDataIfNecessary();

	IPCLOGD(L"(In CreateProcessA) g_pRemoteData->dwDebugDepth = " WPRDW, g_pRemoteData ? g_pRemoteData->dwDebugDepth : -1);

	bRet = orig_fpCreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags | CREATE_SUSPENDED, lpEnvironment, lpCurrentDirectory, lpStartupInfo, &ProcessInformation);
	dwLastError = GetLastError();

	IPCLOGD(L"CreateProcessA: %S, %S, lpProcessAttributes: %#llx, lpThreadAttributes: %#llx, bInheritHandles: %d, dwCreationFlags: %#lx, lpCurrentDirectory: %s; Ret: %u Child winpid " WPRDW L", tid " WPRDW, lpApplicationName, lpCommandLine, (UINT64)(uintptr_t)lpProcessAttributes, (UINT64)(uintptr_t)lpThreadAttributes, bInheritHandles, dwCreationFlags, lpCurrentDirectory, bRet, ProcessInformation.dwProcessId, ProcessInformation.dwThreadId);

	if (lpProcessInformation) {
		CopyMemory(lpProcessInformation, &ProcessInformation, sizeof(PROCESS_INFORMATION));
	}

	IPCLOGV(L"CreateProcessA: Copied.");
	if (!bRet) goto err_orig;
	
	IPCLOGV(L"CreateProcessA: After jmp to err_orig.");

	// Check process name filter before injection (convert ANSI to Wide)
	{
		wchar_t szAppNameW[PXCH_MAX_HOSTNAME_BUFSIZE] = { 0 };
		wchar_t szCmdLineW[PXCH_MAX_HOSTNAME_BUFSIZE] = { 0 };
		if (lpApplicationName) MultiByteToWideChar(CP_ACP, 0, lpApplicationName, -1, szAppNameW, PXCH_MAX_HOSTNAME_BUFSIZE);
		if (lpCommandLine) MultiByteToWideChar(CP_ACP, 0, lpCommandLine, -1, szCmdLineW, PXCH_MAX_HOSTNAME_BUFSIZE);
		if (!ShouldInjectProcess(lpApplicationName ? szAppNameW : NULL, lpCommandLine ? szCmdLineW : NULL)) {
			IPCLOGD(L"CreateProcessA: Process filtered out, not injecting WINPID " WPRDW, ProcessInformation.dwProcessId);
			if (!(dwCreationFlags & CREATE_SUSPENDED)) {
				ResumeThread(ProcessInformation.hThread);
			}
			g_bCurrentlyInWinapiCall = FALSE;
			SetLastError(dwLastError);
			return 1;
		}
	}

	IPCLOGV(L"CreateProcessA: Before InjectTargetProcess.");

	dwReturn = InjectTargetProcess(&ProcessInformation, dwCreationFlags);

	IPCLOGV(L"CreateProcessA: Injected. " WPRDW, dwReturn);

	if (g_bUseRemoteThreadInsteadOfEntryDetour) {
		if (!(dwCreationFlags & CREATE_SUSPENDED)) {
			ResumeThread(ProcessInformation.hThread);
		}
	}

	if (dwReturn != 0) goto err_inject;
	IPCLOGD(L"I've Injected WINPID " WPRDW, ProcessInformation.dwProcessId);

	g_bCurrentlyInWinapiCall = FALSE;
	return 1;

err_orig:
	IPCLOGE(L"CreateProcessA Error: " WPRDW L", %ls", bRet, FormatErrorToStr(dwLastError));
	SetLastError(dwLastError);
	g_bCurrentlyInWinapiCall = FALSE;
	return bRet;

err_inject:
	IPCLOGW(L"Injecting WINPID " WPRDW L" Error: %ls", ProcessInformation.dwProcessId, FormatErrorToStr(dwReturn));
	// TODO: remove this line
	SetLastError(dwReturn);
	g_bCurrentlyInWinapiCall = FALSE;
	return 1;
}

PROXY_FUNC(CreateProcessW)
{
	BOOL bRet;
	DWORD dwLastError;
	DWORD dwReturn = 0;
	PROCESS_INFORMATION ProcessInformation;

	g_bCurrentlyInWinapiCall = TRUE;

	// For cygwin: cygwin fork() will duplicate the data in child process, including pointer g_*.
	RestoreChildDataIfNecessary();

	IPCLOGD(L"(In CreateProcessW) g_pRemoteData->dwDebugDepth = " WPRDW, g_pRemoteData ? g_pRemoteData->dwDebugDepth : -1);

	bRet = orig_fpCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags | CREATE_SUSPENDED, lpEnvironment, lpCurrentDirectory, lpStartupInfo, &ProcessInformation);
	dwLastError = GetLastError();

	IPCLOGD(L"CreateProcessW: %ls, %ls, lpProcessAttributes: %#llx, lpThreadAttributes: %#llx, bInheritHandles: %d, dwCreationFlags: %#lx, lpCurrentDirectory: %s; Ret: %u Child winpid " WPRDW L", tid " WPRDW, lpApplicationName, lpCommandLine, (UINT64)(uintptr_t)lpProcessAttributes, (UINT64)(uintptr_t)lpThreadAttributes, bInheritHandles, dwCreationFlags, lpCurrentDirectory, bRet, ProcessInformation.dwProcessId, ProcessInformation.dwThreadId);

	if (lpProcessInformation) {
		CopyMemory(lpProcessInformation, &ProcessInformation, sizeof(PROCESS_INFORMATION));
	}

	IPCLOGV(L"CreateProcessW: Copied.");
	if (!bRet) goto err_orig;
	
	IPCLOGV(L"CreateProcessW: After jmp to err_orig.");

	// Check process name filter before injection
	if (!ShouldInjectProcess(lpApplicationName, lpCommandLine)) {
		IPCLOGD(L"CreateProcessW: Process filtered out, not injecting WINPID " WPRDW, ProcessInformation.dwProcessId);
		if (!(dwCreationFlags & CREATE_SUSPENDED)) {
			ResumeThread(ProcessInformation.hThread);
		}
		g_bCurrentlyInWinapiCall = FALSE;
		SetLastError(dwLastError);
		return 1;
	}

	IPCLOGV(L"CreateProcessW: Before InjectTargetProcess.");

	dwReturn = InjectTargetProcess(&ProcessInformation, dwCreationFlags);

	IPCLOGV(L"CreateProcessW: Injected. " WPRDW, dwReturn);

	if (g_bUseRemoteThreadInsteadOfEntryDetour) {
		if (!(dwCreationFlags & CREATE_SUSPENDED)) {
			ResumeThread(ProcessInformation.hThread);
		}
	}

	if (dwReturn != 0) goto err_inject;
	IPCLOGD(L"I've Injected WINPID " WPRDW, ProcessInformation.dwProcessId);

	g_bCurrentlyInWinapiCall = FALSE;
	return 1;

err_orig:
	IPCLOGE(L"CreateProcessW Error: " WPRDW L", %ls", bRet, FormatErrorToStr(dwLastError));
	SetLastError(dwLastError);
	g_bCurrentlyInWinapiCall = FALSE;
	return bRet;

err_inject:
	IPCLOGW(L"Injecting WINPID " WPRDW L" Error: %ls", ProcessInformation.dwProcessId, FormatErrorToStr(dwReturn));
	// TODO: remove this line
	SetLastError(dwReturn);
	g_bCurrentlyInWinapiCall = FALSE;
	return 1;
}

PROXY_FUNC(CreateProcessAsUserW)
{
	BOOL bRet;
	DWORD dwLastError;
	DWORD dwReturn = 0;
	PROCESS_INFORMATION ProcessInformation;

	g_bCurrentlyInWinapiCall = TRUE;

	// For cygwin: cygwin fork() will duplicate the data in child process, including pointer g_*.
	RestoreChildDataIfNecessary();

	IPCLOGD(L"(In CreateProcessAsUserW) g_pRemoteData->dwDebugDepth = " WPRDW, g_pRemoteData ? g_pRemoteData->dwDebugDepth : -1);

	IPCLOGD(L"CreateProcessAsUserW: %ls, %ls, lpProcessAttributes: %#llx, lpThreadAttributes: %#llx, bInheritHandles: %d, dwCreationFlags: %#lx, lpCurrentDirectory: %s", lpApplicationName, lpCommandLine, (UINT64)(uintptr_t)lpProcessAttributes, (UINT64)(uintptr_t)lpThreadAttributes, bInheritHandles, dwCreationFlags, lpCurrentDirectory);

	bRet = orig_fpCreateProcessAsUserW(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags | CREATE_SUSPENDED, lpEnvironment, lpCurrentDirectory, lpStartupInfo, &ProcessInformation);
	dwLastError = GetLastError();

	IPCLOGV(L"CreateProcessAsUserW: Created.(%u) Child process id: " WPRDW, bRet, ProcessInformation.dwProcessId);

	if (lpProcessInformation) {
		CopyMemory(lpProcessInformation, &ProcessInformation, sizeof(PROCESS_INFORMATION));
	}

	IPCLOGV(L"CreateProcessAsUserW: Copied.");
	if (!bRet) goto err_orig;

	IPCLOGV(L"CreateProcessAsUserW: After jmp to err_orig.");

	// Check process name filter before injection
	if (!ShouldInjectProcess(lpApplicationName, lpCommandLine)) {
		IPCLOGD(L"CreateProcessAsUserW: Process filtered out, not injecting WINPID " WPRDW, ProcessInformation.dwProcessId);
		if (!(dwCreationFlags & CREATE_SUSPENDED)) {
			ResumeThread(ProcessInformation.hThread);
		}
		g_bCurrentlyInWinapiCall = FALSE;
		SetLastError(dwLastError);
		return 1;
	}

	IPCLOGV(L"CreateProcessAsUserW: Before InjectTargetProcess.");
	dwReturn = InjectTargetProcess(&ProcessInformation, dwCreationFlags);

	IPCLOGV(L"CreateProcessAsUserW: Injected. " WPRDW, dwReturn);

	if (g_bUseRemoteThreadInsteadOfEntryDetour) {
		if (!(dwCreationFlags & CREATE_SUSPENDED)) {
			ResumeThread(ProcessInformation.hThread);
		}
	}

	if (dwReturn != 0) goto err_inject;
	IPCLOGD(L"CreateProcessAsUserW: I've Injected WINPID " WPRDW, ProcessInformation.dwProcessId);

	g_bCurrentlyInWinapiCall = FALSE;
	return 1;

err_orig:
	IPCLOGE(L"CreateProcessAsUserW Error: " WPRDW L", %ls", bRet, FormatErrorToStr(dwLastError));
	SetLastError(dwLastError);
	g_bCurrentlyInWinapiCall = FALSE;
	return bRet;

err_inject:
	IPCLOGW(L"Injecting WINPID " WPRDW L" Error: %ls", ProcessInformation.dwProcessId, FormatErrorToStr(dwReturn));
	SetLastError(dwReturn);
	g_bCurrentlyInWinapiCall = FALSE;
	return 1;
}
