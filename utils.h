#ifndef COMMON_H
#define COMMON_H

#include <windows.h>
#include <sddl.h>

// --- DFR Declarations ---
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT UINT   WINAPI KERNEL32$GetSystemDirectoryA(LPSTR, UINT);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$FindFirstFileA(LPCSTR, LPWIN32_FIND_DATA);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$FindNextFileA(HANDLE, LPWIN32_FIND_DATA);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$FindClose(HANDLE);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetEnvironmentVariableA(LPCSTR, LPSTR, DWORD);

DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$ConvertSidToStringSidA(PSID, LPSTR*);

DECLSPEC_IMPORT void* WINAPI MSVCRT$malloc(size_t);
DECLSPEC_IMPORT void   WINAPI MSVCRT$free(void*);
DECLSPEC_IMPORT void* WINAPI MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT size_t WINAPI MSVCRT$strlen(const char*);
DECLSPEC_IMPORT int    WINAPI MSVCRT$strcmp(const char*, const char*);
DECLSPEC_IMPORT int    WINAPI MSVCRT$_snprintf(char*, size_t, const char*, ...);
DECLSPEC_IMPORT int    WINAPI MSVCRT$_vsnprintf(char*, size_t, const char*, va_list);

// --- Macros ---
#define malloc    MSVCRT$malloc
#define free      MSVCRT$free
#define memcpy    MSVCRT$memcpy
#define strlen    MSVCRT$strlen
#define strcmp    MSVCRT$strcmp
#define snprintf  MSVCRT$_snprintf

// --- Shared Utility Functions ---
// Use 'static inline' so the compiler can embed these without multiple definition errors
static inline void reverseBytes(char* array, int len) {
    for (int i = 0; i < len / 2; i++) {
        char temp = array[i];
        array[i] = array[len - 1 - i];
        array[len - 1 - i] = temp;
    }
}

static inline int IndexOfBytes(char* source, int sourceLen, char* pattern, int patternLen) {
    if (!source || !pattern || patternLen == 0 || sourceLen < patternLen) return -1;
    for (int i = 0; i <= sourceLen - patternLen; i++) {
        int found = 1;
        for (int j = 0; j < patternLen; j++) {
            if (source[i + j] != pattern[j]) { found = 0; break; }
        }
        if (found) return i;
    }
    return -1;
}

#endif