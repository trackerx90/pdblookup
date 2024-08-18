///////////////////////////////////////////////////////////////////////////////
//
// DebugDir.cpp 
//
// DebugDir example source code 
// 
// Author: Oleg Starodumov (www.debuginfo.com)
//
//

#include <windows.h>
#include <crtdbg.h>
#include <stdio.h>
#include <limits.h>
#include <Wininet.h>
#include <Shlwapi.h>

#pragma comment(lib,"shlwapi.lib")

// Thanks to Matt Pietrek 
#define MakePtr( cast, ptr, addValue ) (cast)( (DWORD_PTR)(ptr) + (DWORD_PTR)(addValue))

#define CV_SIGNATURE_NB10   '01BN'
#define CV_SIGNATURE_RSDS   'SDSR'

// CodeView header 
struct CV_HEADER
{
    DWORD CvSignature; // NBxx
    LONG  Offset;      // Always 0 for NB10
};

// CodeView NB10 debug information 
// (used when debug information is stored in a PDB 2.00 file) 
struct CV_INFO_PDB20
{
    CV_HEADER  Header;
    DWORD      Signature;       // seconds since 01.01.1970
    DWORD      Age;             // an always-incrementing value 
    BYTE       PdbFileName[1];  // zero terminated string with the name of the PDB file 
};

// CodeView RSDS debug information 
// (used when debug information is stored in a PDB 7.00 file) 
struct CV_INFO_PDB70
{
    DWORD      CvSignature;
    GUID       Signature;       // unique identifier 
    DWORD      Age;             // an always-incrementing value 
    BYTE       PdbFileName[1];  // zero terminated string with the name of the PDB file 
};

LPCTSTR ProcessCmdLine(int argc, TCHAR* argv[]);
BOOL CheckSectionHeaders(PIMAGE_NT_HEADERS pNtHeaders);
BOOL CheckDebugDirectory(PIMAGE_DEBUG_DIRECTORY pDebugDir, DWORD DebugDirSize);
BOOL IsPE32Plus(PIMAGE_OPTIONAL_HEADER pOptionalHeader, BOOL& bPE32Plus);
BOOL GetDebugDirectoryRVA(PIMAGE_OPTIONAL_HEADER pOptionalHeader, DWORD& DebugDirRva, DWORD& DebugDirSize);
BOOL GetFileOffsetFromRVA(PIMAGE_NT_HEADERS pNtHeaders, DWORD Rva, DWORD& FileOffset);
void DumpDebugDirectoryEntries(LPBYTE pImageBase, PIMAGE_DEBUG_DIRECTORY pDebugDir, DWORD DebugDirSize);
void DumpDebugDirectoryEntry(LPBYTE pImageBase, PIMAGE_DEBUG_DIRECTORY pDebugDir);
void DumpCodeViewDebugInfo(LPBYTE pDebugInfo, DWORD DebugInfoSize);
void DumpMiscDebugInfo(LPBYTE pDebugInfo, DWORD DebugInfoSize);
LPCTSTR DebugTypeToStr(DWORD DebugType);

typedef BOOL(WINAPI* fpSymbolServer)(
    _In_  PCTSTR params,
    _In_  PCTSTR filename,
    _In_  PVOID  id,
    _In_  DWORD  two,
    _In_  DWORD  three,
    _Out_ PTSTR  path
    );

typedef BOOL(WINAPI* fpSymbolServerByIndex)(
    _In_  PCTSTR params,
    _In_  PCTSTR filename,
    _In_  PVOID id,
    _Out_ PTSTR  path
    );

typedef BOOL(WINAPI* fpSymbolServerClose)(void);

typedef BOOL(WINAPI* fpSymbolServerPing)(
    _In_ PCTSTR pParameters
    );

typedef struct _SYMSRV_VERSION {
    unsigned short major;
    unsigned short minor;
    unsigned short build1;
    unsigned short build2;
}SYMSRV_VERSION,
* PSYMSRV_VERSION;

typedef BOOL(WINAPI* fpSymbolServerGetVersion)(
    _In_ PSYMSRV_VERSION pParameters
    );

fpSymbolServerGetVersion SymbolServerGetVersion;
fpSymbolServer SymbolServer;
fpSymbolServerByIndex SymbolServerByIndex;
fpSymbolServerClose SymbolServerClose;
fpSymbolServerPing SymbolServerPing;

_inline
char*
RtlStrcpy(char* s1, const char* s2)
{
    char* s = s1;
    while ((*s++ = *s2++) != 0)
        ;
    return (s1);
}

_inline
unsigned int
RtlStrlen(char* s)
{
    unsigned int c = 0;
    while (*s) { c++; s++; }
    return c;
}

_inline
void
RtlPathRemoveFileName(char* s)
{
    char* p = s + RtlStrlen(s);
    while (*p != '\\') p--; *p = '\0';
}

_inline
char*
RtlStrcat(char* s1, const char* s2)
{
    RtlStrcpy(&s1[RtlStrlen(s1)], s2);
    return s1;
}

char TempFile[MAX_PATH];

BOOL download_pdb(CV_INFO_PDB70* pCvInfo)
{
    BOOL Result = FALSE;
    HMODULE hSymSrv;
    SYMSRV_VERSION version;
    CHAR LocalSymbolsPath[MAX_PATH];

    CHAR outname[MAX_PATH] = { 0 };
    strcpy(outname, (char*)pCvInfo->PdbFileName);
    if (strstr(outname, "\\"))
    {
        printf(" Failed, full PDB path found, doesn't a microsoft file?\r\n");
        return FALSE;
    }

    GetModuleFileNameA(NULL, LocalSymbolsPath, MAX_PATH);
    RtlPathRemoveFileName(LocalSymbolsPath);
    RtlStrcat(LocalSymbolsPath, "\\symsrv.dll");

    if (!((hSymSrv = LoadLibraryA(LocalSymbolsPath)) &&
        (SymbolServerGetVersion = (fpSymbolServerGetVersion)GetProcAddress(hSymSrv, "SymbolServerGetVersion")) &&
        (SymbolServer = (fpSymbolServer)GetProcAddress(hSymSrv, "SymbolServer")) &&
        (SymbolServerClose = (fpSymbolServerClose)GetProcAddress(hSymSrv, "SymbolServerClose")) &&
        (SymbolServerPing = (fpSymbolServerPing)GetProcAddress(hSymSrv, "SymbolServerPing")) &&
        (SymbolServerByIndex = (fpSymbolServerByIndex)GetProcAddress(hSymSrv, "SymbolServerByIndex"))))
    {
        printf(" Failed, some problem with loading symsrv.dll and GetProcAddress\r\n");
        return FALSE;
    }

    if (SymbolServerGetVersion(&version) && (version.major < 6 && version.minor < 11))
    {
        printf(" Failed, symsrv.dll version is not supported\r\n");
        return FALSE;
    }

    RtlPathRemoveFileName(LocalSymbolsPath);
    RtlStrcat(LocalSymbolsPath, "\\pdb");
    CreateDirectory(LocalSymbolsPath, NULL);
    RtlStrcat(LocalSymbolsPath, "*http://msdl.microsoft.com/download/symbols");
    //if (!SymbolServerPing(LocalSymbolsPath))
    //{
    //    printf(" Failed, cannot ping the symbol server\r\n");
    //    return -1;
    //}

    CHAR szVerb[MAX_PATH] = { 0 };
    GUID& Guid = pCvInfo->Signature;
    sprintf(szVerb, "%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%X",
        Guid.Data1,
        Guid.Data2,
        Guid.Data3,
        Guid.Data4[0],
        Guid.Data4[1],
        Guid.Data4[2],
        Guid.Data4[3],
        Guid.Data4[4],
        Guid.Data4[5],
        Guid.Data4[6],
        Guid.Data4[7],
        pCvInfo->Age);

    //SymbolServer(NtSymbolsPath, (char*)pCvInfo->PdbFileName, &pCvInfo->Signature, pCvInfo->Age, 0, outname);


    Result = SymbolServerByIndex(LocalSymbolsPath, outname, szVerb, outname);
    if (!Result)
    {
        DWORD dwError = GetLastError();

        switch (dwError)
        {
        case ERROR_FILE_NOT_FOUND:
            // symbol not found on microsoft server
            printf("The attempt to connect to the server failed.\n");
            break;
        case ERROR_INVALID_HANDLE:
            printf("PDB had dwonloaded but not complete, try again\n");
            break;
        case ERROR_INTERNET_EXTENDED_ERROR:
            // To get more details call InternetGetLastResponseInfo() 
            printf("An extended error was returned from the server.\n");
            break;
        case ERROR_INTERNET_CANNOT_CONNECT:
            // problem with server connection
            printf("The attempt to connect to the server failed.\n");
            break;
        default:
            printf(" SymbolServerByIndex failed %d\n", dwError);
            break;
        }
    }
    else
    {
        printf(" PDB downloaded successfully.\n");
        char SaveBin[MAX_PATH];
        char exefilename[MAX_PATH];
        lstrcpy(exefilename, TempFile);
        lstrcpy(SaveBin, outname);
        PathRemoveFileSpec(SaveBin);
        PathStripPath(exefilename);
        lstrcat(SaveBin, "\\");
        lstrcat(SaveBin, exefilename);
        CopyFile(TempFile, SaveBin, FALSE);
    }

    SymbolServerClose();

    return Result;
}

typedef struct _MAPFILE_PARAM {
    HANDLE hFile;
    HANDLE hFileMap;
    LPVOID lpFileMem;
}MAPFILE_PARAM,
* PMAPFILE_PARAM;

BOOL UnmapFile(MAPFILE_PARAM& Param)
{
    if (Param.lpFileMem != 0) {
        if (!UnmapViewOfFile(Param.lpFileMem)) {
            printf("Error: Cannot unmap the file. Error code: %u \n", GetLastError());
            return FALSE;
        }
    }

    if (Param.hFileMap != NULL) {
        if (!CloseHandle(Param.hFileMap)) {
            printf("Error: Cannot close the file mapping object. Error code: %u \n", GetLastError());
            return FALSE;
        }
    }

    if ((Param.hFile != NULL) && (Param.hFile != INVALID_HANDLE_VALUE)) {
        if (!CloseHandle(Param.hFile)) {
            printf("Error: Cannot close the file. Error code: %u \n", GetLastError());
            return FALSE;
        }
    }
    return TRUE;
}

BOOL MapFile(LPCTSTR FileName, MAPFILE_PARAM& Param)
{
    Param.hFile = CreateFile(FileName, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if ((Param.hFile == INVALID_HANDLE_VALUE) || (Param.hFile == NULL)) {
        printf("Error: Cannot open the file. Error code: %u \n", GetLastError());
        return FALSE;
    }

    Param.hFileMap = CreateFileMapping(Param.hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (Param.hFileMap == NULL) {
        printf("Error: Cannot open the file mapping object. Error code: %u \n", GetLastError());
        return FALSE;
    }

    Param.lpFileMem = MapViewOfFile(Param.hFileMap, FILE_MAP_READ, 0, 0, 0);
    if (Param.lpFileMem == 0) {
        printf("Error: Cannot map the file. Error code: %u \n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

BOOL IsValidPE(PVOID lpFileMem, PVOID pOutNtHeaders)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileMem;
    if (pDosHeader == 0 || IsBadReadPtr(pDosHeader, sizeof(IMAGE_DOS_HEADER)) ||
        pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }

    PIMAGE_NT_HEADERS pNtHeaders = MakePtr(PIMAGE_NT_HEADERS, pDosHeader, pDosHeader->e_lfanew);
    if (pNtHeaders == 0 || IsBadReadPtr(pNtHeaders, sizeof(pNtHeaders->Signature)) ||
        pNtHeaders->Signature != IMAGE_NT_SIGNATURE ||
        IsBadReadPtr(&pNtHeaders->FileHeader, sizeof(IMAGE_FILE_HEADER)) ||  // Invalid header ?
        IsBadReadPtr(&pNtHeaders->OptionalHeader,
            pNtHeaders->FileHeader.SizeOfOptionalHeader)) { // Invalid size of the optional header ?
        return FALSE;
    }

    // Determine the format of the header
    // IMAGE_OPTIONAL_HEADER.Magic field contains the value that allows 
    // to distinguish between PE32 and PE32+ formats 
    if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        // PE32 
    }
    else if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        // PE32+
    }
    else
    {
        // Unknown value -> Report an error 
        return FALSE;
    }
    memcpy(pOutNtHeaders, &pNtHeaders, sizeof(PIMAGE_NT_HEADERS));
    return TRUE;
}

BOOL DoFile(LPCTSTR FileName)
{
    if (FileName == 0)
        return FALSE;

    GetTempPath(MAX_PATH, TempFile);
    lstrcat(TempFile, PathFindFileName(FileName));
    if (!CopyFile(FileName, TempFile, FALSE))
    {
        printf(" Error: cannot copy %s toTEMP (%d)\n", FileName, GetLastError());
        return FALSE;
    }

    MAPFILE_PARAM Param = { 0 };
    if (!MapFile(TempFile, Param))
        return FALSE;

    PIMAGE_NT_HEADERS pNtHeaders;
    if (!IsValidPE(Param.lpFileMem, &pNtHeaders))
        return FALSE;

    if (!CheckSectionHeaders(pNtHeaders)) {
        return FALSE;
    }

    // Look up the debug directory 
    DWORD DebugDirRva = 0;
    DWORD DebugDirSize = 0;

    if (!GetDebugDirectoryRVA(&pNtHeaders->OptionalHeader, DebugDirRva, DebugDirSize)) {
        printf("Error: File is not a PE executable.\n");
        return FALSE;
    }

    if ((DebugDirRva == 0) || (DebugDirSize == 0)) {
        printf("Debug directory not found.\n");
        return FALSE;
    }

    DWORD DebugDirOffset = 0;
    if (!GetFileOffsetFromRVA(pNtHeaders, DebugDirRva, DebugDirOffset)) {
        printf("Debug directory not found.\n");
        return FALSE;
    }

    PIMAGE_DEBUG_DIRECTORY pDebugDir = MakePtr(PIMAGE_DEBUG_DIRECTORY, Param.lpFileMem, DebugDirOffset);
    if (!CheckDebugDirectory(pDebugDir, DebugDirSize)) {
        printf("Error: Debug directory is not valid.\n");
        return FALSE;
    }

    // Display information about every entry in the debug directory 
    DumpDebugDirectoryEntries((LPBYTE)Param.lpFileMem, pDebugDir, DebugDirSize);

    DeleteFile(TempFile);
    return TRUE;
}

void DoDir(LPCTSTR ScanPath)
{
    HANDLE hFind;
    WIN32_FIND_DATA w32Data;
    char FindPath[MAX_PATH];
    char FilePath[MAX_PATH];

    if (strlen(ScanPath) - 1 > MAX_PATH - 1)
        return;

    strcpy((LPTSTR)FindPath, ScanPath);
    strcat((LPTSTR)FindPath, "*");
    hFind = FindFirstFile((LPTSTR)FindPath, &w32Data);
    do
    {
        if (strcmp(w32Data.cFileName, ".") && strcmp(w32Data.cFileName, ".."))
        {
            memset((LPTSTR)FilePath, 0, sizeof(FilePath));
            strcpy((LPTSTR)FilePath, ScanPath);
            strcat((LPTSTR)FilePath, w32Data.cFileName);
            if ((w32Data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY)
            {
                strcat((LPTSTR)FilePath, "\\");
                DoDir((LPTSTR)FilePath);
            }
            else
            {
                DoFile((LPTSTR)FilePath);
            }
        }
    } while (FindNextFile(hFind, &w32Data));
    FindClose(hFind);

    return;
}

int main(int argc, TCHAR* argv[])
{
    LPCTSTR FileName = ProcessCmdLine(argc, argv);
    if (FileName == 0)
        return 0;

    DWORD dwAttr = GetFileAttributes(FileName);
    if (dwAttr == INVALID_FILE_ATTRIBUTES)
        return 0;

    if ((dwAttr & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY)
    {
        char dir[MAX_PATH];
        strcpy(dir, FileName);
        strcat(dir, "\\");
        DoDir(dir);
    }
    else
    {
        DoFile(FileName);
    }


    getchar();

    return 0;
}

// 
// Check whether the specified IMAGE_OPTIONAL_HEADER belongs to 
// a PE32 or PE32+ file format 
// 
// Return value: "true" if succeeded (bPE32Plus contains "true" if the file 
//  format is PE32+, and "false" if the file format is PE32), 
//  "false" if failed 
// 
BOOL IsPE32Plus(PIMAGE_OPTIONAL_HEADER pOptionalHeader, BOOL& bPE32Plus)
{
    // Note: The function does not check the header for validity. 
    // It assumes that the caller has performed all the necessary checks. 

    // IMAGE_OPTIONAL_HEADER.Magic field contains the value that allows 
    // to distinguish between PE32 and PE32+ formats 

    if (pOptionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        bPE32Plus = FALSE; // PE32
    else if (pOptionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        bPE32Plus = TRUE; // PE32+ or 64-bit image
    else
    {
        bPE32Plus = FALSE; // Unknown value -> Report an error 
        return FALSE;
    }

    return TRUE;
}


// 
// Process command line and display usage information, if necessary 
// 
// Return value: If command line parameters are correct, the function 
//   returns a pointer to the file name specified by the user. 
//   If command line parameters are incorrect, the function returns null. 
// 
LPCTSTR ProcessCmdLine(int argc, TCHAR* argv[])
{
    if (argc < 2)
    {
        printf("Usage: %s FileName\n", argv[0]);
        return 0;
    }
    return argv[1];
}

// 
// Lookup the section headers and check whether they are valid 
// 
// Return value: "true" if the headers are valid, "false" otherwise 
// 
BOOL CheckSectionHeaders(PIMAGE_NT_HEADERS pNtHeaders)
{
    if (pNtHeaders == 0)
        return FALSE;

    PIMAGE_SECTION_HEADER pSectionHeaders = IMAGE_FIRST_SECTION(pNtHeaders);
    if (IsBadReadPtr(pSectionHeaders, pNtHeaders->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)))
        return FALSE;  // Invalid header

    return TRUE;
}

// 
// Checks whether the debug directory is valid 
// 
// Return value: "true" if the debug directory is valid, "false" if it is not 
// 
BOOL CheckDebugDirectory(PIMAGE_DEBUG_DIRECTORY pDebugDir, DWORD DebugDirSize)
{
    if ((pDebugDir == 0) || (DebugDirSize == 0))
        return FALSE;

    if (IsBadReadPtr(pDebugDir, DebugDirSize))
        return FALSE; // Invalid debug directory 

    if (DebugDirSize < sizeof(IMAGE_DEBUG_DIRECTORY))
        return FALSE; // Invalid size of the debug directory

    return TRUE;
}

// 
// Returns (in [out] parameters) the RVA and size of the debug directory, 
// using the information in IMAGE_OPTIONAL_HEADER.DebugDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG]
// 
// Return value: "true" if succeeded, "false" if failed
// 
BOOL GetDebugDirectoryRVA(PIMAGE_OPTIONAL_HEADER pOptionalHeader, DWORD& DebugDirRva, DWORD& DebugDirSize)
{
    // Check parameters 
    if (pOptionalHeader == 0)
        return FALSE;

    // Determine the format of the PE executable 
    BOOL bPE32Plus = FALSE;
    if (!IsPE32Plus(pOptionalHeader, bPE32Plus))
        // Probably invalid IMAGE_OPTIONAL_HEADER.Magic
        return FALSE;

    // Obtain the debug directory RVA and size 
    if (bPE32Plus)
    {
        PIMAGE_OPTIONAL_HEADER64 pOptionalHeader64 = (PIMAGE_OPTIONAL_HEADER64)pOptionalHeader;
        DebugDirRva = pOptionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
        DebugDirSize = pOptionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
    }
    else
    {
        PIMAGE_OPTIONAL_HEADER32 pOptionalHeader32 = (PIMAGE_OPTIONAL_HEADER32)pOptionalHeader;
        DebugDirRva = pOptionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
        DebugDirSize = pOptionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
    }

    if ((DebugDirRva == 0) && (DebugDirSize == 0))
        // No debug directory in the executable -> no debug information 
        return TRUE;
    else if ((DebugDirRva == 0) || (DebugDirSize == 0))
        // Inconsistent data in the data directory 
        return FALSE;

    return TRUE;
}

// 
// The function walks through the section headers, finds out the section 
// the given RVA belongs to, and uses the section header to determine 
// the file offset that corresponds to the given RVA 
// 
// Return value: "true" if succeeded, "false" if failed 
// 
BOOL GetFileOffsetFromRVA(PIMAGE_NT_HEADERS pNtHeaders, DWORD Rva, DWORD& FileOffset)
{
    // Check parameters 
    if (pNtHeaders == 0)
        return FALSE;

    // Look up the section the RVA belongs to 
    BOOL bFound = false;
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++)
    {
        DWORD SectionSize = pSectionHeader->Misc.VirtualSize;
        if (SectionSize == 0) // compensate for Watcom linker strangeness, according to Matt Pietrek 
            pSectionHeader->SizeOfRawData;

        if ((Rva >= pSectionHeader->VirtualAddress) &&
            (Rva < pSectionHeader->VirtualAddress + SectionSize))
        {
            // Yes, the RVA belongs to this section 
            bFound = true;
            break;
        }
    }

    if (!bFound)
    {
        // Section not found 
        return FALSE;
    }

    // Look up the file offset using the section header 
    INT Diff = (INT)(pSectionHeader->VirtualAddress - pSectionHeader->PointerToRawData);
    FileOffset = Rva - Diff;

    return TRUE;
}

// 
// Walk through each entry in the debug directory and display information about it 
// 
void DumpDebugDirectoryEntries(LPBYTE pImageBase, PIMAGE_DEBUG_DIRECTORY pDebugDir, DWORD DebugDirSize)
{
    if (!CheckDebugDirectory(pDebugDir, DebugDirSize) || pImageBase == 0)
        return;

    // Determine the number of entries in the debug directory 
    int NumEntries = DebugDirSize / sizeof(IMAGE_DEBUG_DIRECTORY);
    if (NumEntries == 0)
        return;

    printf("Number of entries in debug directory: %d \n", NumEntries);

    // Display information about every entry 
    for (int i = 1; i <= NumEntries; i++, pDebugDir++)
    {
        printf("\nDebug directory entry %d: \n", i);
        DumpDebugDirectoryEntry(pImageBase, pDebugDir);
    }
}

// 
// Display information about debug directory entry 
// 
void DumpDebugDirectoryEntry(LPBYTE pImageBase, PIMAGE_DEBUG_DIRECTORY pDebugDir)
{
    // Check parameters 
    if (pDebugDir == 0 || pImageBase == 0)
        return;

    // Display information about the entry 
    if (pDebugDir->Type != IMAGE_DEBUG_TYPE_UNKNOWN)
    {
        printf("Type: %u ( %s ) \n", pDebugDir->Type, DebugTypeToStr(pDebugDir->Type));
        printf("TimeStamp: %08x  Characteristics: %x  MajorVer: %u  MinorVer: %u \n",
            pDebugDir->TimeDateStamp, pDebugDir->Characteristics, pDebugDir->MajorVersion, pDebugDir->MinorVersion);
        printf("Size: %u  RVA: %08x  FileOffset: %08x  \n", pDebugDir->SizeOfData,
            pDebugDir->AddressOfRawData, pDebugDir->PointerToRawData);
    }
    else
    {
        printf("Type: Unknown.\n");
    }

    // Display additional information for some interesting debug information types 
    LPBYTE pDebugInfo = pImageBase + pDebugDir->PointerToRawData;
    if (pDebugDir->Type == IMAGE_DEBUG_TYPE_CODEVIEW)
    {
        DumpCodeViewDebugInfo(pDebugInfo, pDebugDir->SizeOfData);
    }
    else if (pDebugDir->Type == IMAGE_DEBUG_TYPE_MISC)
    {
        DumpMiscDebugInfo(pDebugInfo, pDebugDir->SizeOfData);
    }
}

// 
// Display information about CodeView debug information block 
// 
void DumpCodeViewDebugInfo(LPBYTE pDebugInfo, DWORD DebugInfoSize)
{
    // Check parameters 
    if ((pDebugInfo == 0) || (DebugInfoSize == 0))
        return;

    if (IsBadReadPtr(pDebugInfo, DebugInfoSize))
        return;

    if (DebugInfoSize < sizeof(DWORD)) // size of the signature 
        return;

    // Determine the format of the information and display it accordingly 
    DWORD CvSignature = *(DWORD*)pDebugInfo;
    if (CvSignature == CV_SIGNATURE_NB10)
    {
        // NB10 -> PDB 2.00 
        CV_INFO_PDB20* pCvInfo = (CV_INFO_PDB20*)pDebugInfo;
        if (IsBadReadPtr(pDebugInfo, sizeof(CV_INFO_PDB20)))
            return;

        if (IsBadStringPtrA((CHAR*)pCvInfo->PdbFileName, UINT_MAX))
            return;

        printf("CodeView format: NB10 \n");
        printf("Signature: %08x  Age: %u  \n", pCvInfo->Signature, pCvInfo->Age);
        printf("PDB File: %s \n", pCvInfo->PdbFileName);

    }
    else if (CvSignature == CV_SIGNATURE_RSDS)
    {
        // RSDS -> PDB 7.00 
        CV_INFO_PDB70* pCvInfo = (CV_INFO_PDB70*)pDebugInfo;
        if (IsBadReadPtr(pDebugInfo, sizeof(CV_INFO_PDB70)))
            return;

        if (IsBadStringPtrA((CHAR*)pCvInfo->PdbFileName, UINT_MAX))
            return;

        printf("CodeView format: RSDS \n");
        printf("Signature: {%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x} \n",
            pCvInfo->Signature.Data1,
            pCvInfo->Signature.Data2,
            pCvInfo->Signature.Data3,
            pCvInfo->Signature.Data4[0],
            pCvInfo->Signature.Data4[1],
            pCvInfo->Signature.Data4[2],
            pCvInfo->Signature.Data4[3],
            pCvInfo->Signature.Data4[4],
            pCvInfo->Signature.Data4[5],
            pCvInfo->Signature.Data4[6],
            pCvInfo->Signature.Data4[7]);
        printf("Age: %u  \n", pCvInfo->Age);
        printf("PdbFile: %s \n", pCvInfo->PdbFileName);
        download_pdb(pCvInfo);
    }
    else
    {
        // Other CodeView format 
        CHAR* pSig = (CHAR*)&CvSignature;
        printf("CodeView signature: %c%c%c%c \n", pSig[0], pSig[1], pSig[2], pSig[3]);
        if ((pSig[0] == 'N') && (pSig[1] == 'B')) // One of NBxx formats 
        {
            CV_HEADER* pCvHeader = (CV_HEADER*)pDebugInfo;
            printf("CodeView information offset: %08x\n", pCvHeader->Offset);
        }
    }
}

// 
// Display information about Misc debug information block 
// 
void DumpMiscDebugInfo(LPBYTE pDebugInfo, DWORD DebugInfoSize)
{
    // Check parameters 
    if ((pDebugInfo == 0) || (DebugInfoSize == 0))
        return;

    if (IsBadReadPtr(pDebugInfo, DebugInfoSize))
        return;

    if (DebugInfoSize < sizeof(IMAGE_DEBUG_MISC))
        return;

    // Display information 
    PIMAGE_DEBUG_MISC pMiscInfo = (PIMAGE_DEBUG_MISC)pDebugInfo;
    printf("Data type: %u  Length: %u  Format: %s \n",
        pMiscInfo->DataType,
        pMiscInfo->Length,
        pMiscInfo->Unicode ? "Unicode" : "ANSI");

    if (pMiscInfo->DataType == IMAGE_DEBUG_MISC_EXENAME)
    {
        // Yes, it should refer to a DBG file 
        if (pMiscInfo->Unicode)
        {
            if (!IsBadStringPtrW((WCHAR*)pMiscInfo->Data, UINT_MAX))
                wprintf(L"File: %s \n", (WCHAR*)pMiscInfo->Data);
        }
        else // ANSI 
        {
            if (!IsBadStringPtrA((CHAR*)pMiscInfo->Data, UINT_MAX))
                printf("File: %s \n", (CHAR*)pMiscInfo->Data);
        }
    }
}

LPCTSTR DebugTypeToStr(DWORD DebugType)
{
    switch (DebugType)
    {
    case IMAGE_DEBUG_TYPE_UNKNOWN:
        return "Unknown";
        break;

    case IMAGE_DEBUG_TYPE_COFF:
        return "COFF";
        break;

    case IMAGE_DEBUG_TYPE_CODEVIEW:
        return "CodeView";
        break;

    case IMAGE_DEBUG_TYPE_FPO:
        return "FPO";
        break;

    case IMAGE_DEBUG_TYPE_MISC:
        return "MISC";
        break;

    case IMAGE_DEBUG_TYPE_EXCEPTION:
        return "Exception";
        break;

    case IMAGE_DEBUG_TYPE_FIXUP:
        return "Fixup";
        break;

    case IMAGE_DEBUG_TYPE_OMAP_TO_SRC:
        return "OMAP-to-SRC";
        break;

    case IMAGE_DEBUG_TYPE_OMAP_FROM_SRC:
        return "OMAP-from-SRC";
        break;

    case IMAGE_DEBUG_TYPE_BORLAND:
        return "Borland";
        break;

    default:
        return "Unknown";
        break;
    }

    return "Unknown";
}

