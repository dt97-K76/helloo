#include <Windows.h>
#include <iostream>
#include <string>
#include <filesystem>

using namespace std;

DWORD RvaToOffset(DWORD rva, PIMAGE_NT_HEADERS ntHeaders, PIMAGE_SECTION_HEADER sectionHeaders, int numberOfSections) {
    for (int i = 0; i < numberOfSections; i++) {
        DWORD sectionStartRVA = sectionHeaders[i].VirtualAddress;
        DWORD sectionEndRVA = sectionStartRVA + sectionHeaders[i].Misc.VirtualSize;
        if (rva >= sectionStartRVA && rva < sectionEndRVA) {
            DWORD delta = rva - sectionStartRVA;
            return sectionHeaders[i].PointerToRawData + delta;
        }
    }
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        cerr << "Usage: <program> <path_to_dll>" << endl;
        return 1;
    }

    string dllPath = argv[1];
    filesystem::path dllFsPath(dllPath);
    string dllName = dllFsPath.stem().string();  // Tên DLL không có đuôi .dll

    // Mở file DLL
    HANDLE hFile = CreateFileA(dllPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        cerr << "Failed to open file." << endl;
        return 1;
    }

    HANDLE hMapping = CreateFileMappingA(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMapping) {
        cerr << "Failed to create file mapping." << endl;
        CloseHandle(hFile);
        return 1;
    }

    LPVOID base = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!base) {
        cerr << "Failed to map view of file." << endl;
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    // Đọc header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        cerr << "Invalid DOS header." << endl;
        return 1;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)base + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        cerr << "Invalid NT header." << endl;
        return 1;
    }

    PIMAGE_SECTION_HEADER sectionHeaders = IMAGE_FIRST_SECTION(ntHeaders);
    int numberOfSections = ntHeaders->FileHeader.NumberOfSections;

    DWORD exportRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportRVA == 0) {
        cerr << "No export directory." << endl;
        return 1;
    }

    DWORD exportOffset = RvaToOffset(exportRVA, ntHeaders, sectionHeaders, numberOfSections);
    if (exportOffset == 0) {
        cerr << "Failed to convert export RVA to file offset." << endl;
        return 1;
    }

    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)base + exportOffset);

    DWORD namesOffset = RvaToOffset(exportDir->AddressOfNames, ntHeaders, sectionHeaders, numberOfSections);
    DWORD ordinalsOffset = RvaToOffset(exportDir->AddressOfNameOrdinals, ntHeaders, sectionHeaders, numberOfSections);
    DWORD funcsOffset = RvaToOffset(exportDir->AddressOfFunctions, ntHeaders, sectionHeaders, numberOfSections);

    if (!namesOffset || !ordinalsOffset || !funcsOffset) {
        cerr << "Failed to resolve export table offsets." << endl;
        return 1;
    }

    DWORD* nameRVAs = (DWORD*)((BYTE*)base + namesOffset);
    WORD* nameOrdinals = (WORD*)((BYTE*)base + ordinalsOffset);
    DWORD* functionRVAs = (DWORD*)((BYTE*)base + funcsOffset);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        DWORD nameRVA = nameRVAs[i];
        WORD ordinalIndex = nameOrdinals[i];
        DWORD funcOrdinal = exportDir->Base + ordinalIndex;

        DWORD nameOffset = RvaToOffset(nameRVA, ntHeaders, sectionHeaders, numberOfSections);
        if (nameOffset == 0) continue;

        char* functionName = (char*)base + nameOffset;
        cout << "#pragma comment(linker, \"/EXPORT:" << functionName << "=" << dllName << "." << functionName << "@" << funcOrdinal << "\")" << endl;
    }

    // Dọn dẹp
    UnmapViewOfFile(base);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return 0;
}
