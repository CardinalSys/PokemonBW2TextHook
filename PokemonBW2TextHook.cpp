#include "proc.c"
#include <iostream>
#include <iomanip>
#include <cctype> 
#include <vector>
#include <cwctype>
#include <locale> 

DWORD_PTR FindPatternSafe(HANDLE hProcess, BYTE* pattern, char* mask, DWORD_PTR start, DWORD_PTR end) { //optimize this when bored
    DWORD_PTR current = start;
    MEMORY_BASIC_INFORMATION mbi;

    while (current < end && VirtualQueryEx(hProcess, (LPCVOID)current, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
            DWORD_PTR regionStart = (DWORD_PTR)mbi.BaseAddress;
            DWORD_PTR regionEnd = regionStart + mbi.RegionSize;
            DWORD_PTR result = FindPattern(hProcess, pattern, mask, regionStart, regionEnd);
            if (result != 0) return result;
        }
        current += mbi.RegionSize;
    }
    return 0;
}

void SetConsoleFont(const std::wstring& fontName) {
    HKEY hKey;
    LPCWSTR subKey = L"Console"; 

    LONG status = RegOpenKeyExW(HKEY_CURRENT_USER, subKey, 0, KEY_SET_VALUE, &hKey);

    if (status == ERROR_FILE_NOT_FOUND) {
        status = RegCreateKeyW(HKEY_CURRENT_USER, subKey, &hKey);
    }

    if (status == ERROR_SUCCESS) {

        status = RegSetValueExW(hKey, L"FaceName", 0, REG_SZ,
            (const BYTE*)fontName.c_str(),
            (fontName.size() + 1) * sizeof(wchar_t));

        RegCloseKey(hKey);

        if (status == ERROR_SUCCESS) {
            std::wcout << L"Console font set to: " << fontName << std::endl;
        }
        else {
            std::wcerr << L"Failed to set font. Error: " << status << std::endl;
        }
    }
    else {
        std::wcerr << L"Failed to open/create registry key. Error: " << status << std::endl;
    }
}


std::string ConvertToUTF8(const std::wstring& wstr) { //Don't ask me how is this working
    if (wstr.empty())
        return std::string();

    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0,
        wstr.c_str(), (int)wstr.size(),
        NULL, 0, NULL, NULL);
    std::string utf8str(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0,
        wstr.c_str(), (int)wstr.size(),
        &utf8str[0], sizeNeeded, NULL, NULL);
    return utf8str;
}

int main(void)
{
    SetConsoleFont(L"NSimSun");
    struct Process proc = GetProcessByName("melonDS.exe");

    if (proc.pid != 0) {
        std::cout << "Process hooked" << std::endl;
        BYTE pattern[] = { 0xA0, 0xF4, 0x64, 0x00, 0xB1, 0x7F, 0x00, 0x00 };
        //BYTE pattern[] = { 0x00, 0x00, 0x7F, 0xB1, 0x00, 0x64, 0xF4, 0xA0 };

        char mask[] = "xxxxxxxx";

        MODULEINFO modInfo;
        GetModuleInformation(proc.handle, (HMODULE)proc.hMods[0], &modInfo, sizeof(modInfo));

        DWORD_PTR foundAddress = FindPatternSafe(
            proc.handle,        
            pattern,            
            mask,
            0x20000000000,
            0x3FFFFFFFFFF
        );

        if (foundAddress) {
            std::cout << "Pattern found at: 0x" << std::hex << foundAddress << std::endl;

            BYTE buffer[150];
            SIZE_T bytesRead;
            if (ReadProcessMemory(proc.handle, (LPCVOID)foundAddress, buffer, sizeof(buffer), &bytesRead)) {
                if (bytesRead % sizeof(wchar_t) != 0) {
                    std::cerr << "Error: bytesRead is not aligned to wide characters." << std::endl;
                }
                else {
                    size_t numChars = bytesRead / sizeof(wchar_t);
                    std::wstring wstr(reinterpret_cast<wchar_t*>(buffer), numChars);


                    std::string utf8str = ConvertToUTF8(wstr);

                    SetConsoleOutputCP(CP_UTF8);

                    std::cout << "Data: " << utf8str << std::endl;
                }
            }
            else {
                std::cerr << "ReadProcessMemory failed. Error: " << GetLastError() << std::endl;
            }
        }
    }
    else {
        std::cout << "Process not found" << std::endl;
    }

    return 0;
}


