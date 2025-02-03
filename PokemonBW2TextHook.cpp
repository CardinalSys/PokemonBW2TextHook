#include "proc.c"
#include <iostream>
#include <iomanip>
#include <cctype> 
#include <vector>
#include <cwctype>
#include <locale>
#include <chrono>
#include <thread>
#include <algorithm>
#include <windows.h>

int delayms = 1000;
using namespace std::this_thread;
using namespace std::chrono;

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

void CopyToClipboard(const std::string& text) {
    if (OpenClipboard(nullptr)) {
        EmptyClipboard();

        // Convert UTF-8 to UTF-16
        int wideSize = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, nullptr, 0);
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, wideSize * sizeof(wchar_t));

        if (hMem) {
            wchar_t* pMem = static_cast<wchar_t*>(GlobalLock(hMem));
            MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, pMem, wideSize);
            GlobalUnlock(hMem);
            SetClipboardData(CF_UNICODETEXT, hMem);
        }

        CloseClipboard();
        GlobalFree(hMem);
    }
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

bool isAllowed(uint32_t cp) {
    return
        // Hiragana (U+3040-U+309F)
        (cp >= 0x3040 && cp <= 0x309F) ||
        // Katakana (U+30A0-U+30FF)
        (cp >= 0x30A0 && cp <= 0x30FF) ||
        // CJK Unified Ideographs
        (cp >= 0x4E00 && cp <= 0x9FFF && (
            // Example: Exclude rare/uncommon kanji blocks
            !(cp >= 0xE000 && cp <= 0xF8FF)  // Private Use Area (PUA)
            )) ||
        // CJK punctuation (e.g., full-width space, 「」)
        (cp >= 0x3000 && cp <= 0x303F) ||
        // Full-width punctuation (！, etc.)
        (cp >= 0xFF00 && cp <= 0xFF0F) ||
        (cp >= 0xFF1A && cp <= 0xFF1F);
}


std::string cleanString(const std::string& input) {
    std::string output;
    size_t i = 0;
    while (i < input.size()) {
        uint32_t cp = 0;
        int bytes = 0;

        // Decode UTF-8
        if ((input[i] & 0x80) == 0x00) {          // 1-byte
            cp = input[i];
            bytes = 1;
        }
        else if ((input[i] & 0xE0) == 0xC0) {   // 2-byte
            cp = ((input[i] & 0x1F) << 6) | (input[i + 1] & 0x3F);
            bytes = 2;
        }
        else if ((input[i] & 0xF0) == 0xE0) {   // 3-byte
            cp = ((input[i] & 0x0F) << 12) | ((input[i + 1] & 0x3F) << 6) | (input[i + 2] & 0x3F);
            bytes = 3;
        }
        else if ((input[i] & 0xF8) == 0xF0) {   // 4-byte
            cp = ((input[i] & 0x07) << 18) | ((input[i + 1] & 0x3F) << 12) | ((input[i + 2] & 0x3F) << 6) | (input[i + 3] & 0x3F);
            bytes = 4;
        }
        else {
            i++;
            continue;  // Skip invalid bytes
        }

        // (0xBE01 is interpreted as a line breaker in the BW2 code)
        if (cp == 0xBE01) {  
            output += '\n';
        }
        else if (isAllowed(cp)) {
            output.append(input.substr(i, bytes));
        }

        i += bytes;
    }
    return output;
}

struct Process proc;

DWORD_PTR GetBaseAddress() {
    //BYTE pattern[] = { 0xA0, 0xF4, 0x64, 0x00, 0xB1, 0x7F, 0x00, 0x00 }; //start game pattern
    BYTE pattern[] = { 0x80, 0x04, 0x00, 0x00, 0xEC, 0xD2, 0xF8, 0xB6, 0x00, 0x00, 0x00, 0x30 }; //needs more test
    char mask[] = "xx?xxxxx???x?";
    DWORD_PTR foundAddress = FindPatternSafe(
        proc.handle,
        pattern,
        mask,
        0x10000000000,
        0x3FFFFFFFFFF
    );

    if(foundAddress == 0){
        std::cout << "Pattern not found" << std::endl;
        sleep_for(milliseconds(delayms));

        foundAddress = GetBaseAddress();
    }

    return foundAddress;
}

int main(void)
{
    SetConsoleFont(L"NSimSun");
    proc = GetProcessByName("melonDS.exe");

    if (proc.pid != 0) {
        std::cout << "Process hooked" << std::endl;


        DWORD_PTR foundAddress = GetBaseAddress();

        std::cout << "Pattern found at: 0x" << std::hex << foundAddress << std::endl;
        std::string lastStr;
        std::cout << "Starting loop (Text auto-copied to clipboard)" << std::endl;
        std::cout << "Use Win+V to paste history or Ctrl+V to paste latest" << std::endl;
        while (true)
        {
            sleep_for(milliseconds(delayms));
            BYTE buffer[500];
            SIZE_T bytesRead;
            if (ReadProcessMemory(proc.handle, (LPCVOID)foundAddress, buffer, sizeof(buffer), &bytesRead)) {
                if (bytesRead % sizeof(wchar_t) != 0) {
                    std::cerr << "Error: bytesRead is not aligned to wide characters." << std::endl;
                }
                else {


                    size_t numChars = bytesRead / sizeof(wchar_t);
                    std::wstring wstr(reinterpret_cast<wchar_t*>(buffer), numChars);


                    std::string utf8str = ConvertToUTF8(wstr);

                    if (utf8str == lastStr) {
                        continue;
                    }


                    SetConsoleOutputCP(CP_UTF8);
                    lastStr = utf8str;

                    std::string cleaned = cleanString(utf8str);
                    CopyToClipboard(cleaned);
                    std::cout << "---------------------------------------" << std::endl;
                    std::cout << "Data: " << cleaned << std::endl;


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


