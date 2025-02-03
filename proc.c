#include <stdio.h>
#include <Windows.h>
#include <psapi.h>

struct Process {
    int pid;
    HANDLE handle;
    HMODULE hMods[1024];
    TCHAR szModName[MAX_PATH];
    const char* fullPath;
};

void GetExecutableName(const char* fullPath, char* exeName, size_t exeNameSize) {
    const char* lastSlash = strrchr(fullPath, '\\');
    if (lastSlash != NULL) {
        strncpy_s(exeName, 255,lastSlash + 1, exeNameSize - 1);
    }
    else {
        strncpy_s(exeName,255, fullPath, exeNameSize - 1);
    }
    exeName[exeNameSize - 1] = '\0';
}

struct Process GetProcessByName(const char name[]) {
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    struct Process proc = { 0, NULL, {0}, TEXT("") };

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
        return proc;
    }

    cProcesses = cbNeeded / sizeof(DWORD);

    for (DWORD i = 0; i < cProcesses; i++) {
        HANDLE handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, aProcesses[i]);

        if (!handle) {
            continue;
        }

        char path[MAX_PATH];
        DWORD pathLen = MAX_PATH;

        if (QueryFullProcessImageNameA(handle, 0, path, &pathLen)) {
            char exeName[MAX_PATH];
            proc.fullPath = path;
            GetExecutableName(path, exeName, sizeof(exeName));

            if (strcmp(name, exeName) == 0) {
                printf("Process found: %s (PID: %d)\n", name, aProcesses[i]);

                if (EnumProcessModules(handle, proc.hMods, sizeof(proc.hMods), &cbNeeded)) {
                    for (DWORD j = 0; j < (cbNeeded / sizeof(HMODULE)); j++) {
                        if (GetModuleFileNameEx(handle, proc.hMods[j], proc.szModName, sizeof(proc.szModName) / sizeof(TCHAR))) {
                            //printf("Module: %ls\n", proc.szModName);
                        }
                    }
                }

                proc.pid = aProcesses[i];
                proc.handle = handle;

                return proc;
            }
        }
        CloseHandle(handle);
    }
    return proc;
}


BOOL DataCompare(const BYTE* data, const BYTE* pattern, const char* mask) {
    for (; *mask; ++mask, ++data, ++pattern) {
        if (*mask == 'x' && *data != *pattern) {
            return FALSE;
        }
    }
    return (*mask) == NULL;
}


DWORD_PTR FindPattern(HANDLE hProcess, BYTE* pattern, char* mask, DWORD_PTR start, DWORD_PTR end) {
    SIZE_T bytesRead;
    BYTE buffer[4096];

    for (DWORD_PTR i = start; i < end; i += sizeof(buffer)) {
        ReadProcessMemory(hProcess, (LPCVOID)i, buffer, sizeof(buffer), &bytesRead);
        for (size_t j = 0; j < bytesRead; j++) {
            if (DataCompare(buffer + j, pattern, mask)) {
                return i + j;
            }
        }
    }
    return 0;
}

