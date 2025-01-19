#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <cstdlib>
#include <tuple>
#include "log.hpp"
#include "ThreadHijack_LLA.hpp"
#include "CreateRemoteThreadEx_LLA.h"

BOOL GetProcessId(const WCHAR name[], PROCESSENTRY32W* pProcessEntry) {
    HANDLE hTooltip = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    PROCESSENTRY32W process_entry = {};
    process_entry.dwSize = sizeof(PROCESSENTRY32W);
    if (!Process32FirstW(hTooltip, &process_entry)) {
        error("Could not get Process32First\n");
        CloseHandle(hTooltip);
        return false;
    }

    do {
        if (wcsncmp(process_entry.szExeFile, name, sizeof(name)) == 0) {
            memcpy_s(pProcessEntry, sizeof(PROCESSENTRY32W), &process_entry, sizeof(PROCESSENTRY32W));
            CloseHandle(hTooltip);
            return true;
        }
    } while (Process32NextW(hTooltip, &process_entry));

    CloseHandle(hTooltip);
    return false;
}

void printUsage(char* path_to_file) {
    printf(
        "usage: %s <process-name> <path-to-dll> <method>\n\n"\
        "Methods:\n"
        "\tCRTE_LLA - CreateRemoteThreadEx with LoadLibraryA\n"
        "\tTH_LLA - ThreadHijack with LoadLibraryA\n"
        , path_to_file);
}


std::tuple<WCHAR*, char*, char*> getArguments(int argc, char** argv) {
    if (argc < 4) {
        printUsage(argv[0]);
        argv[1] = (char*)"DebugMeSimple.exe";
        argv[2] = (char*)"P:\projects\DebugMeSimple\build\x64\Solver.dll";
        argv[3] = (char*)"TH_LLA";
      //  exit(1, "Wrong arguments ...");
    }

    char* process_name = argv[1];
    int process_name_wchar_size = MultiByteToWideChar(CP_ACP, 0, process_name, -1, nullptr, 0);

    if (process_name_wchar_size == 0) {
        exit(1, "MultibyteToWideChar size determination failed\n");
    }

    WCHAR* wProcessName = (WCHAR*)malloc(process_name_wchar_size);

    if (MultiByteToWideChar(CP_ACP, 0, process_name, -1, wProcessName, process_name_wchar_size) == 0) {
        exit(1, "MultiByteToWideChar failed for process_name\n");
    }

    return { wProcessName, argv[2], argv[3]};
}

int main(int argc, char** argv)
{

    auto [wProcessName, wPathToDll, method] = getArguments(argc, argv);
    PROCESSENTRY32W process_entry = {};
    
    if (!GetProcessId(wProcessName, &process_entry)) {
        exit(1, "Could not get process id!\n");
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, process_entry.th32ProcessID);

    if (!hProcess) {
        exit(1, "Could not get process\n");
    }

    info("Injecting %s into %s using %s...\n", wPathToDll, wProcessName, method);

    if (strncmp(method, "CRTE_LLA", sizeof("CRTE_LLA")) == 0) {
        if (!CreateRemoteThreadEx_LLAInjection(hProcess, wPathToDll)) {
            exit(1, "LoadLibraryAInjection Failed!\n");
        }
    }
    else if (strncmp(method, "TH_LLA", sizeof("TH_LLA")) == 0) {
        if (!ThreadHijack_LLAInjection(hProcess, &process_entry, wPathToDll)) {
            exit(1, "ThreadHijack injection Failed!\n");
        }
    }
    else {
        printUsage(argv[0]);
        exit(1, "Method not found: %s\n", method);
    }

    info("Success :)");

    CloseHandle(hProcess);

}
