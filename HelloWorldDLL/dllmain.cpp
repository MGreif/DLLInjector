// dllmain.cpp : Defines the entry point for the DLL application.
#include <stdio.h>
#include <Windows.h>

void PopBox(const char caption[], const char text[]) {
    MessageBoxA(NULL, text, caption, MB_OK);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: {
        char out[64] = { 0x0 };
        sprintf_s(out, "ProcessID: %lu", GetCurrentProcessId());
        PopBox("Process Attach", out);
    }
    case DLL_THREAD_ATTACH: {
        char out[64] = { 0x0 };
        sprintf_s(out, "ThreadID: %lu", GetCurrentThreadId());
        PopBox("Process Attach", out);
    }
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

