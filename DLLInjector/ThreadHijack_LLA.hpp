#pragma once
#ifndef MG_THREADHIJACK
#define MG_THREADHIJACK

#ifndef _WINDOWS_
#include <Windows.h>
#include <TlHelp32.h>
#endif

bool ThreadHijack_LLAInjection(HANDLE hProcess, PROCESSENTRY32W* process_entry, char dll_path[]);


#endif // !MG_THREADHIJACK