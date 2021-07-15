/*
* How to inject dll on Windows
* Method1: modify regedit
* Method2: using SetWindowsHook to let app load target dll
* Method3: using CreateRemoteThread to inject dll to a running process(attach)
* Method4: using CreateProcess to inject dll for the launched child process
* Method5: replace dll with the default one that will be loaded
* How to inject dll on Linux
*/
#pragma once
#include <iostream>
#include <string>
#include <filesystem>
namespace fs = std::filesystem;

#ifdef _WIN32
#include <Windows.h>
#include <tlhelp32.h> 
#else
#endif
//TODO: linux library injection

namespace dll_injector {
    class DLLInjector {
    public:
        DLLInjector(std::string dllName = "", bool globalHook = true);
        ~DLLInjector();
        bool InjectDll(const char* injectedDllName, DWORD targetProcessID = 0);
        bool InjectDll(const char* injectedDllName, const char* targetProcessName);
        bool InjectDllGlobally(const char* injectedDllName, const char* hookProc);
        void EjectDll();
        bool InjectDll2ActiveProcess(const char* injectedDllName, DWORD targetProcessID);
        bool InjectDll2ActiveProcess(const char* injectedDllName, const char* targetProcessName);
        bool CreateProcessWithDll();
    private:
        DWORD GetProcessID(const char* processName);

        HHOOK       m_hookHandle;
        HMODULE     m_injectedDLLModule;
        std::string m_injectedDLLName;
        bool        m_bGlobalHook;
        bool        m_bEjected;
        bool        m_bInjected;
    };

    namespace api {
        //processID default is 0, means dll can be injected globally
        bool InjectDll(const char* injectedDllName, DWORD targetProcessID = 0);
        bool InjectDll(const char* injectedDllName, const char* targetProcessName);
        void EjectDll();
    }
}