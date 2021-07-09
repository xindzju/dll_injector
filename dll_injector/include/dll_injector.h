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