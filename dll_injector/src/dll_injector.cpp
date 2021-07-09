#include "dll_injector.h"

namespace dll_injector {
    DLLInjector::DLLInjector(std::string dllName, bool globalHook)
        : m_injectedDLLName(dllName),
        m_bGlobalHook(globalHook),
        m_bInjected(false),
        m_bEjected(false){
        if (!dllName.empty()) {
            m_injectedDLLModule = LoadLibrary(dllName.c_str());
            m_hookHandle = nullptr;
        }
    }

    DLLInjector::~DLLInjector() {
        if (!m_bEjected)
            EjectDll();
    }

    bool DLLInjector::InjectDll(const char* injectedDllName, DWORD targetProcessID) {
        std::cout << "\n\nInject dll by using SetWindowsHook function" << std::endl;
        bool res = true;
        m_injectedDLLName = injectedDllName;
        m_injectedDLLModule = LoadLibrary(injectedDllName); //gpu_profiler.exe will enterl dllmain DLL_PROCESS_ATTACH
        if (m_injectedDLLModule) {
            //get function address
            HOOKPROC funcAddress = HOOKPROC(GetProcAddress(m_injectedDLLModule, "GPCHookEntry")); 
            if (!funcAddress) {
                std::cout << "Get GPCHookEntry address failed" << std::endl;
                res = false;
            }
            else {
                //set hook in the hook chain, system check which type of hook is enabled
                m_hookHandle = SetWindowsHookExW(WH_CBT, funcAddress, m_injectedDLLModule, targetProcessID);
                if (!m_hookHandle) {
                    std::cout << "SetWindowsHook failed" << std::endl;
                    res = false;
                }
            }
        }
        else {
            std::cout << "Load dll failed: " << injectedDllName << std::endl;
            res = false;
        }

        if (res) {
            std::cout << "Inject dll successfully: " << m_injectedDLLName << std::endl;
            m_bInjected = true;
        }
        else
            std::cout << "Inject dll failed: " << m_injectedDLLName << std::endl;

        return res;
    }

    bool DLLInjector::InjectDllGlobally(const char* injectedDllName, const char* hookProc) {
        bool res = true;
        m_injectedDLLName = injectedDllName;
        m_injectedDLLModule = LoadLibrary(injectedDllName); //gpu_profiler.exe will enterl dllmain DLL_PROCESS_ATTACH
        if (m_injectedDLLModule) {
            //get function address
            HOOKPROC funcAddress = HOOKPROC(GetProcAddress(m_injectedDLLModule, hookProc));
            if (!funcAddress) {
                std::cout << "Get hookProc address failed" << std::endl;
                res = false;
            }
            else {
                //set hook in the hook chain, system check which type of hook is enabled
                m_hookHandle = SetWindowsHookExW(WH_CBT, funcAddress, m_injectedDLLModule, 0);
                if (!m_hookHandle) {
                    std::cout << "SetWindowsHook failed" << std::endl;
                    res = false;
                }
            }
        }
        else {
            std::cout << "Load dll failed: " << injectedDllName << std::endl;
            res = false;
        }

        if (res)
            std::cout << "Dll global injection succeed: " << m_injectedDLLName << std::endl;
        else
            std::cout << "Dll global injection failed: " << m_injectedDLLName << std::endl;

        return res;
    }

    bool DLLInjector::InjectDll(const char* injectedDllName, const char* targetProcessName) {
#ifdef _WIN32
        std::cout << "Inject dll by using the CreateRemoteThread function" << std::endl;
        m_injectedDLLName = injectedDllName;
        DWORD targetProcessID = GetProcessID(targetProcessName);
        //reference: https://www.apriorit.com/dev-blog/679-windows-dll-injection-for-api-hooks
        //get process handle
        HANDLE targetProcessHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, targetProcessID);

        if (targetProcessHandle) {
            //allocate memory in the target process in order to pass the dll path
            fs::path injectedDllPath = fs::current_path() / injectedDllName;
            LPSTR remoteBufferForDllPath = LPSTR(VirtualAllocEx(targetProcessHandle, NULL, injectedDllPath.string().size(), MEM_COMMIT, PAGE_READWRITE));

            //place the dll path into the address space of our target process
            WriteProcessMemory(targetProcessHandle, remoteBufferForDllPath, injectedDllPath.string().c_str(), injectedDllPath.string().size(), NULL);

            // Get the real address of LoadLibrary in Kernel32.dll
            PTHREAD_START_ROUTINE loadLibraryFuncAddress = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("Kernel32"), "LoadLibrary");

            // Create remote thread that calls LoadLibrary
            HANDLE remoteThreadHandle = CreateRemoteThread(targetProcessHandle, NULL, 0, loadLibraryFuncAddress, remoteBufferForDllPath, 0, NULL);

            //free memory allocated in the target process
            VirtualFreeEx(remoteThreadHandle, remoteBufferForDllPath, injectedDllPath.string().size(), MEM_RELEASE);

            std::cout << "Inject dll successfully" << std::endl;
        }
        else {
            std::cout << "Inject dll failed" << std::endl;
            return false;
        }
        return true;
#else
#endif
    }

    void DLLInjector::EjectDll() {
        UnhookWindowsHookEx(m_hookHandle);
        if (m_injectedDLLModule) {
            FreeLibrary(m_injectedDLLModule); ////gpu_profiler.exe will enterl dllmain DLL_PROCESS_DETACH
        }
        m_bEjected = true;
        std::cout << "Ejected dll successfully: " << m_injectedDLLName << std::endl;
    }

    DWORD DLLInjector::GetProcessID(const char* processName) {
        //copied from https://en.ciholas.fr/get-process-id-pid-from-process-name-string-c-windows-api/
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //all processes

        PROCESSENTRY32 entry; //current process
        entry.dwSize = sizeof entry;

        if (!Process32First(snap, &entry)) { //start with the first in snapshot
            return 0;
        }

        do {
            if (entry.szExeFile == processName) {
                std::cout << "process name: " << processName << " process id: " << entry.th32ProcessID << std::endl;
                return entry.th32ProcessID; //name matches; add to list
            }
        } while (Process32Next(snap, &entry)); //keep going until end of snapshot

        return 0;
    }

    namespace api {
        HHOOK s_hookHandle;

        DWORD GetProcessID(const char* processName) {
            //copied from https://en.ciholas.fr/get-process-id-pid-from-process-name-string-c-windows-api/
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //all processes

            PROCESSENTRY32 entry; //current process
            entry.dwSize = sizeof entry;

            if (!Process32First(snap, &entry)) { //start with the first in snapshot
                return 0;
            }

            do {
                if (entry.szExeFile == processName) {
                    std::cout << "process name: " << processName << " process id: " << entry.th32ProcessID << std::endl;
                    return entry.th32ProcessID; //name matches; add to list
                }
            } while (Process32Next(snap, &entry)); //keep going until end of snapshot

            return 0;
        }

        bool InjectDll(const char* injectedDllName, DWORD targetProcessID) {
            std::cout << "Inject dll by using SetWindowsHook function" << std::endl;
            HMODULE injectedDLL = LoadLibrary(injectedDllName);
            if (injectedDLL) {
                //get function address
                HOOKPROC functionAddress = HOOKPROC(GetProcAddress(injectedDLL, "CBTProc")); //how to set all the hook functions?
                //set hook in the hook chain, system check which type of hook is enabled
                s_hookHandle = SetWindowsHookExW(WH_CBT, functionAddress, injectedDLL, targetProcessID);
                std::cout << "Inject dll successfully" << std::endl;
            }
            else {
                std::cout << "Inject dll failed" << std::endl;
                return false;
            }

            return true;
        }

        bool InjectDll(const char* injectedDllName, const char* targetProcessName) {
            std::cout << "Inject dll by using the CreateRemoteThread function" << std::endl;
            DWORD targetProcessID = GetProcessID(targetProcessName);
            //reference: https://www.apriorit.com/dev-blog/679-windows-dll-injection-for-api-hooks
            //get process handle
            HANDLE targetProcessHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, targetProcessID);

            if (targetProcessHandle) {
                //allocate memory in the target process in order to pass the dll path
                fs::path injectedDllPath = fs::current_path() / injectedDllName;
                LPSTR remoteBufferForDllPath = LPSTR(VirtualAllocEx(targetProcessHandle, NULL, injectedDllPath.string().size(), MEM_COMMIT, PAGE_READWRITE));

                //place the dll path into the address space of our target process
                WriteProcessMemory(targetProcessHandle, remoteBufferForDllPath, injectedDllPath.string().c_str(), injectedDllPath.string().size(), NULL);

                // Get the real address of LoadLibrary in Kernel32.dll
                PTHREAD_START_ROUTINE loadLibraryFuncAddress = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("Kernel32"), "LoadLibrary");

                // Create remote thread that calls LoadLibrary
                HANDLE remoteThreadHandle = CreateRemoteThread(targetProcessHandle, NULL, 0, loadLibraryFuncAddress, remoteBufferForDllPath, 0, NULL);

                //free memory allocated in the target process
                VirtualFreeEx(remoteThreadHandle, remoteBufferForDllPath, injectedDllPath.string().size(), MEM_RELEASE);

                std::cout << "Inject dll successfully" << std::endl;
            }
            else {
                std::cout << "Inject dll failed" << std::endl;
                return false;
            }

            return true;
        }

        void EjectDll() {
            UnhookWindowsHookEx(s_hookHandle);
        }
    }
}