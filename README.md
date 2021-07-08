# DLL Injector


### Implementation
SetWindowsHookExW(WH_GETMESSAGE, functionAddress, dllToBeInjected, 0); It was originally published on https://www.apriorit.com/

WH_GETMESSAGE: determine the type of hook
functionAddress: determine the address of function(in the address space of your process)
dllToBeInjected: identify the dll containing the functionAddress function
0: indicates this is a global hook


### Steps
system check which type of hook is enabled
dll main function is called with DLL_PROCESS_ATTACH parameter
callbacks are inserted into the address space of target process

### CreateRemoteThread
invoking the LoadLibrary function within the thread of target process, since managing thread of another process is extremely complicated, so it better to create your own thread in it.
HANDLE CreateRemoteThread(
  HANDLE                 hProcess,
  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
  SIZE_T                 dwStackSize,
  LPTHREAD_START_ROUTINE lpStartAddress,
  LPVOID                 lpParameter,
  DWORD                  dwCreationFlags,
  LPDWORD                lpThreadId
);

hParameter: identify the process to which the new thread will belong 

* Getting the handle of process we're going to hook
HANDLE processHandle = OpenProcess(
               PROCESS_CREATE_THREAD | // For CreateRemoteThread
               PROCESS_VM_OPERATION  | // For VirtualAllocEx/VirtualFreeEx
               PROCESS_VM_WRITE,       // For WriteProcessMemory
               FALSE,                  // Don't inherit handles
               processPid);            // PID of our target process 

* Allocate some memory in the target process to pass the dll path
  // How many bytes we need to hold the whole DLL path
int bytesToAlloc = (1 + lstrlenW(injectLibraryPath)) * sizeof(WCHAR);
  
// Allocate memory in the remote process for the DLL path
LPWSTR remoteBufferForLibraryPath = LPWSTR(VirtualAllocEx(
        processHandle, NULL, bytesToAlloc, MEM_COMMIT, PAGE_READWRITE));



