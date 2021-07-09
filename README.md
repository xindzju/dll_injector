# DLL Injector
### Features
* Support Windows and Linux
* Support X86, X86_64 and ARM
  
### Implementations Details
* Windows: leverage Windows system API to inject a DLL into a running processes, there are mainly two ways
  * SetWindowsHookExA/W:https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexa 
  * CreateRemoteThread:https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
* Linux: 
  * LD_PRELOAD:https://man7.org/linux/man-pages/man8/ld.so.8.html
  * ptrace:https://man7.org/linux/man-pages/man2/ptrace.2.html


### Building
```
git clone git@github.com:xindzju/dll_injector.git
mkdir build & cd build
cmake ..
```




