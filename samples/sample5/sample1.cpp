#include <iostream>
#include "dll_injector.h"

int main(int argc, char** argv) {
    dll_injector::DLLInjector dllInjector;
    const char* injectedDllName = "injectedDllName.dll"; //replace with your dll name
    const char* hookedFunctionName = "hookedFunctionName"; //replace with your exposed function name    
    std::cout << "Start to inject dll" << std::endl;
    /*for global hook, you need specify the exposed function name of your injected dll*/
    dllInjector.InjectDllGlobally(injectedDllName, hookedFunctionName);

    std::cout << "Press x to eject dll" << std::endl;
    bool exit = false;
    char keyPressed = ' ';
    while (!exit) {
        keyPressed = std::cin.get();
        std::cout << "Pressed " << keyPressed << std::endl;
        if (keyPressed == 'x')
            exit = true;
    }
    std::cout << "Start to eject dll" << std::endl;
    dllInjector.EjectDll();
    return 0;
}