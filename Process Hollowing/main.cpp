#include <iostream>
#include <windows.h>

#include <libpeconv/peconv.h>
#include "RunPE.hpp"

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "Args: <payloadPath> <targetPath>\n";
        system("pause");
        return -1;
    }

    std::string payloadPath = argv[1], targetPath = argv[2];
    std::string cmdLine = GetCommandLine();
    std::string trimmedCmdLine = cmdLine.substr(cmdLine.find(targetPath));

    std::cout << "Payload: " << payloadPath << "\nTarget: " << targetPath << "\n";
    bool isOk = RunPe(payloadPath.c_str(), targetPath.c_str(), trimmedCmdLine.c_str());

    std::cout << (isOk ? "Done!" : "Failed!") << "\n";
    return isOk ? 0 : -1;
}