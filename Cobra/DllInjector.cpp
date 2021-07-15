#include "DllInjector.h"
#include "ScopedHandle.h"

bool inject_dll(const DWORD& target_pid, const std::wstring& module_path)
{
    const ScopedHandle target_proc(OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid));
    const HMODULE kernel32(GetModuleHandleW(L"Kernel32"));

    void* mem = VirtualAllocEx(target_proc.get_handle(), nullptr, module_path.size() * sizeof(wchar_t), MEM_COMMIT, PAGE_READWRITE);

    if (mem == nullptr)
    {
        return false;
    }

    if (!WriteProcessMemory(target_proc.get_handle(), mem, reinterpret_cast<LPCVOID>(module_path.c_str()), wcslen(module_path.c_str()) * 2, nullptr))
    {
        return false;
    }

    ScopedHandle thread(CreateRemoteThread(target_proc.get_handle(), nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(kernel32, "LoadLibraryW")), mem, 0, nullptr));
    return thread.get_handle() != nullptr;
}
