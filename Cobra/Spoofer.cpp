#include "Spoofer.h"
#include <vector>
#include <filesystem>
#include "ScopedHandle.h"

int spoof(const DWORD& target_pid, std::wstring& command)
{
	int spoofed_pid = 0;

	STARTUPINFO startup_info{};
	STARTUPINFOEX startup_info_ex{};
	PROCESS_INFORMATION process_info{};
	SECURITY_ATTRIBUTES security_attributes{};
	SIZE_T size = 0;

	try
	{
		DWORD our_pid = GetCurrentProcessId();

		// Make sure same session ID
		DWORD notepad_session = 0;
		DWORD our_session = 0;

		if (!ProcessIdToSessionId(target_pid, &notepad_session) || !ProcessIdToSessionId(our_pid, &our_session))
		{
			return spoofed_pid;
		}

		if (notepad_session != our_session)
		{
			return spoofed_pid;
		}

		security_attributes.nLength = sizeof(security_attributes);
		startup_info.cb = sizeof(startup_info_ex);
		startup_info_ex.StartupInfo = startup_info;

		const ScopedHandle fake_parent_process(OpenProcess(0x1fffff, 0, target_pid));
		const std::wstring our_path = std::filesystem::current_path();
		InitializeProcThreadAttributeList(nullptr, 1, 0, &size);

		std::vector<unsigned char> attribute_list_data;
		attribute_list_data.reserve(size);
		startup_info_ex.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attribute_list_data.data());

		InitializeProcThreadAttributeList(startup_info_ex.lpAttributeList, 1, 0, &size);
		HANDLE raw_fake_parent_handle = fake_parent_process.get_handle();

		if (!UpdateProcThreadAttribute(startup_info_ex.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &raw_fake_parent_handle, sizeof(raw_fake_parent_handle), nullptr, nullptr))
		{
			return spoofed_pid;
		}

		CreateProcessW(nullptr, command.data(), &security_attributes, &security_attributes, 0, EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, nullptr, our_path.c_str(), reinterpret_cast<LPSTARTUPINFOW>(&startup_info_ex), &process_info);
		spoofed_pid = process_info.dwProcessId;
	}
	catch (const std::exception&)
	{
	}

	CloseHandle(process_info.hProcess);
	CloseHandle(process_info.hThread);

	return spoofed_pid;
}

