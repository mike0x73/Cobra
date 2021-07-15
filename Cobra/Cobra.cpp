#include <iostream>
#include <vector>
#include "Arguments.h"
#include "Spoofer.h"
#include "DllInjector.h"
#include "ScopedHandle.h"
#include <chrono>
#include <thread>

void print_help()
{
	std::cout << "cobra.exe <target pid> <path to executable> [options]" << std::endl;
	std::cout << "\t-d <path to dll>\tInject target dll into spoofed process" << std::endl;
	std::cout << "\t-h\t\t\tPrint help" << std::endl;
}

Arguments parse_args(const std::vector<std::string>& arguments)
{
	uint32_t target_pid_spoof = 0;
	std::wstring program_to_spoof = L"";
	
	bool inject_dll = false;
	std::wstring module_to_inject = L"";
	
	target_pid_spoof = std::stoi((arguments[0]));
	program_to_spoof = std::wstring(arguments[1].begin(), arguments[1].end());


	auto inject_dll_it = std::find(arguments.begin(), arguments.end(), "-d");
	if (inject_dll_it != arguments.end())
	{
		inject_dll = true;
		module_to_inject = std::wstring((*(inject_dll_it + 1)).begin(), (*(inject_dll_it + 1)).end());
	}

	return Arguments(target_pid_spoof, program_to_spoof, inject_dll, module_to_inject);
}

int main(int argc, char* argv[])
{
	if (argc < 3 || argc > 5)
	{
		print_help();
		return -1;
	}

	std::vector<std::string> vector_args;
	for (int i = 1; i < argc; i++) // skip first input (filepath)
	{
		std::string argument = argv[i];
		if (argument == "-h")
		{
			print_help();
			return 0;
		}

		vector_args.push_back(argument);
	}

	try
	{
		Arguments arguments = parse_args(vector_args);

		std::wstring spoof_program = arguments.get_spoof_program(); // We can't pass in spoof program directly as needs to be non const.
		
		// Check if target pid exists
		ScopedHandle target_process(OpenProcess(PROCESS_ALL_ACCESS, TRUE, arguments.get_spoof_target()));
		DWORD return_code;
		GetExitCodeProcess(target_process.get_handle(), &return_code);

		if (return_code != STILL_ACTIVE)
		{
			std::cout << "Target process does not exist!";
			return -1;
		}

		int spoofed_pid = spoof(arguments.get_spoof_target(), spoof_program);
		if (spoofed_pid != 0)
		{
			std::cout << "Spoof successful. New pid: " << spoofed_pid << std::endl;
		}
		else
		{
			std::cout << "Failed to spoof. Error: " << GetLastError() << std::endl;
			return -1;
		}

		if (arguments.get_inject_dll())
		{
			try
			{
				if (inject_dll(spoofed_pid, arguments.get_inject_module()))
				{
					std::cout << "Injection succesful." << std::endl;
				}
				else
				{
					std::cout << "Failed to inject. Error: " << GetLastError() << std::endl;
				}
			}
			catch (const std::exception& ex)
			{
				std::cout << "Error thrown during dll injection. Error: " << ex.what() << std::endl;
			}
		}
	}
	catch (const std::exception& ex)
	{
		std::cout << "Exception: " << ex.what() << std::endl;
		return -1;
	}
}
