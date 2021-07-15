#pragma once
#include <Windows.h>
#include <string>

bool inject_dll(const DWORD& target_pid, const std::wstring& module_path);
