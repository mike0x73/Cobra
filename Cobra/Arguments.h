#pragma once
#include <string>

class Arguments
{
private:
	const uint32_t m_spoof_target_pid;
	const std::wstring m_spoof_program;
	const bool m_inject;
	const std::wstring m_inject_module;

public:
	Arguments(
		const uint32_t &spoof_target_pid,
		const std::wstring &spoof_program,
		const bool &inject,
		const std::wstring &inject_module)
		: m_spoof_target_pid(spoof_target_pid)
		, m_spoof_program(spoof_program)
		, m_inject(inject)
		, m_inject_module(inject_module)
	{
	};

	uint32_t get_spoof_target() const
	{
		return m_spoof_target_pid;
	}

	std::wstring get_spoof_program() const
	{
		return m_spoof_program;
	}

	bool get_inject_dll() const
	{
		return m_inject;
	}

	std::wstring get_inject_module() const
	{
		return m_inject_module;
	}
};
