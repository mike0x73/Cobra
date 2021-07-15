#pragma once
#include <Windows.h>

class ScopedHandle
{
private:
	HANDLE m_handle;

public:
	ScopedHandle(const HANDLE& handle)
		: m_handle(handle)
	{
	}

	~ScopedHandle()
	{
		CloseHandle(m_handle);
	}

	HANDLE get_handle() const
	{
		return m_handle;
	}
};